use reqwest::Client;
use serde_json::Value as JsonValue;
use tokio::process::Command;

use crate::core::config::get_config;
use crate::core::exceptions::ApiError;
use crate::services::grok::statsig::StatsigService;

const LIMITS_API: &str = "https://grok.com/rest/rate-limits";

pub struct UsageService {
    client: Client,
}

impl UsageService {
    pub async fn new() -> Self {
        let proxy: String = get_config("grok.base_proxy_url", String::new()).await;
        let mut builder = Client::builder();
        if !proxy.is_empty() {
            if let Ok(proxy) = reqwest::Proxy::all(&proxy) {
                builder = builder.proxy(proxy);
            }
        }
        let client = builder.build().unwrap();
        Self { client }
    }

    async fn build_headers(&self, token: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert(
            "Accept-Encoding",
            "gzip, deflate, br, zstd".parse().unwrap(),
        );
        headers.insert("Accept-Language", "zh-CN,zh;q=0.9".parse().unwrap());
        headers.insert("Baggage", "sentry-environment=production,sentry-release=d6add6fb0460641fd482d767a335ef72b9b6abb8,sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c".parse().unwrap());
        headers.insert("Cache-Control", "no-cache".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("Origin", "https://grok.com".parse().unwrap());
        headers.insert("Pragma", "no-cache".parse().unwrap());
        headers.insert("Priority", "u=1, i".parse().unwrap());
        headers.insert("Referer", "https://grok.com/".parse().unwrap());
        headers.insert(
            "Sec-Ch-Ua",
            "\"Google Chrome\";v=\"136\", \"Chromium\";v=\"136\", \"Not(A:Brand\";v=\"24\""
                .parse()
                .unwrap(),
        );
        headers.insert("Sec-Ch-Ua-Arch", "arm".parse().unwrap());
        headers.insert("Sec-Ch-Ua-Bitness", "64".parse().unwrap());
        headers.insert("Sec-Ch-Ua-Mobile", "?0".parse().unwrap());
        headers.insert("Sec-Ch-Ua-Model", "".parse().unwrap());
        headers.insert("Sec-Ch-Ua-Platform", "\"macOS\"".parse().unwrap());
        headers.insert("Sec-Fetch-Dest", "empty".parse().unwrap());
        headers.insert("Sec-Fetch-Mode", "cors".parse().unwrap());
        headers.insert("Sec-Fetch-Site", "same-origin".parse().unwrap());
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        let statsig = StatsigService::gen_id().await;
        headers.insert("x-statsig-id", statsig.parse().unwrap());
        headers.insert(
            "x-xai-request-id",
            uuid::Uuid::new_v4().to_string().parse().unwrap(),
        );
        let raw = token.strip_prefix("sso=").unwrap_or(token);
        let cf: String = get_config("grok.cf_clearance", String::new()).await;
        let cookie = if cf.is_empty() {
            format!("sso={raw}")
        } else {
            format!("sso={raw};cf_clearance={cf}")
        };
        headers.insert("Cookie", cookie.parse().unwrap());
        headers
    }

    async fn get_via_curl(&self, token: &str, model_name: &str) -> Result<JsonValue, ApiError> {
        let headers = self.build_headers(token).await;
        let payload = serde_json::json!({
            "requestKind": "DEFAULT",
            "modelName": model_name,
        });
        let timeout: u64 = get_config("grok.timeout", 10u64).await;
        let curl_path: String = get_config("grok.curl_path", "curl-impersonate".to_string()).await;
        let impersonate: String =
            get_config("grok.curl_impersonate", "chrome136".to_string()).await;

        let resolved_path = if curl_path.trim().is_empty() {
            "curl-impersonate".to_string()
        } else {
            curl_path
        };

        let mut cmd = Command::new(resolved_path);
        cmd.arg("-sS")
            .arg("--compressed")
            .arg("--http2")
            .arg("-X")
            .arg("POST")
            .arg(LIMITS_API)
            .arg("--max-time")
            .arg(timeout.to_string())
            .arg("-w")
            .arg("\\n%{http_code}");

        if !impersonate.trim().is_empty() {
            cmd.arg("--impersonate").arg(impersonate.trim());
        }

        for (name, value) in headers.iter() {
            let val = value.to_str().unwrap_or("");
            cmd.arg("-H").arg(format!("{}: {}", name.as_str(), val));
        }

        cmd.arg("--data").arg(payload.to_string());

        let output = cmd
            .output()
            .await
            .map_err(|e| ApiError::upstream(format!("Usage curl error: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::upstream(format!("Usage curl failed: {stderr}")));
        }

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        while stdout.ends_with('\n') {
            stdout.pop();
        }
        let (body, code_str) = stdout.rsplit_once('\n').unwrap_or((stdout.as_str(), ""));
        let status: u16 = code_str.trim().parse().unwrap_or(0);
        if status != 200 {
            return Err(ApiError::upstream(format!(
                "Failed to get usage stats: {status}"
            )));
        }
        let value: JsonValue = serde_json::from_str(body)
            .map_err(|e| ApiError::upstream(format!("Usage parse error: {e}")))?;
        Ok(value)
    }

    pub async fn get(&self, token: &str, model_name: &str) -> Result<JsonValue, ApiError> {
        let use_curl: bool = get_config("grok.use_curl_impersonate", true).await;
        if !use_curl {
            return Err(ApiError::upstream(
                "curl-impersonate is required for Grok requests".to_string(),
            ));
        }
        self.get_via_curl(token, model_name).await
    }
}

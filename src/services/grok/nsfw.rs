use std::process::Stdio;

use reqwest::Client;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::core::config::get_config;
use crate::core::exceptions::ApiError;
use crate::services::grok::grpc_web::{
    encode_grpc_web_payload, get_grpc_status, parse_grpc_web_response,
};

const NSFW_API: &str = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls";

#[derive(Debug, Clone)]
pub struct NsfwResult {
    pub success: bool,
    pub http_status: u16,
    pub grpc_status: Option<i32>,
    pub grpc_message: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct NsfwService {
    client: Client,
}

impl NsfwService {
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
        headers.insert("accept", "*/*".parse().unwrap());
        headers.insert(
            "content-type",
            "application/grpc-web+proto".parse().unwrap(),
        );
        headers.insert("origin", "https://grok.com".parse().unwrap());
        headers.insert("referer", "https://grok.com/".parse().unwrap());
        headers.insert(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                .parse()
                .unwrap(),
        );
        headers.insert("x-grpc-web", "1".parse().unwrap());
        headers.insert("x-user-agent", "connect-es/2.1.1".parse().unwrap());
        let raw = token.strip_prefix("sso=").unwrap_or(token);
        let cf: String = get_config("grok.cf_clearance", String::new()).await;
        let mut cookie = format!("sso={raw}; sso-rw={raw}");
        if !cf.is_empty() {
            cookie.push_str(&format!("; cf_clearance={cf}"));
        }
        headers.insert("cookie", cookie.parse().unwrap());
        headers
    }

    pub async fn enable(&self, token: &str) -> NsfwResult {
        let use_curl: bool = get_config("grok.use_curl_impersonate", false).await;
        if !use_curl {
            return NsfwResult {
                success: false,
                http_status: 0,
                grpc_status: None,
                grpc_message: None,
                error: Some("curl-impersonate is required for Grok requests".to_string()),
            };
        }

        match self.enable_via_curl(token).await {
            Ok(result) => result,
            Err(err) => NsfwResult {
                success: false,
                http_status: 0,
                grpc_status: None,
                grpc_message: None,
                error: Some(err.to_string()),
            },
        }
    }

    async fn enable_via_curl(&self, token: &str) -> Result<NsfwResult, ApiError> {
        let headers = self.build_headers(token).await;
        let payload = encode_grpc_web_payload(&[0x08, 0x01, 0x10, 0x01]);
        let timeout: u64 = get_config("grok.timeout", 30u64).await;
        let proxy: String = get_config("grok.base_proxy_url", String::new()).await;
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
            .arg(NSFW_API)
            .arg("--max-time")
            .arg(timeout.to_string())
            .arg("-w")
            .arg("\\n%{http_code}")
            .arg("--data-binary")
            .arg("@-");

        if !proxy.trim().is_empty() {
            cmd.arg("-x").arg(proxy.trim());
        }

        if !impersonate.trim().is_empty() {
            cmd.arg("--impersonate").arg(impersonate.trim());
        }

        for (name, value) in headers.iter() {
            let val = value.to_str().unwrap_or("");
            cmd.arg("-H").arg(format!("{}: {}", name.as_str(), val));
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| ApiError::upstream(format!("NSFW curl error: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&payload)
                .await
                .map_err(|e| ApiError::upstream(format!("NSFW curl stdin error: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| ApiError::upstream(format!("NSFW curl wait error: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::upstream(format!("NSFW curl failed: {stderr}")));
        }

        let mut stdout = output.stdout;
        let split = stdout.iter().rposition(|b| *b == b'\n');
        let (body, code_bytes) = match split {
            Some(idx) => (&stdout[..idx], &stdout[idx + 1..]),
            None => (stdout.as_slice(), &stdout[..0]),
        };
        let status: u16 = std::str::from_utf8(code_bytes)
            .unwrap_or("")
            .trim()
            .parse()
            .unwrap_or(0);

        if status != 200 {
            return Ok(NsfwResult {
                success: false,
                http_status: status,
                grpc_status: None,
                grpc_message: None,
                error: Some(format!("HTTP {status}")),
            });
        }

        let (_, trailers) = parse_grpc_web_response(body, None, None);
        let grpc = get_grpc_status(&trailers);
        let success = grpc.code == -1 || grpc.ok();

        Ok(NsfwResult {
            success,
            http_status: status,
            grpc_status: Some(grpc.code),
            grpc_message: if grpc.message.is_empty() {
                None
            } else {
                Some(grpc.message)
            },
            error: None,
        })
    }
}

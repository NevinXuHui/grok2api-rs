use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fs2::FileExt;
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;

use crate::core::config::{config_to_toml, project_root, toml_to_json};

#[derive(Debug, Clone)]
pub struct StorageError(pub String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StorageError {}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn load_config(&self) -> Result<JsonValue, StorageError>;
    async fn save_config(&self, data: &JsonValue) -> Result<(), StorageError>;
    async fn load_tokens(&self) -> Result<JsonValue, StorageError>;
    async fn save_tokens(&self, data: &JsonValue) -> Result<(), StorageError>;
    async fn with_lock<F, Fut, T>(&self, name: &str, timeout: u64, f: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, StorageError>> + Send,
        T: Send;
}

pub struct LocalStorage {
    lock: Mutex<()>,
}

impl LocalStorage {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }

    fn config_path() -> PathBuf {
        project_root().join("data").join("config.toml")
    }

    fn token_path() -> PathBuf {
        project_root().join("data").join("token.json")
    }

    fn lock_dir() -> PathBuf {
        project_root().join("data").join(".locks")
    }

    async fn acquire_file_lock(name: &str, timeout: u64) -> Result<File, StorageError> {
        let lock_dir = Self::lock_dir();
        if let Err(err) = fs::create_dir_all(&lock_dir) {
            return Err(StorageError(format!("create lock dir failed: {err}")));
        }
        let path = lock_dir.join(format!("{name}.lock"));
        let start = Instant::now();
        loop {
            let file = File::options()
                .create(true)
                .write(true)
                .open(&path)
                .map_err(|e| StorageError(format!("open lock file failed: {e}")))?;
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(_) => {
                    if start.elapsed() >= Duration::from_secs(timeout) {
                        return Err(StorageError(format!("lock timeout: {name}")));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn load_config(&self) -> Result<JsonValue, StorageError> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(JsonValue::Object(Default::default()));
        }
        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| StorageError(format!("read config failed: {e}")))?;
        let value: toml::Value = content
            .parse()
            .map_err(|e| StorageError(format!("parse config failed: {e}")))?;
        Ok(toml_to_json(value))
    }

    async fn save_config(&self, data: &JsonValue) -> Result<(), StorageError> {
        let path = Self::config_path();
        let dir = path.parent().unwrap_or(Path::new("."));
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| StorageError(format!("create config dir failed: {e}")))?;
        let toml_value = config_to_toml(data);
        let content = toml::to_string(&toml_value)
            .map_err(|e| StorageError(format!("serialize config failed: {e}")))?;
        let tmp_path = path.with_extension("toml.tmp");
        tokio::fs::write(&tmp_path, content)
            .await
            .map_err(|e| StorageError(format!("write tmp config failed: {e}")))?;
        tokio::fs::rename(&tmp_path, &path)
            .await
            .map_err(|e| StorageError(format!("rename config failed: {e}")))?;
        Ok(())
    }

    async fn load_tokens(&self) -> Result<JsonValue, StorageError> {
        let path = Self::token_path();
        if !path.exists() {
            return Ok(JsonValue::Object(Default::default()));
        }
        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| StorageError(format!("read tokens failed: {e}")))?;
        let value: JsonValue = serde_json::from_str(&content)
            .map_err(|e| StorageError(format!("parse tokens failed: {e}")))?;
        Ok(value)
    }

    async fn save_tokens(&self, data: &JsonValue) -> Result<(), StorageError> {
        let path = Self::token_path();
        let dir = path.parent().unwrap_or(Path::new("."));
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| StorageError(format!("create token dir failed: {e}")))?;
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| StorageError(format!("serialize tokens failed: {e}")))?;
        let tmp_path = path.with_extension("json.tmp");
        tokio::fs::write(&tmp_path, content)
            .await
            .map_err(|e| StorageError(format!("write tmp tokens failed: {e}")))?;
        tokio::fs::rename(&tmp_path, &path)
            .await
            .map_err(|e| StorageError(format!("rename tokens failed: {e}")))?;
        Ok(())
    }

    async fn with_lock<F, Fut, T>(&self, name: &str, timeout: u64, f: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, StorageError>> + Send,
        T: Send,
    {
        let _guard = tokio::time::timeout(Duration::from_secs(timeout), self.lock.lock())
            .await
            .map_err(|_| StorageError(format!("lock timeout: {name}")))?;
        let file = Self::acquire_file_lock(name, timeout).await?;
        let result = f().await;
        let _ = file.unlock();
        result
    }
}

static STORAGE: once_cell::sync::OnceCell<std::sync::Arc<LocalStorage>> =
    once_cell::sync::OnceCell::new();

pub fn get_storage() -> std::sync::Arc<LocalStorage> {
    STORAGE
        .get_or_init(|| {
            let storage_type =
                std::env::var("SERVER_STORAGE_TYPE").unwrap_or_else(|_| "local".to_string());
            if storage_type.to_lowercase() != "local" {
                tracing::warn!(
                    "Only local storage is supported in Rust version. Requested: {storage_type}"
                );
            }
            std::sync::Arc::new(LocalStorage::new())
        })
        .clone()
}

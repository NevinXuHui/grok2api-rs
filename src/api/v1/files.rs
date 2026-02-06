use axum::http::{HeaderMap, StatusCode};
use axum::{
    Router,
    extract::Path,
    response::{IntoResponse, Response},
    routing::get,
};
use mime_guess::MimeGuess;

use crate::core::config::get_config;

pub fn router() -> Router {
    Router::new()
        .route("/v1/files/image/*file", get(get_image))
        .route("/images/*file", get(get_image_alias))
        .route("/v1/files/video/*file", get(get_video))
}

async fn serve_file(file: String, media_type: &str) -> Response {
    let safe = file.replace('/', "-");
    let base = crate::core::config::project_root().join("data").join("tmp");
    let dir = if media_type == "image" {
        base.join("image")
    } else {
        base.join("video")
    };
    let path = dir.join(safe);
    if let Ok(bytes) = tokio::fs::read(&path).await {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Cache-Control",
            "public, max-age=31536000, immutable".parse().unwrap(),
        );
        let mime = if media_type == "image" {
            MimeGuess::from_path(&path)
                .first_or_octet_stream()
                .to_string()
        } else {
            "video/mp4".to_string()
        };
        headers.insert("Content-Type", mime.parse().unwrap());
        return (headers, bytes).into_response();
    }
    (StatusCode::NOT_FOUND, "File not found").into_response()
}

async fn get_image(Path(file): Path<String>) -> Response {
    let enabled: bool = get_config("downstream.enable_files", true).await;
    if !enabled {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    serve_file(file, "image").await
}

async fn get_image_alias(Path(file): Path<String>) -> Response {
    let enabled: bool = get_config("downstream.enable_files", true).await;
    if !enabled {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    serve_file(file, "image").await
}

async fn get_video(Path(file): Path<String>) -> Response {
    let enabled: bool = get_config("downstream.enable_files", true).await;
    if !enabled {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    serve_file(file, "video").await
}

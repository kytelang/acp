//! Static serving of the embedded Vue console (A.4). Dependency-free: reads files from the configured
//! console directory and falls back to index.html for SPA client routes. All API routes are matched
//! before this fallback, so only unknown paths (assets and SPA routes) reach here.
use crate::state::AppState;
use axum::{
    extract::State,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

/// Read a file under `dir`, rejecting path traversal. Returns (content-type, bytes).
fn read_under(dir: &str, rel: &str) -> Option<(&'static str, Vec<u8>)> {
    let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|seg| seg == ".." || seg == ".") {
        return None;
    }
    let full = std::path::Path::new(dir).join(rel);
    std::fs::read(&full).ok().map(|b| (content_type(rel), b))
}

fn serve(st: &Arc<AppState>, path: &str) -> Response {
    let dir = match &st.console_dir {
        Some(d) => d,
        None => return (StatusCode::NOT_FOUND, "console not built; run the Vite build or set --console").into_response(),
    };
    // Serve the exact asset when it exists; otherwise fall back to index.html so client-side routes
    // (for example /overview, /reports) load the SPA which then renders the route.
    if !path.is_empty() && path != "/" {
        if let Some((ct, bytes)) = read_under(dir, path) {
            return ([(header::CONTENT_TYPE, ct)], bytes).into_response();
        }
    }
    match read_under(dir, "index.html") {
        Some((ct, bytes)) => ([(header::CONTENT_TYPE, ct)], bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "console index.html not found").into_response(),
    }
}

/// Serve a specific static asset file (for example /main.js, /main.css) with the right content type.
/// Unlike the SPA fallback this does NOT fall back to index.html: a missing asset is a real 404, so a
/// bad asset URL never returns an HTML page with a 200.
pub(crate) async fn asset(State(st): State<Arc<AppState>>, uri: Uri) -> Response {
    let dir = match &st.console_dir {
        Some(d) => d,
        None => return (StatusCode::NOT_FOUND, "console not built").into_response(),
    };
    match read_under(dir, uri.path()) {
        Some((ct, bytes)) => ([(header::CONTENT_TYPE, ct)], bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// GET / -> the console entry (index.html).
pub(crate) async fn spa_index(State(st): State<Arc<AppState>>) -> Response {
    serve(&st, "/")
}

/// Fallback for any unmatched path: an asset file, else the SPA index.
pub(crate) async fn spa_fallback(State(st): State<Arc<AppState>>, uri: Uri) -> Response {
    serve(&st, uri.path())
}

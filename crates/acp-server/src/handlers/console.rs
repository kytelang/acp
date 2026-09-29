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

// The console uses stable, unhashed filenames (index.html, main.js, main.css). Without content-hash
// cache-busting, tell browsers to always revalidate so a redeploy is never served stale.
const NO_CACHE: &str = "no-cache, must-revalidate";

#[cfg(feature = "embed-console")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../console/dist"]
struct EmbeddedConsole;

/// Read an asset from the embedded bundle when built with --features embed-console (single-binary
/// deploy). Returns None otherwise, so serving falls through to the on-disk console directory.
fn embedded_asset(rel: &str) -> Option<(&'static str, Vec<u8>)> {
    #[cfg(feature = "embed-console")]
    {
        let mut rel = rel.trim_start_matches('/');
        if rel.is_empty() { rel = "index.html"; }
        if let Some(f) = EmbeddedConsole::get(rel) {
            return Some((content_type(rel), f.data.into_owned()));
        }
    }
    #[cfg(not(feature = "embed-console"))]
    { let _ = rel; }
    None
}

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
    let dir = st.console_dir.as_deref();
    // A specific asset: embedded bundle first (single-binary build), else the on-disk console dir.
    if !path.is_empty() && path != "/" {
        if let Some((ct, bytes)) = embedded_asset(path).or_else(|| dir.and_then(|d| read_under(d, path))) {
            return ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, NO_CACHE)], bytes).into_response();
        }
    }
    // SPA fallback: index.html (embedded, else disk).
    if let Some((ct, bytes)) = embedded_asset("index.html").or_else(|| dir.and_then(|d| read_under(d, "index.html"))) {
        return ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, NO_CACHE)], bytes).into_response();
    }
    (StatusCode::NOT_FOUND, "console not built; run the Vite build, set --console, or build with --features embed-console").into_response()
}

/// Serve a specific static asset file (for example /main.js, /main.css) with the right content type.
/// Unlike the SPA fallback this does NOT fall back to index.html: a missing asset is a real 404, so a
/// bad asset URL never returns an HTML page with a 200.
pub(crate) async fn asset(State(st): State<Arc<AppState>>, uri: Uri) -> Response {
    let dir = st.console_dir.as_deref();
    match embedded_asset(uri.path()).or_else(|| dir.and_then(|d| read_under(d, uri.path()))) {
        Some((ct, bytes)) => ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, NO_CACHE)], bytes).into_response(),
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

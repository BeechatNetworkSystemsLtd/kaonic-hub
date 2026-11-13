//! The web UI's files (built into the binary, or from a directory), and the security
//! headers every response carries.
//!
//! Hashed files under `/assets/` are cached forever; `index.html` never is.
//! Any other path that is not a file gets `index.html` (browser-history routing).

use std::path::{Component, Path, PathBuf};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; \
                   connect-src 'self'; frame-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The file a URL path names inside `root`, or None if it tries to leave it.
fn resolve(root: &Path, url_path: &str) -> Option<PathBuf> {
    let relative = Path::new(url_path.trim_start_matches('/'));
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        || url_path.contains('\0')
        || url_path.contains('\\')
    {
        return None;
    }
    Some(root.join(relative))
}

/// Where the web UI comes from.
#[derive(Clone, Debug)]
pub enum Webui {
    /// Built into the binary (`build.rs`): the UI always matches this hub.
    Embedded,
    /// Files on disk, for working on the UI without rebuilding the hub (`--webui-dir`).
    Dir(PathBuf),
}

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/webui.rs"));
}

impl Webui {
    /// The UI's version: built in, or the `version` file next to its files.
    pub fn version(&self) -> Option<String> {
        match self {
            Webui::Embedded => embedded::VERSION.map(str::to_owned),
            Webui::Dir(dir) => std::fs::read_to_string(dir.join("version"))
                .ok()
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty()),
        }
    }

    async fn read(&self, url_path: &str) -> Option<(Body, &'static str)> {
        match self {
            Webui::Embedded => {
                let index = embedded::FILES.binary_search_by(|(url, _)| (*url).cmp(url_path)).ok()?;
                Some((Body::from(embedded::FILES[index].1), content_type(Path::new(url_path))))
            }
            Webui::Dir(root) => {
                let file = resolve(root, url_path).filter(|file| file.is_file())?;
                let bytes = tokio::fs::read(&file).await.ok()?;
                Some((Body::from(bytes), content_type(&file)))
            }
        }
    }
}

pub async fn files(State(webui): State<Webui>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/") || path.starts_with("/apps/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (found, immutable) = match webui.read(&path).await {
        Some(found) => (found, path.starts_with("/assets/")),
        // A missing hashed asset is a real 404; anything else is a route of the app.
        None if path.starts_with("/assets/") => return StatusCode::NOT_FOUND.into_response(),
        None => match webui.read("/index.html").await {
            Some(found) => (found, false),
            None => return (StatusCode::SERVICE_UNAVAILABLE, "The web UI is not installed on this device.").into_response(),
        },
    };
    let (body, content_type) = found;
    let cache = if immutable { "public, max-age=31536000, immutable" } else { "no-cache" };
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, cache)], body).into_response()
}

/// Adds the security headers to responses.
/// A plugin page (`/apps/<id>/…`) is served from the hub's origin. Opened on its own (a
/// link, a QR code) its scripts would run as the hub, with the session cookie, and could
/// read the CSRF token and act as the admin. The `sandbox` directive gives it an opaque
/// origin wherever it is opened, as the UI's sandboxed iframe already does.
const PLUGIN_CSP: &str = "sandbox allow-scripts allow-forms allow-downloads; frame-ancestors 'self'";

pub async fn security_headers(request: Request, next: Next) -> Response {
    let plugin = request.uri().path().starts_with("/apps/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if plugin {
        plugin_headers(headers);
        return response;
    }
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // A handler's own policy (an icon's `default-src 'none'`) stays: every policy applies.
    headers.append("content-security-policy", HeaderValue::from_static(CSP));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Headers for a plugin page: its own CSP stays (several CSPs all apply), the sandbox is
/// added, and the UI may frame it.
fn plugin_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    headers.append("content-security-policy", HeaderValue::from_static(PLUGIN_CSP));
    headers.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plugin_page_is_always_sandboxed_and_keeps_its_own_policy() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("content-security-policy", HeaderValue::from_static("default-src 'self'"));
        plugin_headers(&mut headers);
        let policies: Vec<&str> = headers.get_all("content-security-policy").iter().map(|value| value.to_str().unwrap()).collect();
        assert_eq!(policies, vec!["default-src 'self'", PLUGIN_CSP]);
        assert!(PLUGIN_CSP.starts_with("sandbox ") && !PLUGIN_CSP.contains("allow-same-origin"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    #[test]
    fn the_built_in_ui_can_be_looked_up() {
        assert!(embedded::FILES.windows(2).all(|pair| pair[0].0 < pair[1].0), "sorted and unique for binary search");
        assert!(embedded::FILES.iter().all(|(url, _)| url.starts_with('/') && !url.contains("..")));
        assert!(embedded::FILES.is_empty() || embedded::FILES.iter().any(|(url, _)| *url == "/index.html"));
    }

    #[test]
    fn paths_cannot_leave_the_ui_directory() {
        let root = Path::new("/usr/share/kaonic-webui");
        assert_eq!(
            resolve(root, "/assets/app.js"),
            Some(root.join("assets/app.js"))
        );
        assert_eq!(resolve(root, "/../etc/shadow"), None);
        assert_eq!(resolve(root, "/assets/../../etc/shadow"), None);
        assert_eq!(resolve(root, "/a\\b"), None);
        assert_eq!(resolve(root, "/./x"), None);
    }
}

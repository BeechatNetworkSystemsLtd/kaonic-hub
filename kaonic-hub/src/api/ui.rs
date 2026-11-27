//! `/ui/*`: how the web UI looks on this device, kept here so every browser sees the same.

use axum::extract::State;
use axum::response::Response;
use kaonic_store::settings;
use serde::{Deserialize, Serialize};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};

/// The pages shown in the menu, by the UI's page ids; unset until the admin chooses.
const PAGES: &str = "ui.pages";
const MAX_PAGES: usize = 32;
const MAX_ID: usize = 32;

#[derive(Serialize)]
struct PagesView {
    /// Null: the UI's own defaults.
    shown: Option<Vec<String>>,
}

async fn read(app: &App) -> ApiResult<PagesView> {
    let text = app.store.call(|c| settings::get(c, PAGES)).await?;
    let shown = text.map(|text| text.split(',').filter(|id| !id.is_empty()).map(str::to_owned).collect());
    Ok(PagesView { shown })
}

/// `GET /ui/pages`
pub async fn pages(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(read(&app).await?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagesBody {
    /// The page ids to show; null goes back to the UI's defaults.
    shown: Option<Vec<String>>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// `PUT /ui/pages`
pub async fn set_pages(State(app): State<App>, _: Admin, Json(body): Json<PagesBody>) -> ApiResult<Response> {
    match body.shown {
        Some(shown) => {
            if shown.len() > MAX_PAGES || !shown.iter().all(|id| valid_id(id)) {
                return Err(ApiError::field("shown", "Use page ids of lowercase letters, digits and dashes."));
            }
            let mut ids: Vec<String> = Vec::new();
            for id in shown {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            let text = ids.join(",");
            app.store.call(move |c| settings::set(c, PAGES, &text)).await?;
        }
        None => {
            app.store.call(|c| settings::delete(c, PAGES)).await?;
        }
    }
    Ok(no_store(axum::Json(read(&app).await?)))
}

#[cfg(test)]
mod tests {
    use super::valid_id;

    #[test]
    fn page_ids_are_plain() {
        assert!(valid_id("talk") && valid_id("vpn") && valid_id("mesh-chat"));
        assert!(!valid_id("") && !valid_id("Talk") && !valid_id("a,b") && !valid_id(&"x".repeat(33)));
    }
}

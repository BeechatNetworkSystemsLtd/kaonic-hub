//! The one error shape of the API.

use std::collections::BTreeMap;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub fields: BTreeMap<String, String>,
    pub retry_after: Option<u64>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            fields: BTreeMap::new(),
            retry_after: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated", message)
    }
    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
    pub fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Something went wrong on the device. Try again.",
        )
    }
    pub fn rate_limited(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many tries. Wait and try again.",
            )
        }
    }

    /// One or more fields are invalid: `[(field, message)]`.
    pub fn invalid<I: IntoIterator<Item = (&'static str, String)>>(fields: I) -> Self {
        let fields: BTreeMap<String, String> = fields
            .into_iter()
            .map(|(field, message)| (field.to_owned(), message))
            .collect();
        Self {
            fields,
            ..Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                "Check the highlighted fields.",
            )
        }
    }

    pub fn field(field: &'static str, message: impl Into<String>) -> Self {
        Self::invalid([(field, message.into())])
    }
}

/// Anything unexpected: logged here, never shown to the caller.
impl<E: std::fmt::Display> From<E> for ApiError
where
    E: Into<Box<dyn std::error::Error>>,
{
    fn from(error: E) -> Self {
        log::error!("internal error: {error}");
        Self::internal()
    }
}

#[derive(Serialize)]
struct Body<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Details<'a>>,
}

#[derive(Serialize)]
struct Details<'a> {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    fields: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let details = (!self.fields.is_empty() || self.retry_after.is_some()).then_some(Details {
            fields: &self.fields,
            retry_after_secs: self.retry_after,
        });
        let body = serde_json::to_vec(&Body {
            code: self.code,
            message: &self.message,
            details,
        })
        .unwrap_or_default();
        let mut response = (
            self.status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response();
        if let Some(seconds) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

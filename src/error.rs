use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Error body shared with the web app: `{ code, message, verbatim? }` (packages/protocol errors.ts).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiError {
  #[serde(skip)]
  pub status: StatusCode,
  pub code: &'static str,
  pub message: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub verbatim: Option<String>,
}

impl ApiError {
  pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
    Self {
      status,
      code,
      message: message.into(),
      verbatim: None,
    }
  }
  pub fn with_verbatim(mut self, v: impl Into<String>) -> Self {
    self.verbatim = Some(v.into());
    self
  }
  pub fn not_paired() -> Self {
    Self::new(
      StatusCode::UNAUTHORIZED,
      "notPaired",
      "Pair this browser with the Helper first.",
    )
  }
  pub fn bad_request(message: impl Into<String>) -> Self {
    Self::new(StatusCode::BAD_REQUEST, "unknown", message)
  }
  pub fn internal(message: impl Into<String>) -> Self {
    Self::new(StatusCode::INTERNAL_SERVER_ERROR, "unknown", message)
  }
}

impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    (self.status, Json(&self)).into_response()
  }
}

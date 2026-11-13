//! Localhost HTTP + WebSocket server (docs/helper-api.md).

use crate::binaries::{Binaries, Tool};
use crate::catalog::{self, Cursor};
use crate::error::ApiError;
use crate::hops::{Failure, Hub};
use crate::pairing::{PairError, Pairing};
use crate::ytdlp;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

pub const PROD_ORIGIN: &str = "https://bunniehop.party";
const DEV_ORIGINS: &[&str] = &[
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
];

/// Which web origins may drive this Helper. Release builds: the production origin only.
pub fn allowed_origins(dev: bool) -> Vec<String> {
  let mut v = vec![PROD_ORIGIN.to_string()];
  if dev {
    v.extend(DEV_ORIGINS.iter().map(|s| s.to_string()));
  }
  v
}

/// Shows the pairing code to the creator (window, notification, terminal).
pub type Notifier = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
  pub pairing: Arc<Pairing>,
  pub origins: Arc<Vec<String>>,
  pub port: u16,
  pub vault_dir: PathBuf,
  pub show_code: Notifier,
  pub tools: Arc<Tooling>,
  pub hub: Arc<Hub>,
  pub connections: Arc<crate::connections::Store>,
  pub http: reqwest::Client,
  pub endpoints: crate::uploaders::Endpoints,
  /// Opens a web page in the creator's default browser (OAuth sign-in).
  pub open_url: Opener,
  /// OAuth sign-ins waiting for the browser to come back: state → code.
  pub oauth: Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>>,
  /// Sign-ins waiting for an emailed code (Ghost): "site|email" → (admin URL, session cookie, since).
  pub pending: Arc<std::sync::Mutex<HashMap<String, PendingCode>>>,
}

/// (admin URL, session cookie, when Ghost sent the code).
pub type PendingCode = (String, String, std::time::Instant);

pub type Opener = Arc<dyn Fn(&str) + Send + Sync>;

/// The system browser: `open` / `explorer` / `xdg-open` with the URL as one argument.
pub fn system_opener() -> Opener {
  Arc::new(|url: &str| {
    let opener = if cfg!(target_os = "macos") {
      "open"
    } else if cfg!(windows) {
      "explorer"
    } else {
      "xdg-open"
    };
    if let Err(e) = std::process::Command::new(opener).arg(url).spawn() {
      tracing::warn!(error = %e, "couldn't open the browser");
    }
  })
}

/// Test state with fakes for the browser and uploaders.
#[cfg(test)]
pub(crate) fn test_state(dir: &std::path::Path, show_code: Notifier, open_url: Opener) -> AppState {
  let pairing = Pairing::with(
    dir.join("p.json"),
    Box::new(|| "424242".into()),
    Box::new(SystemTime::now),
  );
  let tools = Arc::new(Tooling::new(Binaries::new(dir.join("bin")), false));
  AppState {
    pairing: Arc::new(pairing),
    origins: Arc::new(allowed_origins(false)),
    port: 17333,
    vault_dir: dir.join("vault"),
    show_code,
    tools: tools.clone(),
    hub: Hub::new(
      dir.join("hops"),
      dir.join("tmp"),
      dir.join("vault"),
      tools,
      Arc::new(|_: &str, _: &str| None),
    ),
    connections: Arc::new(crate::connections::Store::open(
      dir.join("connections.json"),
      Box::new(crate::connections::MemorySecrets::default()),
    )),
    http: reqwest::Client::new(),
    endpoints: crate::uploaders::Endpoints::default(),
    open_url,
    oauth: Arc::default(),
    pending: Arc::default(),
  }
}

/// yt-dlp, ffmpeg and Deno: where they are, and installing missing ones on first use.
pub struct Tooling {
  pub bins: Binaries,
  pub http: reqwest::Client,
  /// Install from official releases when a tool is missing (off in tests).
  pub auto_install: bool,
  install: tokio::sync::Mutex<()>,
  /// Ids already returned per listing URL, so Shorts that also sit under Videos appear once.
  listings: std::sync::Mutex<HashMap<String, HashSet<String>>>,
}

impl Tooling {
  pub fn new(bins: Binaries, auto_install: bool) -> Self {
    let http = reqwest::Client::builder()
      .user_agent(concat!("BunnieHop-Helper/", env!("CARGO_PKG_VERSION")))
      .build()
      .unwrap_or_default();
    Self {
      bins,
      http,
      auto_install,
      install: tokio::sync::Mutex::new(()),
      listings: std::sync::Mutex::new(HashMap::new()),
    }
  }

  /// The tool's path, installing it first when allowed. One install at a time.
  pub async fn ensure(&self, tool: Tool) -> Result<PathBuf, ApiError> {
    if let Some(p) = self.bins.find(tool) {
      return Ok(p);
    }
    if !self.auto_install {
      return Err(missing(tool, None));
    }
    let _g = self.install.lock().await;
    if let Some(p) = self.bins.find(tool) {
      return Ok(p);
    }
    tracing::info!(tool = tool.exe(), "installing from the official release");
    self
      .bins
      .install(&self.http, tool)
      .await
      .map_err(|e| missing(tool, Some(e.to_string())))
  }

  /// Tools passed to yt-dlp: ffmpeg when present, Deno (installed if needed) for YouTube.
  async fn ytdlp_tools(&self, youtube: bool) -> ytdlp::Tools {
    let deno = if youtube {
      self.ensure(Tool::Deno).await.ok()
    } else {
      self.bins.find(Tool::Deno)
    };
    ytdlp::Tools {
      ffmpeg: self.bins.find(Tool::Ffmpeg),
      deno,
    }
  }
}

fn missing(tool: Tool, verbatim: Option<String>) -> ApiError {
  let e = ApiError::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "needsHelper",
    format!(
      "The Helper couldn't set up {}. Check your connection and try again.",
      tool.exe()
    ),
  );
  match verbatim {
    Some(v) => e.with_verbatim(v),
    None => e,
  }
}

pub fn router(state: AppState) -> Router {
  Router::new()
    .route("/v1/hello", get(hello))
    .route(PAIR_PAGE, get(pair_page))
    .route("/v1/pair/start", post(pair_start))
    .route("/v1/pair/finish", post(pair_finish))
    .route("/v1/pair", axum::routing::delete(unpair))
    .route("/v1/status", get(status))
    .route("/v1/capabilities", get(capabilities))
    .route("/v1/catalog", post(list_catalog))
    .route("/v1/binaries/install", post(install_tools))
    .route(
      "/v1/exports",
      post(upload_export).layer(axum::extract::DefaultBodyLimit::disable()),
    )
    .route("/v1/hops", post(start_hop))
    .route("/v1/hops/{id}/{action}", post(hop_action))
    .route(
      "/v1/hops/{id}/items/{item}/{dest}/{action}",
      post(cell_action),
    )
    .route("/v1/stop-all", post(stop_all))
    .route("/v1/ledger", get(ledger))
    .route(
      "/v1/ledger/merge",
      post(merge_ledger).layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024)),
    )
    .route("/v1/open-folder", post(open_folder))
    .route("/v1/events", get(events))
    .merge(crate::connect::routes())
    .fallback(|| async {
      ApiError::new(
        StatusCode::NOT_FOUND,
        "notFound404",
        "No such Helper route.",
      )
    })
    .layer(middleware::from_fn_with_state(state.clone(), guard))
    .with_state(state.clone())
    .merge(telegram_router(state))
}

/// Telegram has a separate router and guard. The existing web API guard is unchanged.
fn telegram_router(state: AppState) -> Router {
  crate::connect::telegram_routes()
    .layer(middleware::from_fn_with_state(
      state.clone(),
      telegram_guard,
    ))
    .with_state(state)
}

async fn telegram_guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
  let origin = req
    .headers()
    .get(header::ORIGIN)
    .and_then(|v| v.to_str().ok());
  let local = format!("http://127.0.0.1:{}", st.port);
  // The paired request opens the first page as a top-level browser navigation. It has no
  // Origin header; Fetch Metadata and the one-time capability restrict this bootstrap.
  // All API requests require the page's exact origin. No CORS permissions are returned.
  let navigation = req.uri().path() == crate::connect::TELEGRAM_PAGE
    && req.method() == Method::GET
    && origin.is_none()
    && req
      .headers()
      .get("sec-fetch-site")
      .is_some_and(|v| v == "none")
    && req
      .headers()
      .get("sec-fetch-mode")
      .is_some_and(|v| v == "navigate")
    && req
      .headers()
      .get("sec-fetch-dest")
      .is_some_and(|v| v == "document");
  let host = req
    .headers()
    .get(header::HOST)
    .and_then(|v| v.to_str().ok());
  if host != Some(format!("127.0.0.1:{}", st.port).as_str())
    || !(origin == Some(local.as_str()) || navigation)
  {
    return ApiError::new(
      StatusCode::FORBIDDEN,
      "originNotAllowed",
      "Use the Helper's local Telegram sign-in page.",
    )
    .into_response();
  }
  let capability = crate::connect::telegram_capability(&req).unwrap_or_default();
  if !st.connections.telegram.active(&capability).await {
    return ApiError::new(
      StatusCode::UNAUTHORIZED,
      "signInRequired",
      "This Telegram sign-in expired. Start again from BunnieHop.",
    )
    .into_response();
  }
  let mut response = next.run(req).await;
  let h = response.headers_mut();
  h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
  h.insert(
    header::REFERRER_POLICY,
    HeaderValue::from_static("no-referrer"),
  );
  h.insert(
    "x-content-type-options",
    HeaderValue::from_static("nosniff"),
  );
  h.insert("content-security-policy",HeaderValue::from_static("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
  response
}

/// Origin + Host checks, CORS and Private Network Access, before any handler runs.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
  let origin = req
    .headers()
    .get(header::ORIGIN)
    .and_then(|v| v.to_str().ok())
    .map(str::to_owned);
  // The OAuth redirect is a top-level navigation from the creator's server: no Origin header.
  // It only completes a sign-in this Helper started (unguessable `state`); Host is still checked.
  let page = matches!(
    req.uri().path(),
    crate::connect::CALLBACK_PATH | crate::connect::RELAY_CALLBACK_PATH | PAIR_PAGE
  );
  if page && req.method() == Method::GET {
    if !host_ok(req.headers(), st.port) {
      return ApiError::new(
        StatusCode::FORBIDDEN,
        "originNotAllowed",
        "Unexpected Host header.",
      )
      .into_response();
    }
    return next.run(req).await;
  }
  let Some(origin) = origin.filter(|o| st.origins.iter().any(|a| a == o)) else {
    return ApiError::new(
      StatusCode::FORBIDDEN,
      "originNotAllowed",
      "Only bunniehop.party can use this Helper.",
    )
    .into_response();
  };
  if !host_ok(req.headers(), st.port) {
    return ApiError::new(
      StatusCode::FORBIDDEN,
      "originNotAllowed",
      "Unexpected Host header.",
    )
    .into_response();
  }
  let mut res = if req.method() == Method::OPTIONS {
    let mut r = StatusCode::NO_CONTENT.into_response();
    let h = r.headers_mut();
    h.insert(
      header::ACCESS_CONTROL_ALLOW_METHODS,
      HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    h.insert(
      header::ACCESS_CONTROL_ALLOW_HEADERS,
      HeaderValue::from_static("authorization, content-type"),
    );
    h.insert(
      header::ACCESS_CONTROL_MAX_AGE,
      HeaderValue::from_static("600"),
    );
    h.insert(
      "access-control-allow-private-network",
      HeaderValue::from_static("true"),
    );
    r
  } else {
    next.run(req).await
  };
  let h = res.headers_mut();
  if let Ok(v) = HeaderValue::from_str(&origin) {
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
  }
  h.insert(header::VARY, HeaderValue::from_static("Origin"));
  h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
  res
}

/// DNS-rebinding guard: only loopback host names on our own port.
fn host_ok(headers: &HeaderMap, port: u16) -> bool {
  let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
    return false;
  };
  host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

/// Extractor for authenticated routes: a valid pairing token in `Authorization: Bearer`.
pub struct PairedToken(pub String);

impl FromRequestParts<AppState> for PairedToken {
  type Rejection = ApiError;
  async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
    let token = parts
      .headers
      .get(header::AUTHORIZATION)
      .and_then(|v| v.to_str().ok())
      .and_then(|v| v.strip_prefix("Bearer "))
      .map(str::trim)
      .filter(|t| !t.is_empty())
      .ok_or_else(ApiError::not_paired)?;
    if st.pairing.verify(token) {
      Ok(PairedToken(token.to_string()))
    } else {
      Err(ApiError::not_paired())
    }
  }
}

async fn hello() -> impl IntoResponse {
  Json(json!({ "app": "bunniehop-helper", "version": crate::VERSION, "protocol": 1 }))
}

/// The Helper's own page with the pairing code. It opens in the creator's browser when pairing
/// starts, so no terminal is needed. Only this computer can load it (Host check), other sites can't
/// read it (no CORS) or frame it, and pairing itself can only be started by bunniehop.party.
pub const PAIR_PAGE: &str = "/pair";

async fn pair_page(State(st): State<AppState>) -> impl IntoResponse {
  let body = match st.pairing.pending_code() {
    Some(code) => {
      let spaced = format!(
        "{} {}",
        &code[..3.min(code.len())],
        &code[3.min(code.len())..]
      );
      format!("<p style='margin:0 0 8px'>Type this code on bunniehop.party</p><p style='font:700 56px ui-monospace,monospace;letter-spacing:6px;margin:0'>{spaced}</p><p style='opacity:.7;margin:12px 0 0'>It works once and expires in 5 minutes. Then you can close this tab.</p>")
    }
    None => {
      "<p>No pairing is waiting. Start it on bunniehop.party → Settings → Pair the Helper.</p>"
        .into()
    }
  };
  (
    [
      (header::CONTENT_TYPE, "text/html; charset=utf-8"),
      (header::CACHE_CONTROL, "no-store"),
      (header::X_FRAME_OPTIONS, "DENY"),
      (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"),
      (header::REFERRER_POLICY, "no-referrer"),
    ],
    format!("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>BunnieHop Helper</title><body style='font:16px system-ui;background:#0b0b10;color:#eee;display:grid;place-items:center;height:90vh;text-align:center'><div>{body}</div>"),
  )
}

async fn pair_start(State(st): State<AppState>) -> Result<impl IntoResponse, ApiError> {
  let (code, expires) = st
    .pairing
    .start()
    .map_err(|e| ApiError::new(StatusCode::TOO_MANY_REQUESTS, "pairingLimited", e.message()))?;
  (st.show_code)(&code);
  Ok(Json(json!({ "expiresAt": iso(expires) })))
}

#[derive(Deserialize)]
struct FinishBody {
  code: String,
  #[serde(default)]
  label: String,
}

async fn pair_finish(
  State(st): State<AppState>,
  body: Option<Json<FinishBody>>,
) -> Result<impl IntoResponse, ApiError> {
  let Json(b) = body.ok_or_else(|| ApiError::bad_request("Send the 6-digit code."))?;
  match st.pairing.finish(&b.code, &b.label) {
    Ok(token) => Ok(Json(json!({ "token": token }))),
    Err(e) => {
      let status = match e {
        PairError::Storage => StatusCode::INTERNAL_SERVER_ERROR,
        PairError::Limited { .. } => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::BAD_REQUEST,
      };
      Err(ApiError::new(status, "pairingFailed", e.message()))
    }
  }
}

async fn unpair(State(st): State<AppState>, PairedToken(t): PairedToken) -> impl IntoResponse {
  st.pairing.unpair(&t);
  StatusCode::NO_CONTENT
}

async fn status(State(st): State<AppState>, _t: PairedToken) -> impl IntoResponse {
  let found = |t: Tool| st.tools.bins.find(t).is_some();
  Json(json!({
    "version": crate::VERSION,
    "paired": true,
    "vaultDir": st.vault_dir,
    "binaries": { "ytdlp": found(Tool::YtDlp), "ffmpeg": found(Tool::Ffmpeg), "deno": found(Tool::Deno) },
  }))
}

/// What this Helper can honestly do today (D12): only destinations whose uploader ships.
async fn capabilities(_t: PairedToken) -> impl IntoResponse {
  Json(json!({
    "kind": "helper",
    "version": crate::VERSION,
    "sources": ["youtube", "tiktok", "instagram", "vimeo", "dailymotion", "rumble", "odysee", "twitch", "x", "facebook", "soundcloud"],
    "destinations": crate::connect::PLATFORMS.iter().map(|p| json!({ "platform": p, "paths": ["api"] })).collect::<Vec<_>>(),
    "vaults": std::iter::once("local").chain(crate::connect::VAULT_ACCOUNTS).collect::<Vec<_>>(),
    // no transform is wired into hops yet, so having ffmpeg doesn't mean BunnieHop edits video
    "canTransform": false,
    "canDriveBrowser": false,
    // self-hosted WordPress opens bunniehop.party/connect/wp-start, never WordPress directly (D-120);
    // the web app keeps the O-020 pause for a Helper that doesn't say this
    "wordpressStartPage": true,
    // GET /v1/ledger and POST /v1/ledger/merge exist, so the browser engine can copy this
    // Helper's posts and hand over its own (D-082); a Helper without it has neither
    "ledgerMerge": true,
  }))
}

/// Installs every missing tool now (Settings → "Set up tools"), instead of on first use.
async fn install_tools(
  State(st): State<AppState>,
  _t: PairedToken,
) -> Result<impl IntoResponse, ApiError> {
  let mut out = serde_json::Map::new();
  for tool in [Tool::YtDlp, Tool::Deno, Tool::Ffmpeg, Tool::Ffprobe] {
    if st.tools.bins.find(tool).is_none() {
      let _g = st.tools.install.lock().await;
      if st.tools.bins.find(tool).is_none() {
        st.tools
          .bins
          .install(&st.tools.http, tool)
          .await
          .map_err(|e| missing(tool, Some(e.to_string())))?;
      }
    }
    out.insert(tool_key(tool).into(), json!(true));
  }
  Ok(Json(Value::Object(out)))
}

fn tool_key(t: Tool) -> &'static str {
  match t {
    Tool::YtDlp => "ytdlp",
    Tool::Ffmpeg => "ffmpeg",
    Tool::Ffprobe => "ffprobe",
    Tool::Deno => "deno",
  }
}

#[derive(Deserialize)]
struct CatalogBody {
  url: String,
  #[serde(default)]
  cursor: Option<String>,
}

/// One page (≤200) of a source, listed flat by yt-dlp. Empty tabs (a channel with no Shorts)
/// are skipped, so a page is only empty when the whole source is.
async fn list_catalog(
  State(st): State<AppState>,
  _t: PairedToken,
  body: Option<Json<CatalogBody>>,
) -> Result<impl IntoResponse, ApiError> {
  let Json(b) = body.ok_or_else(|| ApiError::bad_request("Send the source URL."))?;
  let url = ytdlp::checked_url(&b.url)
    .ok_or_else(|| ApiError::bad_request("That doesn't look like a web address."))?
    .to_string();
  let exe = st.tools.ensure(Tool::YtDlp).await?;
  let tabs = catalog::tabs(&url);
  let youtube = catalog::platform_of(&url, None) == "youtube";
  let tools = st.tools.ytdlp_tools(youtube).await;
  let mut cursor = Cursor::parse(b.cursor.as_deref());
  if cursor.tab >= tabs.len() {
    cursor = Cursor { tab: 0, start: 1 };
  }
  let mut seen = {
    let mut l = st.tools.listings.lock().unwrap_or_else(|e| e.into_inner());
    let prior = l.remove(&url);
    if b.cursor.is_some() {
      prior.unwrap_or_default()
    } else {
      HashSet::new()
    }
  };
  let mut source: Option<Value> = None;
  let page = loop {
    let (tab_url, tab) = &tabs[cursor.tab];
    let args = ytdlp::catalog_args(
      tab_url,
      cursor.start,
      cursor.start + catalog::PAGE - 1,
      &tools,
    );
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let doc = match ytdlp::run(&exe, &args, rx, |_| {}).await {
      Ok(out) => serde_json::from_str::<Value>(out.stdout.trim()).map_err(|e| {
        ApiError::new(
          StatusCode::BAD_GATEWAY,
          "unknown",
          "yt-dlp returned something the Helper couldn't read.",
        )
        .with_verbatim(e.to_string())
      })?,
      // A missing tab on an expanded channel (no Shorts, never streamed) is just empty.
      Err(ytdlp::RunError::Failed { .. }) if tabs.len() > 1 && cursor.tab > 0 => json!({}),
      Err(e) => return Err(run_error(e)),
    };
    let p = catalog::map_window(&doc, cursor, tabs.len(), *tab, &url, &mut seen);
    if source.is_none() && p.title.is_some() {
      source = Some(json!({ "title": p.title, "handle": p.handle, "total": p.total }));
    }
    match (&p.next, p.items.is_empty()) {
      (Some(n), true) => cursor = Cursor::parse(Some(n)),
      _ => break p,
    }
  };
  if page.next.is_some() {
    st.tools
      .listings
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .insert(url.clone(), seen);
  }
  let mut res = json!({ "items": page.items });
  if let Some(n) = page.next {
    res["next"] = json!(n);
  }
  if let Some(mut s) = source {
    if let Some(o) = s.as_object_mut() {
      o.retain(|_, v| !v.is_null());
    }
    res["source"] = s;
  }
  Ok(Json(res))
}

fn failure(f: Failure) -> ApiError {
  let status = match f.code {
    "notFound404" => StatusCode::NOT_FOUND,
    "duplicate" | "stopped" => StatusCode::CONFLICT,
    _ => StatusCode::BAD_REQUEST,
  };
  let e = ApiError::new(status, f.code, f.message);
  match f.verbatim {
    Some(v) => e.with_verbatim(v),
    None => e,
  }
}

/// An export zip dropped on bunniehop.party, streamed here over loopback (never anywhere else).
async fn upload_export(
  State(st): State<AppState>,
  _t: PairedToken,
  body: axum::body::Body,
) -> Result<impl IntoResponse, ApiError> {
  use futures_util::StreamExt;
  use tokio::io::AsyncWriteExt;
  let (id, path) = st.hub.exports().create().map_err(|e| {
    ApiError::internal("Couldn't make room for the export.").with_verbatim(e.to_string())
  })?;
  let write = async {
    let mut f = tokio::fs::File::create(&path).await?;
    let mut stream = body.into_data_stream();
    let mut n: u64 = 0;
    while let Some(chunk) = stream.next().await {
      let chunk = chunk.map_err(std::io::Error::other)?;
      n += chunk.len() as u64;
      f.write_all(&chunk).await?;
    }
    f.flush().await?;
    Ok::<u64, std::io::Error>(n)
  };
  let bytes = match write.await {
    Ok(n) => n,
    Err(e) => {
      st.hub.exports().remove(&id);
      return Err(
        ApiError::new(
          StatusCode::INSUFFICIENT_STORAGE,
          "diskFull",
          "Couldn't save the export on this computer.",
        )
        .with_verbatim(e.to_string()),
      );
    }
  };
  let p2 = path.clone();
  match tokio::task::spawn_blocking(move || crate::exports::check_zip(&p2)).await {
    Ok(Ok(_)) => Ok(Json(json!({ "exportId": id, "bytes": bytes }))),
    other => {
      st.hub.exports().remove(&id);
      let v = match other {
        Ok(Err(e)) => e,
        Err(e) => e.to_string(),
        Ok(Ok(_)) => String::new(),
      };
      Err(ApiError::bad_request("That file isn't a readable zip.").with_verbatim(v))
    }
  }
}

async fn start_hop(
  State(st): State<AppState>,
  _t: PairedToken,
  body: Option<Json<Value>>,
) -> Result<impl IntoResponse, ApiError> {
  let Json(plan) = body.ok_or_else(|| ApiError::bad_request("Send a hop plan."))?;
  let id = st.hub.start(plan).map_err(failure)?;
  Ok(Json(json!({ "hopId": id })))
}

async fn hop_action(
  State(st): State<AppState>,
  _t: PairedToken,
  axum::extract::Path((id, action)): axum::extract::Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
  match action.as_str() {
    "pause" => st.hub.pause(&id),
    "resume" => st.hub.resume(&id),
    "cancel" => st.hub.cancel(&id),
    _ => {
      return Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "notFound404",
        "No such hop action.",
      ))
    }
  }
  .map_err(failure)?;
  Ok(StatusCode::NO_CONTENT)
}

async fn cell_action(
  State(st): State<AppState>,
  _t: PairedToken,
  axum::extract::Path((id, item, dest, action)): axum::extract::Path<(
    String,
    String,
    String,
    String,
  )>,
) -> Result<StatusCode, ApiError> {
  match action.as_str() {
    "retry" => st.hub.retry(&id, &item, &dest),
    "skip" => st.hub.skip(&id, &item, &dest),
    "postAgain" => st.hub.post_again(&id, &item, &dest),
    _ => {
      return Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "notFound404",
        "No such item action.",
      ))
    }
  }
  .map_err(failure)?;
  Ok(StatusCode::NO_CONTENT)
}

async fn stop_all(State(st): State<AppState>, _t: PairedToken) -> StatusCode {
  st.hub.stop_all();
  StatusCode::NO_CONTENT
}

/// What this Helper has posted (D11), for the browser engine to merge (D-082). Keys, states and
/// destination links only; no credentials.
async fn ledger(State(st): State<AppState>, _t: PairedToken) -> Json<serde_json::Value> {
  Json(serde_json::json!({ "entries": st.hub.ledger() }))
}

#[derive(Deserialize)]
struct LedgerBody {
  entries: HashMap<String, serde_json::Value>,
}

/// The browser engine's posts, so a Helper hop never posts them again (D-082).
async fn merge_ledger(
  State(st): State<AppState>,
  _t: PairedToken,
  body: Result<Json<LedgerBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
  let Json(b) = body
    .map_err(|e| ApiError::bad_request("Send the ledger entries.").with_verbatim(e.body_text()))?;
  Ok(Json(
    serde_json::json!({ "changed": st.hub.merge_ledger(&b.entries) }),
  ))
}

#[derive(Deserialize)]
struct FolderBody {
  path: String,
}

/// Opens a vault folder in Finder / Explorer. Only paths inside the vault are accepted.
async fn open_folder(
  State(st): State<AppState>,
  _t: PairedToken,
  body: Option<Json<FolderBody>>,
) -> Result<StatusCode, ApiError> {
  let Json(b) = body.ok_or_else(|| ApiError::bad_request("Send a folder."))?;
  let refuse = || {
    ApiError::new(
      StatusCode::FORBIDDEN,
      "originNotAllowed",
      "Only folders inside the vault can be opened.",
    )
  };
  let vault = std::fs::canonicalize(&st.vault_dir).map_err(|_| {
    ApiError::new(
      StatusCode::NOT_FOUND,
      "vaultUnavailable",
      "The vault folder doesn't exist yet.",
    )
  })?;
  let path = std::fs::canonicalize(&b.path).map_err(|_| refuse())?;
  if !path.starts_with(&vault) || !path.is_dir() {
    return Err(refuse());
  }
  let opener = if cfg!(target_os = "macos") {
    "open"
  } else if cfg!(windows) {
    "explorer"
  } else {
    "xdg-open"
  };
  tokio::process::Command::new(opener)
    .arg(&path)
    .spawn()
    .map_err(|e| ApiError::internal("Couldn't open the folder.").with_verbatim(e.to_string()))?;
  Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct EventsHello {
  token: String,
  #[serde(default)]
  since: Option<u64>,
}

/// `/v1/events`: the first message carries the token (never the URL), then replay + live.
async fn events(State(st): State<AppState>, ws: axum::extract::ws::WebSocketUpgrade) -> Response {
  ws.on_upgrade(move |socket| stream_events(st, socket))
}

async fn stream_events(st: AppState, mut socket: axum::extract::ws::WebSocket) {
  use axum::extract::ws::{CloseFrame, Message};
  let first = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv()).await;
  let hello = match first {
    Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str::<EventsHello>(t.as_str()).ok(),
    _ => None,
  };
  let Some(hello) = hello.filter(|h| st.pairing.verify(&h.token)) else {
    let _ = socket
      .send(Message::Close(Some(CloseFrame {
        code: 4401,
        reason: "notPaired".into(),
      })))
      .await;
    return;
  };
  let (replay, mut rx) = st.hub.subscribe(hello.since.unwrap_or(0));
  let mut last = hello.since.unwrap_or(0);
  for env in replay {
    last = env.seq;
    let text = serde_json::to_string(&env).unwrap_or_default();
    if socket.send(Message::Text(text.into())).await.is_err() {
      return;
    }
  }
  loop {
    tokio::select! {
      msg = rx.recv() => match msg {
        Ok(env) if env.seq > last => {
          last = env.seq;
          let text = serde_json::to_string(&env).unwrap_or_default();
          if socket.send(Message::Text(text.into())).await.is_err() {
            return;
          }
        }
        Ok(_) => {}
        // Fell behind: close, and the browser reconnects with `since` to replay the gap.
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
          let _ = socket.send(Message::Close(None)).await;
          return;
        }
        Err(_) => return,
      },
      incoming = socket.recv() => match incoming {
        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
        _ => {}
      },
    }
  }
}

fn run_error(e: ytdlp::RunError) -> ApiError {
  match e {
    ytdlp::RunError::Cancelled => {
      ApiError::new(StatusCode::CONFLICT, "stopped", "Listing was stopped.")
    }
    ytdlp::RunError::Spawn(v) => ApiError::new(
      StatusCode::SERVICE_UNAVAILABLE,
      "needsHelper",
      "The Helper couldn't start yt-dlp.",
    )
    .with_verbatim(v),
    ytdlp::RunError::Failed { code, verbatim } => {
      let status = match code {
        "notFound404" => StatusCode::NOT_FOUND,
        "rateLimited429" => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::BAD_GATEWAY,
      };
      ApiError::new(status, code, "The source couldn't be listed.").with_verbatim(verbatim)
    }
  }
}

pub fn iso(t: SystemTime) -> String {
  let secs = t
    .duration_since(SystemTime::UNIX_EPOCH)
    .map(|d| d.as_secs() as i64)
    .unwrap_or(0);
  time::OffsetDateTime::from_unix_timestamp(secs)
    .ok()
    .and_then(|d| {
      d.format(&time::format_description::well_known::Rfc3339)
        .ok()
    })
    .unwrap_or_default()
}

/// Binds the first free port in [`crate::PORTS`] on loopback only.
pub async fn bind() -> std::io::Result<(tokio::net::TcpListener, u16)> {
  let mut last = None;
  for port in crate::PORTS {
    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
      Ok(l) => return Ok((l, port)),
      Err(e) => last = Some(e),
    }
  }
  Err(last.unwrap_or_else(|| std::io::Error::other("no port")))
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::Body;
  use http_body_util::BodyExt;
  use std::sync::Mutex;
  use tower::ServiceExt;

  struct Fx {
    app: Router,
    shown: Arc<Mutex<Vec<String>>>,
    hub: Arc<Hub>,
    _dir: tempfile::TempDir,
  }

  fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let shown = Arc::new(Mutex::new(Vec::new()));
    let s2 = shown.clone();
    let st = test_state(
      dir.path(),
      Arc::new(move |c: &str| s2.lock().unwrap().push(c.to_string())),
      Arc::new(|_: &str| {}),
    );
    let hub = st.hub.clone();
    Fx {
      app: router(st),
      shown,
      hub,
      _dir: dir,
    }
  }

  fn req(
    method: &str,
    path: &str,
    origin: Option<&str>,
    token: Option<&str>,
    body: Option<serde_json::Value>,
  ) -> Request<Body> {
    let mut b = Request::builder()
      .method(method)
      .uri(path)
      .header("host", "127.0.0.1:17333");
    if let Some(o) = origin {
      b = b.header("origin", o);
    }
    if let Some(t) = token {
      b = b.header("authorization", format!("Bearer {t}"));
    }
    match body {
      Some(v) => b
        .header("content-type", "application/json")
        .body(Body::from(v.to_string()))
        .unwrap(),
      None => b.body(Body::empty()).unwrap(),
    }
  }

  async fn send(app: &Router, r: Request<Body>) -> (StatusCode, HeaderMap, serde_json::Value) {
    let res = app.clone().oneshot(r).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
      status,
      headers,
      serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
  }

  #[tokio::test]
  async fn pairing_origin_allow_list_is_bunniehop_party_only() {
    let f = fx();
    let (s, h, _) = send(
      &f.app,
      req("GET", "/v1/hello", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.get("access-control-allow-origin").unwrap(), PROD_ORIGIN);
    for bad in [
      Some("https://evil.example"),
      Some("http://localhost:5173"),
      Some("https://bunniehop.party.evil.example"),
      None,
    ] {
      let (s, h, b) = send(&f.app, req("GET", "/v1/hello", bad, None, None)).await;
      assert_eq!(s, StatusCode::FORBIDDEN, "{bad:?}");
      assert_eq!(b["code"], "originNotAllowed");
      assert!(h.get("access-control-allow-origin").is_none());
    }
    // simple POSTs skip the CORS preflight, so the server must refuse them itself
    let (s, _, _) = send(
      &f.app,
      req(
        "POST",
        "/v1/pair/start",
        Some("https://evil.example"),
        None,
        None,
      ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(f.shown.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn pairing_rejects_rebinding_hosts() {
    let f = fx();
    let r = Request::builder()
      .uri("/v1/hello")
      .header("host", "attacker.example:17333")
      .header("origin", PROD_ORIGIN)
      .body(Body::empty())
      .unwrap();
    let (s, _, _) = send(&f.app, r).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn pairing_preflight_allows_private_network_access() {
    let f = fx();
    let (s, h, _) = send(
      &f.app,
      req("OPTIONS", "/v1/status", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
      h.get("access-control-allow-private-network").unwrap(),
      "true"
    );
    assert!(h
      .get("access-control-allow-headers")
      .unwrap()
      .to_str()
      .unwrap()
      .contains("authorization"));
  }

  #[tokio::test]
  async fn pairing_page_shows_the_code_only_on_this_computer() {
    let f = fx();
    let page = |host: &str| {
      Request::builder()
        .uri(PAIR_PAGE)
        .header("host", host)
        .body(Body::empty())
        .unwrap()
    };
    let get = |host: &'static str| {
      let app = f.app.clone();
      async move {
        let r = app.oneshot(page(host)).await.unwrap();
        let (s, h) = (r.status(), r.headers().clone());
        let b = r.into_body().collect().await.unwrap().to_bytes();
        (s, h, String::from_utf8_lossy(&b).to_string())
      }
    };
    let (s, _, b) = get("127.0.0.1:17333").await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.contains("No pairing is waiting") && !b.contains("424"));
    send(
      &f.app,
      req("POST", "/v1/pair/start", Some(PROD_ORIGIN), None, None),
    )
    .await;
    let (s, h, b) = get("127.0.0.1:17333").await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.contains("424 242"), "{b}");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["cache-control"], "no-store");
    assert!(
      h.get("access-control-allow-origin").is_none(),
      "no site can read it"
    );
    let (s, _, b) = get("evil.example:17333").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "DNS rebinding refused");
    assert!(!b.contains("424"));
  }

  #[tokio::test]
  async fn pairing_flow_code_then_token_then_authenticated_status() {
    let f = fx();
    let (s, _, _) = send(
      &f.app,
      req("GET", "/v1/status", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, b) = send(
      &f.app,
      req("POST", "/v1/pair/start", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["expiresAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(f.shown.lock().unwrap().as_slice(), ["424242"]);
    let (s, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/pair/finish",
        Some(PROD_ORIGIN),
        None,
        Some(json!({ "code": "111111" })),
      ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["code"], "pairingFailed");
    let (_, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/pair/finish",
        Some(PROD_ORIGIN),
        None,
        Some(json!({ "code": "424242", "label": "Chrome" })),
      ),
    )
    .await;
    let token = b["token"].as_str().unwrap().to_string();
    let (s, _, b) = send(
      &f.app,
      req("GET", "/v1/status", Some(PROD_ORIGIN), Some(&token), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["paired"], true);
    let (s, _, _) = send(
      &f.app,
      req("GET", "/v1/status", Some(PROD_ORIGIN), Some("wrong"), None),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = send(
      &f.app,
      req("DELETE", "/v1/pair", Some(PROD_ORIGIN), Some(&token), None),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = send(
      &f.app,
      req("GET", "/v1/status", Some(PROD_ORIGIN), Some(&token), None),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
  }

  async fn paired(f: &Fx) -> String {
    send(
      &f.app,
      req("POST", "/v1/pair/start", Some(PROD_ORIGIN), None, None),
    )
    .await;
    let (_, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/pair/finish",
        Some(PROD_ORIGIN),
        None,
        Some(json!({ "code": "424242" })),
      ),
    )
    .await;
    b["token"].as_str().unwrap().to_string()
  }

  /// A stand-in yt-dlp: Videos has one window of two items, Shorts repeats one of them,
  /// Streams doesn't exist (yt-dlp errors), like a real channel without live streams.
  #[cfg(unix)]
  fn fake_ytdlp(f: &Fx) {
    let bin = f._dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = bin.join("yt-dlp");
    std::fs::write(
      &script,
      r#"#!/bin/sh
for a; do last="$a"; done
case "$last" in
  */videos) echo '{"channel":"Mara Vee","uploader_id":"@maravee","playlist_count":3,"entries":[{"id":"a1","url":"https://www.youtube.com/watch?v=a1","title":"One"},{"id":"s1","url":"https://www.youtube.com/shorts/s1","title":"Short"}]}' ;;
  */shorts) echo '{"entries":[{"id":"s1","url":"https://www.youtube.com/shorts/s1"},{"id":"s2","url":"https://www.youtube.com/shorts/s2"}]}' ;;
  */streams) echo 'ERROR: [youtube:tab] @maravee: This channel does not have a streams tab' >&2; exit 1 ;;
  *) echo 'ERROR: [generic] Unable to download webpage: HTTP Error 404: Not Found' >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn catalog_route_pages_a_channel_tab_by_tab() {
    let f = fx();
    fake_ytdlp(&f);
    let t = paired(&f).await;
    let list = |cursor: Option<&str>| {
      let mut body = json!({ "url": "https://www.youtube.com/@maravee" });
      if let Some(c) = cursor {
        body["cursor"] = json!(c);
      }
      req(
        "POST",
        "/v1/catalog",
        Some(PROD_ORIGIN),
        Some(&t),
        Some(body),
      )
    };
    let (s, _, b) = send(&f.app, list(None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["items"].as_array().unwrap().len(), 2);
    assert_eq!(b["source"]["title"], "Mara Vee");
    assert_eq!(b["source"]["handle"], "maravee");
    assert_eq!(b["next"], "1:1");
    let (_, _, b) = send(&f.app, list(Some("1:1"))).await;
    let ids: Vec<_> = b["items"]
      .as_array()
      .unwrap()
      .iter()
      .map(|i| i["id"].clone())
      .collect();
    assert_eq!(ids, [json!("s2")], "s1 was already listed under Videos");
    assert_eq!(b["items"][0]["kind"], "short");
    assert_eq!(b["next"], "2:1");
    let (s, _, b) = send(&f.app, list(Some("2:1"))).await;
    assert_eq!(
      s,
      StatusCode::OK,
      "a missing Streams tab is empty, not an error"
    );
    assert!(b["items"].as_array().unwrap().is_empty());
    assert!(b.get("next").is_none());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn catalog_route_reports_the_source_error_verbatim() {
    let f = fx();
    fake_ytdlp(&f);
    let t = paired(&f).await;
    let (s, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/catalog",
        Some(PROD_ORIGIN),
        Some(&t),
        Some(json!({ "url": "https://example.org/gone" })),
      ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(b["code"], "notFound404");
    assert!(b["verbatim"].as_str().unwrap().contains("HTTP Error 404"));
    let (s, _, _) = send(
      &f.app,
      req(
        "POST",
        "/v1/catalog",
        Some(PROD_ORIGIN),
        Some(&t),
        Some(json!({ "url": "--exec=rm" })),
      ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "only http(s) URLs reach yt-dlp");
  }

  #[tokio::test]
  async fn capabilities_say_ledger_merge() {
    let f = fx();
    let t = paired(&f).await;
    let (s, _, b) = send(
      &f.app,
      req("GET", "/v1/capabilities", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // the web app copies ledgers both ways only with a Helper that says this (plan 2026-11-11 S5)
    assert_eq!(b["ledgerMerge"], true);
    // and the routes it promises answer
    let (s, _, b) = send(
      &f.app,
      req("GET", "/v1/ledger", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["entries"].is_object());
  }

  #[tokio::test]
  async fn capabilities_list_only_destinations_with_an_uploader() {
    let f = fx();
    let t = paired(&f).await;
    // a working ffmpeg on the computer still doesn't make transforms real
    let bin = f._dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join(Tool::Ffmpeg.exe()), b"fake").unwrap();
    let (s, _, b) = send(
      &f.app,
      req("GET", "/v1/capabilities", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["kind"], "helper");
    assert_eq!(b["canTransform"], false, "no promise of video edits");
    // the web app lifts the O-020 pause only for a Helper that says this (D-120)
    assert_eq!(b["wordpressStartPage"], true);
    assert!(b["sources"].as_array().unwrap().contains(&json!("youtube")));
    let d: Vec<_> = b["destinations"]
      .as_array()
      .unwrap()
      .iter()
      .map(|d| d["platform"].as_str().unwrap())
      .collect();
    assert_eq!(d, crate::connect::PLATFORMS);
    assert!(!d.contains(&"snapchat"), "no uploader yet → not offered");
    let (_, _, b) = send(
      &f.app,
      req("GET", "/v1/status", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert!(b["binaries"]["ytdlp"].is_boolean());
  }

  #[tokio::test]
  async fn export_upload_streams_a_zip_and_refuses_anything_else() {
    let f = fx();
    let t = paired(&f).await;
    let dir = tempfile::tempdir().unwrap();
    let zp = dir.path().join("a.zip");
    crate::exports::tests::make_zip(&zp, &[("data/tweets.js", b"window.YTD = []")]);
    let up = |bytes: Vec<u8>| {
      Request::builder()
        .method("POST")
        .uri("/v1/exports")
        .header("host", "127.0.0.1:17333")
        .header("origin", PROD_ORIGIN)
        .header("authorization", format!("Bearer {t}"))
        .header("content-type", "application/zip")
        .body(Body::from(bytes))
        .unwrap()
    };
    let (s, _, b) = send(&f.app, up(std::fs::read(&zp).unwrap())).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let id = b["exportId"].as_str().unwrap();
    assert!(b["bytes"].as_u64().unwrap() > 0);
    assert!(f.hub.exports().path(id).is_some());
    let (s, _, b) = send(&f.app, up(b"not a zip".to_vec())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(b["message"].as_str().unwrap().contains("zip"));
  }

  #[tokio::test]
  async fn ledger_routes_require_pairing() {
    let f = fx();
    let (s, _, _) = send(
      &f.app,
      req("GET", "/v1/ledger", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let body = json!({ "entries": { "bluesky|a1|export|x": { "state": "published", "at": "t" } } });
    let (s, _, _) = send(
      &f.app,
      req(
        "POST",
        "/v1/ledger/merge",
        Some(PROD_ORIGIN),
        None,
        Some(body.clone()),
      ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let t = paired(&f).await;
    let (s, _, _) = send(
      &f.app,
      req(
        "GET",
        "/v1/ledger",
        Some("https://evil.example"),
        Some(&t),
        None,
      ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(f.hub.ledger().is_empty(), "nothing merged without pairing");
  }

  #[tokio::test]
  async fn ledger_get_lists_entries() {
    let f = fx();
    let t = paired(&f).await;
    let (s, _, b) = send(
      &f.app,
      req("GET", "/v1/ledger", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!((s, b["entries"].clone()), (StatusCode::OK, json!({})));
    let body = json!({ "entries": {
      "bluesky|a1|export|x": { "state": "published", "destUrl": "https://bsky.app/x", "at": "t" },
      "bluesky|a1|export|y": { "state": "reserved", "at": "t" }
    } });
    let (s, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/ledger/merge",
        Some(PROD_ORIGIN),
        Some(&t),
        Some(body),
      ),
    )
    .await;
    assert_eq!((s, b["changed"].as_u64()), (StatusCode::OK, Some(2)));
    let (_, _, b) = send(
      &f.app,
      req("GET", "/v1/ledger", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!(
      b["entries"]["bluesky|a1|export|x"]["destUrl"],
      "https://bsky.app/x"
    );
    assert_eq!(
      b["entries"]["bluesky|a1|export|y"]["state"],
      "publishedUnverified"
    );
    let (s, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/ledger/merge",
        Some(PROD_ORIGIN),
        Some(&t),
        Some(json!({ "entries": [] })),
      ),
    )
    .await;
    assert_eq!(
      (s, b["code"].as_str()),
      (StatusCode::BAD_REQUEST, Some("unknown"))
    );
  }

  #[tokio::test]
  async fn hop_routes_need_pairing_and_check_the_plan() {
    let f = fx();
    let (s, _, _) = send(
      &f.app,
      req("POST", "/v1/stop-all", Some(PROD_ORIGIN), None, None),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let t = paired(&f).await;
    let (s, _, _) = send(
      &f.app,
      req("POST", "/v1/stop-all", Some(PROD_ORIGIN), Some(&t), None),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, b) = send(
      &f.app,
      req(
        "POST",
        "/v1/hops/nope/pause",
        Some(PROD_ORIGIN),
        Some(&t),
        None,
      ),
    )
    .await;
    assert_eq!(
      (s, b["code"].as_str()),
      (StatusCode::NOT_FOUND, Some("notFound404"))
    );
    let (s, _, b) = send(
      &f.app,
      req("POST", "/v1/hops", Some(PROD_ORIGIN), Some(&t), Some(json!({ "id": "h1", "items": [{ "id": "a" }], "destinations": [], "vault": { "kind": "s3", "target": "x" } }))),
    )
    .await;
    assert_eq!(
      (s, b["code"].as_str()),
      (StatusCode::BAD_REQUEST, Some("notSupported"))
    );
    // Dropbox ships, but needs its sign-in first
    let (_, _, b) = send(
      &f.app,
      req("POST", "/v1/hops", Some(PROD_ORIGIN), Some(&t), Some(json!({ "id": "h2", "items": [{ "id": "a" }], "destinations": [], "vault": { "kind": "dropbox", "target": "/BunnieHop" } }))),
    )
    .await;
    assert_eq!(b["code"], "signInRequired");
  }

  #[tokio::test]
  async fn open_folder_only_inside_the_vault() {
    let f = fx();
    let t = paired(&f).await;
    std::fs::create_dir_all(f._dir.path().join("vault")).unwrap();
    for bad in [
      "/",
      "/etc",
      &format!("{}/vault/../bin", f._dir.path().display()),
    ] {
      let (s, _, _) = send(
        &f.app,
        req(
          "POST",
          "/v1/open-folder",
          Some(PROD_ORIGIN),
          Some(&t),
          Some(json!({ "path": bad })),
        ),
      )
      .await;
      assert_ne!(s, StatusCode::NO_CONTENT, "{bad}");
    }
  }

  #[test]
  fn pairing_dev_origins_only_in_dev_builds() {
    assert_eq!(allowed_origins(false), vec![PROD_ORIGIN.to_string()]);
    assert!(allowed_origins(true).contains(&"http://localhost:5173".to_string()));
  }
}

#[cfg(test)]
mod telegram_guard_tests {
  use super::*;
  use axum::{body::Body, http::Request};
  use tower::ServiceExt;

  #[tokio::test]
  async fn telegram_local_origin_table_preserves_existing_guards() {
    let dir = tempfile::tempdir().unwrap();
    let st = test_state(dir.path(), Arc::new(|_| {}), Arc::new(|_| {}));
    let app = router(st);
    for (path, origin, status) in [
      ("/telegram/step", Some("http://127.0.0.1:17333"), 401),
      ("/telegram/step", Some(PROD_ORIGIN), 403),
      ("/telegram/step", Some("https://elsewhere.example"), 403),
      ("/telegram/step", Some("http://localhost:17333"), 403),
      ("/telegram/step", Some("http://127.0.0.1:17334"), 403),
      ("/telegram/step", None, 403),
      ("/v1/hello", Some(PROD_ORIGIN), 200),
      ("/v1/hello", Some("http://127.0.0.1:17333"), 403),
      ("/v1/hello", Some("https://elsewhere.example"), 403),
      ("/v1/hello", None, 403),
    ] {
      let mut r = Request::builder()
        .method(if path.ends_with("step") {
          "POST"
        } else {
          "GET"
        })
        .uri(path)
        .header("host", "127.0.0.1:17333")
        .header("content-type", "application/json");
      if let Some(o) = origin {
        r = r.header("origin", o);
      }
      let res = app
        .clone()
        .oneshot(r.body(Body::from("{} ")).unwrap())
        .await
        .unwrap();
      assert_eq!(res.status().as_u16(), status, "{path} {origin:?}");
    }
  }
}

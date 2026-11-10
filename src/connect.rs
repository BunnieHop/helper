//! `/v1/connections`: signing destination accounts in on this computer (PLAN §6.3 lazy sign-in).
//! Credentials go from bunniehop.party straight to this Helper over loopback, are checked with
//! the platform, and are stored in the OS keychain. They never reach BunnieHop's servers (D8).

use crate::connections::{new_id, Connection};
use crate::error::ApiError;
use crate::hops::Failure;
use crate::server::{iso, AppState, PairedToken};
use crate::uploaders::{
  atproto_oauth, base_url, bluesky, discord, ghost, linkedin, mastodon, peertube, wordpress,
  youtube,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub const CALLBACK_PATH: &str = "/v1/oauth/callback";
/// Where api.bunniehop.party's OAuth relay sends the browser back (apps/worker/src/oauth.ts).
pub const RELAY_CALLBACK_PATH: &str = "/oauth/callback";
/// Sign-ins that come back to a bunniehop.party page (WordPress app approval) are handed to the
/// Helper here by that page; only a sign-in this Helper started (by `state`) is completed.
pub const RETURN_PATH: &str = "/v1/oauth/return";
const CODE_WAIT: Duration = Duration::from_secs(600);
/// Destinations with a shipped uploader (capabilities, D12).
pub const PLATFORMS: [&str; 16] = [
  "bluesky",
  "mastodon",
  "pixelfed",
  "peertube",
  "discord",
  "ghost",
  "wordpress",
  "linkedin",
  "youtube",
  "facebook",
  "threads",
  "instagram",
  "pinterest",
  "tiktok",
  "tumblr",
  "telegram",
];
/// Cloud vault accounts the Helper can sign in to (capabilities `vaults`).
pub const VAULT_ACCOUNTS: [&str; 2] = ["dropbox", "google-drive"];
const SIGN_IN_WAIT: Duration = Duration::from_secs(300);

pub fn routes() -> Router<AppState> {
  Router::new()
    .route("/v1/connections", get(list))
    .route("/v1/connections/{key}", post(connect).delete(remove))
    .route(
      "/v1/connections/{key}/publish-options",
      get(publish_options),
    )
    .route(CALLBACK_PATH, get(callback))
    .route(RELAY_CALLBACK_PATH, get(callback))
    .route(RETURN_PATH, post(returned))
}

fn fail(f: Failure) -> ApiError {
  let status = match f.code {
    "signInRequired" | "tokenExpired" => StatusCode::UNAUTHORIZED,
    "notSupported" => StatusCode::BAD_REQUEST,
    "rateLimited429" => StatusCode::TOO_MANY_REQUESTS,
    "networkLost" | "server5xx" => StatusCode::BAD_GATEWAY,
    _ => StatusCode::BAD_REQUEST,
  };
  let e = ApiError::new(status, f.code, f.message);
  match f.verbatim {
    Some(v) => e.with_verbatim(v),
    None => e,
  }
}

async fn list(State(st): State<AppState>, _t: PairedToken) -> impl IntoResponse {
  Json(st.connections.list())
}

#[derive(Deserialize, Default)]
struct ConnectBody {
  #[serde(default)]
  fields: HashMap<String, String>,
}

fn field<'a>(f: &'a HashMap<String, String>, k: &str, ask: &str) -> Result<&'a str, ApiError> {
  f.get(k)
    .map(|s| s.trim())
    .filter(|s| !s.is_empty())
    .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "requiredChoiceMissing", ask))
}

fn opt<'a>(f: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
  f.get(k).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn new_state() -> String {
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use base64::Engine;
  URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

async fn connect(
  State(st): State<AppState>,
  _t: PairedToken,
  headers: axum::http::HeaderMap,
  Path(platform): Path<String>,
  body: Option<Json<ConnectBody>>,
) -> Result<Json<Connection>, ApiError> {
  let f = body.map(|Json(b)| b.fields).unwrap_or_default();
  // the bunniehop.party page a sign-in returns to (the guard already checked this origin)
  let web = headers
    .get(axum::http::header::ORIGIN)
    .and_then(|v| v.to_str().ok())
    .unwrap_or(crate::server::PROD_ORIGIN)
    .to_string();
  let now = iso(SystemTime::now());
  let conn = |label: String, choices: HashMap<String, String>| Connection {
    id: new_id(&platform),
    platform: platform.clone(),
    label,
    path: "api".into(),
    checked_at: now.clone(),
    choices,
    account: String::new(),
  };
  let (c, secret) = match platform.as_str() {
    "telegram" => return telegram_connect(&st, &f).await,
    "bluesky" => {
      let handle = field(
        &f,
        "handle",
        "Type your Bluesky handle, for example you.bsky.social.",
      )?;
      match opt(&f, "appPassword") {
        // advanced fallback: an app password the creator already made
        Some(pass) => {
          let service = match opt(&f, "service") {
            Some(s) => base_url(s).map_err(fail)?,
            None => "https://bsky.social".into(),
          };
          let (did, handle) = bluesky::connect(&st.http, &service, handle, pass)
            .await
            .map_err(fail)?;
          (
            conn(format!("@{handle}"), HashMap::new()),
            json!({ "service": service, "identifier": did, "appPassword": pass }),
          )
        }
        // the creator's own server shows its sign-in page; nothing to paste
        None => {
          let state = new_state();
          let (authorize, pending) = atproto_oauth::begin(&st.http, &st.endpoints, handle, &state)
            .await
            .map_err(fail)?;
          let open = format!(
            "{}/oauth/bluesky/start?return={}&state={state}&authorize={}",
            st.endpoints.worker,
            crate::uploaders::ghost::urlencode(&format!("http://127.0.0.1:{}", st.port)),
            crate::uploaders::ghost::urlencode(&authorize)
          );
          let back = browser_return(&st, &state, &open).await?;
          let code = back["code"].as_str().unwrap_or("");
          let mut secret =
            atproto_oauth::finish(&st.http, &st.endpoints, pending, code, back["iss"].as_str())
              .await
              .map_err(fail)?;
          let h = handle.trim().trim_start_matches('@').to_ascii_lowercase();
          secret["handle"] = json!(h);
          (conn(format!("@{h}"), HashMap::new()), secret)
        }
      }
    }
    "peertube" => {
      let instance = field(
        &f,
        "instance",
        "Type your PeerTube server, for example peertube.tv.",
      )?;
      let user = field(&f, "username", "Type your PeerTube username.")?;
      let pass = f.get("password").filter(|p| !p.is_empty()).ok_or_else(|| {
        ApiError::new(
          StatusCode::BAD_REQUEST,
          "requiredChoiceMissing",
          "Type your PeerTube password.",
        )
      })?;
      let a = peertube::connect(&st.http, instance, user, pass)
        .await
        .map_err(fail)?;
      let mut choices = HashMap::new();
      let wanted = f
        .get("channel")
        .filter(|c| a.channels.iter().any(|(id, _)| id == *c));
      if let Some(ch) = wanted
        .cloned()
        .or_else(|| a.channels.first().map(|(id, _)| id.clone()))
      {
        choices.insert("channel".into(), ch);
      }
      (conn(a.label, choices), a.secret)
    }
    "mastodon" | "pixelfed" => {
      let instance = field(
        &f,
        "instance",
        "Type your server, for example mastodon.social.",
      )?;
      let base = base_url(instance).map_err(fail)?;
      let redirect = format!("http://127.0.0.1:{}{CALLBACK_PATH}", st.port);
      let (id, secret) = mastodon::register_app(&st.http, &base, &redirect)
        .await
        .map_err(fail)?;
      let state = hex::encode(rand::random::<[u8; 16]>());
      let code = browser_sign_in(
        &st,
        &state,
        &mastodon::authorize_url(&base, &id, &redirect, &state),
      )
      .await?;
      let (token, label) = mastodon::finish(&st.http, &base, (&id, &secret), &redirect, &code)
        .await
        .map_err(fail)?;
      (
        conn(label, HashMap::new()),
        json!({ "instance": base, "token": token }),
      )
    }
    "discord" => {
      // Discord's own page: the creator picks the server and channel, Discord makes the webhook
      let hook = match opt(&f, "webhook") {
        Some(h) => h.to_string(),
        None => {
          let tokens = relay_sign_in(&st, "discord").await?;
          tokens
            .pointer("/webhook/url")
            .and_then(Value::as_str)
            .ok_or_else(|| {
              ApiError::new(
                StatusCode::UNAUTHORIZED,
                "signInRequired",
                "Discord didn't finish connecting a channel. Try again and pick a channel.",
              )
            })?
            .to_string()
        }
      };
      let (url, label) = discord::connect(&st.http, &hook).await.map_err(fail)?;
      (conn(label, HashMap::new()), json!({ "url": url }))
    }
    "ghost" => {
      let url = field(
        &f,
        "site",
        "Type your Ghost site, for example mara.ghost.io.",
      )?;
      let (admin, key) = match opt(&f, "adminKey") {
        Some(k) => (url.to_string(), k.to_string()),
        None => {
          let email = field(&f, "email", "Type the email you sign in to Ghost with.")?;
          let password = field(&f, "password", "Type your Ghost password.")?;
          let code = opt(&f, "code");
          let pk = format!("{}|{}", url.to_lowercase(), email.to_lowercase());
          let waiting = code
            .and_then(|_| {
              st.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&pk)
            })
            .filter(|(_, _, at)| at.elapsed() < CODE_WAIT)
            .map(|(a, c, _)| (a, c));
          match ghost::sign_in(&st.http, url, email, password, waiting, code)
            .await
            .map_err(fail)?
          {
            ghost::SignIn::Key { admin, key } => (admin, key),
            ghost::SignIn::NeedsCode { admin, cookie } => {
              st.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(pk, (admin, cookie, std::time::Instant::now()));
              return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "verificationCode",
                "Ghost emailed you a sign-in code. Type it here.",
              ));
            }
          }
        }
      };
      let (label, secret) = ghost::connect(&st.http, &admin, &key).await.map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "dropbox" => {
      let tokens = relay_sign_in(&st, "dropbox").await?;
      let (label, secret) = crate::cloud::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "google-drive" => {
      let tokens = relay_sign_in(&st, "gdrive").await?;
      let (label, secret) = crate::gdrive::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "youtube" => {
      let tokens = relay_sign_in(&st, "youtube").await?;
      let (label, secret) = youtube::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "instagram" => {
      let tokens = relay_sign_in(&st, "instagram").await?;
      let (label, secret) =
        crate::uploaders::instagram::connect(&st.http, &st.endpoints, &tokens, opt(&f, "account"))
          .await
          .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "pinterest" => {
      let tokens = relay_sign_in(&st, "pinterest").await?;
      let (label, secret) =
        crate::uploaders::pinterest::connect(&st.http, &st.endpoints, &tokens, opt(&f, "board"))
          .await
          .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "tumblr" => {
      let tokens = relay_sign_in(&st, "tumblr").await?;
      let (label, secret) =
        crate::uploaders::tumblr::connect(&st.http, &st.endpoints, &tokens, opt(&f, "blog"))
          .await
          .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "tiktok" => {
      let tokens = relay_sign_in(&st, "tiktok").await?;
      let (label, secret) = crate::uploaders::tiktok::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "threads" => {
      let tokens = relay_sign_in(&st, "threads").await?;
      let (label, secret) = crate::uploaders::threads::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "facebook" => {
      let tokens = relay_sign_in(&st, "facebook").await?;
      let (label, secret) =
        crate::uploaders::facebook::connect(&st.http, &st.endpoints, &tokens, opt(&f, "page"))
          .await
          .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "linkedin" => {
      let tokens = relay_sign_in(&st, "linkedin").await?;
      let (label, secret) = linkedin::connect(&st.http, &st.endpoints, &tokens)
        .await
        .map_err(fail)?;
      (conn(label, HashMap::new()), secret)
    }
    "wordpress" => {
      let url = field(
        &f,
        "site",
        "Type your WordPress site, for example example.com/blog.",
      )?;
      let (label, secret) = match (opt(&f, "username"), opt(&f, "appPassword")) {
        (Some(u), Some(p)) => wordpress::connect(&st.http, url, u, p)
          .await
          .map_err(fail)?,
        // WordPress.com sites: WordPress.com's own sign-in page, the creator picks the site
        _ if wordpress::is_wpcom(&st.http, &st.endpoints, url).await => {
          let host = url
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
          let tokens = relay_sign_in_with(&st, "wpcom", &[("blog", &host)]).await?;
          wordpress::connect_wpcom(&st.http, &st.endpoints, &tokens)
            .await
            .map_err(fail)?
        }
        // self-hosted: the site's own "Authorize application" page
        _ => {
          let (site, user, pass) = wordpress_approve(&st, &web, url).await?;
          wordpress::connect(&st.http, &site, &user, &pass)
            .await
            .map_err(fail)?
        }
      };
      (conn(label, HashMap::new()), secret)
    }
    _ => {
      return Err(ApiError::new(
        StatusCode::BAD_REQUEST,
        "notSupported",
        format!("This Helper can't sign in to {platform} yet."),
      ));
    }
  };
  let saved = st.connections.save(c, &secret).map_err(|e| {
    ApiError::internal("Couldn't save the sign-in to this computer's keychain.").with_verbatim(e)
  })?;
  tracing::info!(platform = %saved.platform, "connected");
  Ok(Json(saved))
}

/// Opens `url` in the creator's browser and waits (≤5 min) for the platform to send the browser
/// back to this Helper with a code for `state`.
pub async fn browser_sign_in(st: &AppState, state: &str, url: &str) -> Result<String, ApiError> {
  let v = browser_return(st, state, url).await?;
  Ok(v["code"].as_str().unwrap_or("").to_string())
}

/// Like `browser_sign_in`, but returns everything the platform sent back (code, iss, …) as JSON.
pub async fn browser_return(st: &AppState, state: &str, url: &str) -> Result<Value, ApiError> {
  let (tx, rx) = tokio::sync::oneshot::channel();
  st.oauth
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(state.to_string(), tx);
  (st.open_url)(url);
  let code = tokio::time::timeout(SIGN_IN_WAIT, rx).await;
  st.oauth
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .remove(state);
  match code {
    Ok(Ok(c)) if !c.is_empty() => Ok(serde_json::from_str(&c).unwrap_or(Value::Null)),
    Ok(Ok(_)) => Err(ApiError::new(
      StatusCode::UNAUTHORIZED,
      "signInRequired",
      "The sign-in was cancelled.",
    )),
    _ => Err(ApiError::new(
      StatusCode::REQUEST_TIMEOUT,
      "signInRequired",
      "The sign-in window closed before it finished. Try again.",
    )),
  }
}

/// Sign-in through api.bunniehop.party for platforms that need a confidential client (LinkedIn,
/// Dropbox, Vimeo). The Worker only adds its client secret to the code exchange; the tokens come
/// back here and go to the keychain (D8). PKCE is always used where the platform supports it.
pub async fn relay_sign_in(st: &AppState, provider: &str) -> Result<Value, ApiError> {
  relay_sign_in_with(st, provider, &[]).await
}

/// `relay_sign_in` with hints for the platform's page (WordPress.com `blog` pre-selects a site).
pub async fn relay_sign_in_with(
  st: &AppState,
  provider: &str,
  hints: &[(&str, &str)],
) -> Result<Value, ApiError> {
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use base64::Engine;
  use sha2::{Digest, Sha256};
  let state = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
  let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
  let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
  let ret = format!("http://127.0.0.1:{}", st.port);
  let worker = &st.endpoints.worker;
  let mut q = format!(
    "return={}&state={state}&code_challenge={challenge}",
    crate::uploaders::ghost::urlencode(&ret)
  );
  for (k, v) in hints {
    q.push_str(&format!("&{k}={}", crate::uploaders::ghost::urlencode(v)));
  }
  let code = browser_sign_in(st, &state, &format!("{worker}/oauth/{provider}/start?{q}")).await?;
  let r = st
    .http
    .post(format!("{worker}/v1/oauth/{provider}/token"))
    .json(&json!({ "state": state, "code": code, "code_verifier": verifier }))
    .send()
    .await;
  crate::uploaders::json_or_fail(provider, r)
    .await
    .map_err(fail)
}

/// WordPress's own "Authorize application" page: the creator signs in to their site as usual and
/// clicks Approve; WordPress makes an application password and sends it back to a bunniehop.party
/// page, which hands it to this Helper over loopback. Nothing is typed but the site address.
///
/// The Helper opens bunniehop.party's `/connect/wp-start`, never WordPress itself: that page goes on
/// to the approve page only once the browser's BunnieHop service worker answers `/connect/return`
/// locally, so the password in WordPress's redirect never reaches a server (D-120). The site, state
/// and port ride in the fragment, which the browser keeps to itself.
async fn wordpress_approve(
  st: &AppState,
  web: &str,
  site: &str,
) -> Result<(String, String, String), ApiError> {
  use crate::uploaders::ghost::urlencode;
  let base = crate::uploaders::site_url(site).map_err(fail)?;
  let state = new_state();
  let url = format!(
    "{web}/connect/wp-start#site={}&state={state}&port={}",
    urlencode(&base),
    st.port
  );
  let v = browser_return(st, &state, &url).await?;
  let (Some(user), Some(pass)) = (v["user_login"].as_str(), v["password"].as_str()) else {
    return Err(ApiError::new(
      StatusCode::UNAUTHORIZED,
      "signInRequired",
      "WordPress didn't approve BunnieHop. Try again and click Approve.",
    ));
  };
  // WordPress may answer with its canonical address (www., a path); keep it only on the same site
  let host = |u: &str| {
    u.split("://")
      .nth(1)
      .unwrap_or(u)
      .split('/')
      .next()
      .unwrap_or("")
      .trim_start_matches("www.")
      .to_ascii_lowercase()
  };
  let site = match v["site_url"].as_str() {
    Some(s) if host(s) == host(&base) => s.to_string(),
    _ => base,
  };
  Ok((site, user.to_string(), pass.to_string()))
}

/// `POST /v1/oauth/return`: the bunniehop.party return page delivers what the platform sent back.
async fn returned(
  State(st): State<AppState>,
  Json(body): Json<HashMap<String, String>>,
) -> StatusCode {
  let tx = body
    .get("state")
    .and_then(|s| st.oauth.lock().unwrap_or_else(|e| e.into_inner()).remove(s));
  let Some(tx) = tx else {
    return StatusCode::BAD_REQUEST;
  };
  let out = if body.contains_key("rejected") {
    String::new()
  } else {
    serde_json::to_string(&body).unwrap_or_default()
  };
  let _ = tx.send(out);
  StatusCode::NO_CONTENT
}

/// `GET /v1/connections/{id}/publish-options`: what TikTok lets this account choose right now,
/// asked fresh each time the TikTok panel opens (D-066, O-015).
async fn publish_options(
  State(st): State<AppState>,
  _t: PairedToken,
  Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
  let missing = || {
    ApiError::new(
      StatusCode::NOT_FOUND,
      "signInRequired",
      "Connect TikTok first.",
    )
  };
  let c = st
    .connections
    .get(&id)
    .filter(|c| c.platform == "tiktok")
    .ok_or_else(missing)?;
  let secret = st.connections.secret(&c.id).ok_or_else(missing)?;
  let up = crate::uploaders::tiktok::TikTok::new(
    st.http.clone(),
    st.connections.clone(),
    &c.id,
    &secret,
    &st.endpoints,
    st.endpoints.upload_handles.clone(),
  )
  .ok_or_else(missing)?;
  let creator = up.creator().await.map_err(fail)?;
  Ok(Json(creator.to_json()))
}

async fn remove(State(st): State<AppState>, _t: PairedToken, Path(id): Path<String>) -> StatusCode {
  if st.connections.remove(&id) {
    StatusCode::NO_CONTENT
  } else {
    StatusCode::NOT_FOUND
  }
}

const PAGE: &str = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>BunnieHop</title><body style='font:16px system-ui;background:#0b0b10;color:#eee;display:grid;place-items:center;height:90vh'><p>";

async fn callback(
  State(st): State<AppState>,
  Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
  let tx = q
    .get("state")
    .and_then(|s| st.oauth.lock().unwrap_or_else(|e| e.into_inner()).remove(s));
  match tx {
    Some(tx) => {
      let ok = q.contains_key("code");
      let _ = tx.send(if ok {
        serde_json::to_string(&q).unwrap_or_default()
      } else {
        String::new()
      });
      let msg = if ok {
        "Signed in. You can close this tab and go back to BunnieHop."
      } else {
        "Sign-in cancelled. You can close this tab."
      };
      (StatusCode::OK, Html(format!("{PAGE}{msg}</p>")))
    }
    None => (
      StatusCode::BAD_REQUEST,
      Html(format!(
        "{PAGE}This sign-in link has expired. Start again from BunnieHop.</p>"
      )),
    ),
  }
}

/// Local Telegram sign-ins. A paired request creates one short-lived capability. Phone,
/// code and password are accepted only by the separate loopback router in server.rs.
#[derive(Default)]
pub struct TelegramSignIns {
  jobs: tokio::sync::Mutex<HashMap<String, TelegramJob>>,
  last_phone: tokio::sync::Mutex<Option<std::time::Instant>>,
}
struct TelegramJob {
  flow: crate::uploaders::telegram_user::SignIn,
  done: tokio::sync::oneshot::Sender<Connection>,
  created: std::time::Instant,
}
impl TelegramSignIns {
  pub(crate) async fn active(&self, state: &str) -> bool {
    self
      .jobs
      .lock()
      .await
      .get(state)
      .is_some_and(|j| j.created.elapsed() < crate::uploaders::telegram_user::SIGN_IN_TTL)
  }
}

async fn telegram_connect(
  st: &AppState,
  fields: &HashMap<String, String>,
) -> Result<Json<Connection>, ApiError> {
  if !fields.is_empty() {
    return Err(fail(Failure::new("notSupported", "Telegram sign-in takes place in the Helper's local page. Start again without sending sign-in details from the website.")));
  }
  let api = crate::uploaders::telegram_user::Gram::configured(None).map_err(fail)?;
  let state = new_state();
  let (tx, rx) = tokio::sync::oneshot::channel();
  {
    let mut jobs = st.connections.telegram.jobs.lock().await;
    jobs.retain(|_, j| j.created.elapsed() < crate::uploaders::telegram_user::SIGN_IN_TTL);
    if !jobs.is_empty() {
      return Err(fail(Failure::new(
        "signInRequired",
        "A Telegram sign-in is already open in the Helper. Finish it or wait for it to expire.",
      )));
    }
    jobs.insert(
      state.clone(),
      TelegramJob {
        flow: crate::uploaders::telegram_user::SignIn::new(Box::new(api)),
        done: tx,
        created: std::time::Instant::now(),
      },
    );
  }
  (st.open_url)(&format!(
    "http://127.0.0.1:{}/telegram?state={state}",
    st.port
  ));
  let result = tokio::time::timeout(crate::uploaders::telegram_user::SIGN_IN_TTL, rx).await;
  st.connections.telegram.jobs.lock().await.remove(&state);
  match result {
    Ok(Ok(c)) => Ok(Json(c)),
    _ => Err(ApiError::new(
      StatusCode::BAD_REQUEST,
      "signInRequired",
      "The Telegram sign-in closed or expired. Start again.",
    )),
  }
}

pub const TELEGRAM_PAGE: &str = "/telegram";
pub const TELEGRAM_STEP: &str = "/telegram/step";

pub fn telegram_routes() -> Router<AppState> {
  Router::new()
    .route(TELEGRAM_PAGE, get(telegram_page))
    .route(TELEGRAM_STEP, post(telegram_step))
    .layer(axum::extract::DefaultBodyLimit::max(4096))
}

/// Called by the additive guard before parsing any sign-in input.
pub fn telegram_capability(req: &axum::extract::Request) -> Option<String> {
  let state = if req.uri().path() == TELEGRAM_PAGE && req.method() == axum::http::Method::GET {
    req.uri().query().and_then(|q| q.strip_prefix("state="))
  } else {
    req
      .headers()
      .get(axum::http::header::AUTHORIZATION)
      .and_then(|v| v.to_str().ok())
      .and_then(|s| s.strip_prefix("Bearer "))
  };
  state.filter(|s| s.len() == 43).map(str::to_owned)
}

async fn telegram_page() -> impl IntoResponse {
  Html(include_str!("telegram-connect.html"))
}

#[derive(Deserialize)]
struct TelegramStep {
  stage: String,
  #[serde(default)]
  value: String,
}
async fn telegram_step(
  State(st): State<AppState>,
  headers: axum::http::HeaderMap,
  body: Result<Json<TelegramStep>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
  let state = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .unwrap_or("");
  let Json(input) = body.map_err(|_| {
    fail(Failure::new(
      "signInRequired",
      "The Helper couldn't read that sign-in step. Start again.",
    ))
  })?;
  let mut job = st
    .connections
    .telegram
    .jobs
    .lock()
    .await
    .remove(state)
    .ok_or_else(|| {
      fail(Failure::new(
        "signInRequired",
        "This Telegram sign-in expired. Start again.",
      ))
    })?;
  if job.created.elapsed() >= crate::uploaders::telegram_user::SIGN_IN_TTL {
    return Err(fail(Failure::new(
      "signInRequired",
      "This Telegram sign-in expired. Start again.",
    )));
  }
  if input.stage == "channel" {
    let (label, secret) = job.flow.finish(&input.value).await.map_err(fail)?;
    let c = st
      .connections
      .save(
        Connection {
          id: new_id("telegram"),
          platform: "telegram".into(),
          label,
          path: "api".into(),
          checked_at: iso(SystemTime::now()),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .map_err(|_| {
        ApiError::internal("Couldn't save the Telegram session to this computer's keychain.")
      })?;
    let _ = job.done.send(c);
    return Ok(Json(json!({"stage":"done"})));
  }
  if input.stage == "phone" {
    let mut last = st.connections.telegram.last_phone.lock().await;
    if last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
      return Err(fail(Failure::new(
        "rateLimited429",
        "Wait a minute before asking Telegram for another code.",
      )));
    }
    *last = Some(std::time::Instant::now());
  }
  let output = tokio::time::timeout(
    Duration::from_secs(60),
    job.flow.advance(&input.stage, &input.value),
  )
  .await
  .map_err(|_| {
    fail(Failure::new(
      "signInRequired",
      "Telegram did not answer in time. Check Telegram before starting sign-in again.",
    ))
  })?
  .map_err(fail)?;
  st.connections
    .telegram
    .jobs
    .lock()
    .await
    .insert(state.into(), job);
  Ok(Json(output))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::server::{router, test_state, PROD_ORIGIN};
  use crate::uploaders::testkit::serve;
  use axum::body::Body;
  use axum::http::Request;
  use http_body_util::BodyExt;
  use serde_json::Value;
  use std::sync::{Arc, Mutex};
  use tower::ServiceExt;

  async fn send(app: &Router, r: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(r).await.unwrap();
    let s = res.status();
    let b = res.into_body().collect().await.unwrap().to_bytes();
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
  }

  fn req(method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder()
      .method(method)
      .uri(path)
      .header("host", "127.0.0.1:17333")
      .header("origin", PROD_ORIGIN);
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

  async fn paired(app: &Router) -> String {
    send(app, req("POST", "/v1/pair/start", None, None)).await;
    send(
      app,
      req(
        "POST",
        "/v1/pair/finish",
        None,
        Some(json!({ "code": "424242" })),
      ),
    )
    .await
    .1["token"]
      .as_str()
      .unwrap()
      .to_string()
  }

  fn fake_mastodon() -> Router {
    Router::new()
      .route(
        "/api/v1/apps",
        post(|| async { Json(json!({ "client_id": "cid", "client_secret": "csec" })) }),
      )
      .route(
        "/oauth/token",
        post(|| async { Json(json!({ "access_token": "tok" })) }),
      )
      .route(
        "/api/v1/accounts/verify_credentials",
        get(|| async { Json(json!({ "acct": "mara" })) }),
      )
  }

  async fn opened_url(opened: &Arc<Mutex<Vec<String>>>) -> String {
    loop {
      if let Some(u) = opened.lock().unwrap().first().cloned() {
        return u;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
      if b[i] == b'%' && i + 2 < b.len() {
        out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
        i += 3;
      } else {
        out.push(b[i]);
        i += 1;
      }
    }
    String::from_utf8(out).unwrap()
  }

  #[tokio::test]
  async fn connect_wordpress_needs_only_the_site_and_the_approve_click() {
    let dir = tempfile::tempdir().unwrap();
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = opened.clone();
    let mut st = test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(move |u: &str| o2.lock().unwrap().push(u.into())),
    );
    let store = st.connections.clone();
    let wp = Router::new()
      .route(
        "/wp-json/",
        get(|| async { Json(json!({ "name": "Mara's Blog" })) }),
      )
      .route(
        "/wp-json/wp/v2/users/me",
        get(|h: axum::http::HeaderMap| async move {
          assert!(h["authorization"].to_str().unwrap().starts_with("Basic "));
          Json(json!({ "id": 1, "capabilities": { "publish_posts": true } }))
        }),
      )
      // WordPress.com doesn't host this site
      .route(
        "/rest/v1.1/sites/{host}",
        get(|| async {
          (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown_blog" })),
          )
        }),
      );
    let base = serve(wp).await;
    st.endpoints.wpcom_api = base.clone();
    let app = router(st);
    let t = paired(&app).await;
    let (a2, t2, b2) = (app.clone(), t.clone(), base.clone());
    let pending = tokio::spawn(async move {
      send(
        &a2,
        req(
          "POST",
          "/v1/connections/wordpress",
          Some(&t2),
          Some(json!({ "fields": { "site": b2 } })),
        ),
      )
      .await
    });
    // the Helper opens BunnieHop's start page, never WordPress itself: the start page goes on to
    // WordPress only once the browser answers /connect/return locally (D-120)
    let url = opened_url(&opened).await;
    assert!(!url.contains("authorize-application.php"));
    let start = format!(
      "https://bunniehop.party/connect/wp-start#site={}&state=",
      crate::uploaders::ghost::urlencode(&base)
    );
    assert!(url.starts_with(&start), "{url}");
    assert!(url.ends_with("&port=17333"));
    let state = url
      .split("state=")
      .nth(1)
      .unwrap()
      .split('&')
      .next()
      .unwrap()
      .to_string();
    let ret = |state: &str| {
      req(
        "POST",
        RETURN_PATH,
        None,
        Some(
          json!({ "provider": "wordpress", "state": state, "site_url": base, "user_login": "mara", "password": "abcd efgh ijkl" }),
        ),
      )
    };
    assert_eq!(send(&app, ret("forged")).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send(&app, ret(&state)).await.0, StatusCode::NO_CONTENT);
    let (s, c) = pending.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["label"], "Mara's Blog");
    let secret = store.secret(c["id"].as_str().unwrap()).unwrap();
    assert!(secret.to_string().contains("abcd efgh ijkl"));
    assert!(!c.to_string().contains("abcd"));
  }

  #[tokio::test]
  async fn connect_wordpress_com_site_signs_in_on_wordpress_com() {
    let dir = tempfile::tempdir().unwrap();
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = opened.clone();
    let mut st = test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(move |u: &str| o2.lock().unwrap().push(u.into())),
    );
    let store = st.connections.clone();
    let bearer = |h: &axum::http::HeaderMap| {
      h.get("authorization")
        .is_some_and(|v| v == "Bearer wpcom-tok")
    };
    let fake = Router::new()
      .route(
        "/v1/oauth/wpcom/token",
        post(|Json(b): Json<Value>| async move {
          assert_eq!(b["code"], "c0de");
          Json(json!({ "access_token": "wpcom-tok", "token_type": "bearer", "blog_id": "4242", "blog_url": "https://mara.blog" }))
        }),
      )
      .route(
        "/rest/v1.1/sites/{host}",
        get(
          move |Path(host): Path<String>, h: axum::http::HeaderMap| async move {
            match host.as_str() {
              // the creator typed their custom domain: hosted on WordPress.com, not Jetpack
              "mara.blog" => Json(json!({ "ID": 4242, "jetpack": false })),
              "4242" => {
                assert!(bearer(&h));
                Json(json!({ "name": "Mara's Notes", "URL": "https://mara.blog" }))
              }
              _ => panic!("unexpected site {host}"),
            }
          },
        ),
      )
      .route(
        "/wp/v2/sites/4242/users/me",
        get(move |h: axum::http::HeaderMap| async move {
          assert!(bearer(&h));
          Json(json!({ "id": 1, "capabilities": { "publish_posts": true } }))
        }),
      );
    let base = serve(fake).await;
    st.endpoints.worker = base.clone();
    st.endpoints.wpcom_api = base.clone();
    let app = router(st);
    let t = paired(&app).await;
    let (a2, t2) = (app.clone(), t.clone());
    let pending = tokio::spawn(async move {
      send(
        &a2,
        req(
          "POST",
          "/v1/connections/wordpress",
          Some(&t2),
          Some(json!({ "fields": { "site": "https://Mara.blog/" } })),
        ),
      )
      .await
    });
    let url = opened_url(&opened).await;
    assert!(
      url.starts_with(&format!("{base}/oauth/wpcom/start?")),
      "{url}"
    );
    assert!(url.ends_with("&blog=mara.blog"), "{url}");
    let state = url
      .split(['?', '&'])
      .find_map(|p| p.strip_prefix("state="))
      .unwrap()
      .to_string();
    let cb = Request::builder()
      .uri(format!(
        "{RELAY_CALLBACK_PATH}?provider=wpcom&state={state}&code=c0de"
      ))
      .header("host", "127.0.0.1:17333")
      .body(Body::empty())
      .unwrap();
    assert_eq!(
      app.clone().oneshot(cb).await.unwrap().status(),
      StatusCode::OK
    );
    let (s, c) = pending.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["label"], "Mara's Notes");
    let secret = store.secret(c["id"].as_str().unwrap()).unwrap();
    assert_eq!(secret["wpcom"], true);
    assert_eq!(secret["blogId"], "4242");
    assert!(!c.to_string().contains("wpcom-tok"));
  }

  #[tokio::test]
  async fn connect_ghost_with_email_password_and_the_emailed_code() {
    let dir = tempfile::tempdir().unwrap();
    let st = test_state(dir.path(), Arc::new(|_: &str| {}), Arc::new(|_: &str| {}));
    let store = st.connections.clone();
    let app = router(st);
    let t = paired(&app).await;
    const COOKIE: &str = "ghost-admin-api-session=s%3Aabc";
    let ok = |h: &axum::http::HeaderMap| h.get("cookie").is_some_and(|c| c == COOKIE);
    let ghost = Router::new()
      .route("/ghost/", get(|| async { "admin" }))
      .route(
        "/ghost/api/admin/session/",
        post(|h: axum::http::HeaderMap, Json(b): Json<Value>| async move {
          assert!(h.contains_key("origin"));
          if b["password"] != "pw" {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "errors": [{ "type": "UnauthorizedError" }] }))).into_response();
          }
          (
            StatusCode::FORBIDDEN,
            [("set-cookie", format!("{COOKIE}; Path=/ghost; HttpOnly"))],
            Json(json!({ "errors": [{ "type": "Needs2FAError", "code": "2FA_NEW_DEVICE_DETECTED" }] })),
          )
            .into_response()
        })
        .delete(|| async { StatusCode::NO_CONTENT }),
      )
      .route(
        "/ghost/api/admin/session/verify/",
        axum::routing::put(move |h: axum::http::HeaderMap, Json(b): Json<Value>| async move {
          if ok(&h) && b["token"] == "123456" {
            StatusCode::OK
          } else {
            StatusCode::BAD_REQUEST
          }
        }),
      )
      .route(
        "/ghost/api/admin/integrations/",
        post(move |h: axum::http::HeaderMap, Json(b): Json<Value>| async move {
          assert!(ok(&h));
          assert_eq!(b["integrations"][0]["name"], "BunnieHop");
          Json(json!({ "integrations": [{ "api_keys": [
            { "type": "content", "id": "c1", "secret": "x" },
            { "type": "admin", "id": "abc123", "secret": "00112233445566778899aabbccddeeff" },
          ] }] }))
        }),
      )
      .route(
        "/ghost/api/admin/posts/",
        get(|h: axum::http::HeaderMap| async move {
          assert!(h["authorization"].to_str().unwrap().starts_with("Ghost "));
          Json(json!({ "posts": [] }))
        }),
      )
      .route(
        "/ghost/api/admin/site/",
        get(|| async { Json(json!({ "site": { "title": "Mara Writes" } })) }),
      );
    let base = serve(ghost).await;
    let body = |code: Option<&str>| {
      let mut f = json!({ "site": base, "email": "mara@example.com", "password": "pw" });
      if let Some(c) = code {
        f["code"] = json!(c);
      }
      Some(json!({ "fields": f }))
    };
    let (s, e) = send(
      &app,
      req("POST", "/v1/connections/ghost", Some(&t), body(None)),
    )
    .await;
    assert_eq!(
      (s, e["code"].as_str()),
      (StatusCode::UNAUTHORIZED, Some("verificationCode"))
    );
    let (s, e) = send(
      &app,
      req(
        "POST",
        "/v1/connections/ghost",
        Some(&t),
        body(Some("999999")),
      ),
    )
    .await;
    assert_eq!(e["code"], "verificationCode", "{s}");
    // a wrong code used up the waiting session; signing in again sends a new code
    send(
      &app,
      req("POST", "/v1/connections/ghost", Some(&t), body(None)),
    )
    .await;
    let (s, c) = send(
      &app,
      req(
        "POST",
        "/v1/connections/ghost",
        Some(&t),
        body(Some("123456")),
      ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["label"], "Mara Writes");
    let secret = store.secret(c["id"].as_str().unwrap()).unwrap();
    assert_eq!(
      secret["adminKey"],
      "abc123:00112233445566778899aabbccddeeff"
    );
    assert!(
      !secret.to_string().contains("\"pw\""),
      "the password is never kept"
    );
  }

  #[tokio::test]
  async fn connect_linkedin_goes_through_the_worker_relay_with_pkce() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = opened.clone();
    let mut st = test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(move |u: &str| o2.lock().unwrap().push(u.into())),
    );
    let seen = Arc::new(Mutex::new(Value::Null));
    let s2 = seen.clone();
    let fake = Router::new()
      .route(
        "/v1/oauth/linkedin/token",
        post(move |Json(b): Json<Value>| async move {
          *s2.lock().unwrap() = b;
          Json(json!({ "access_token": "li-tok", "expires_in": 5_184_000 }))
        }),
      )
      .route(
        "/v2/userinfo",
        get(|| async { Json(json!({ "sub": "m1", "name": "Mara Lin" })) }),
      );
    let base = serve(fake).await;
    st.endpoints.worker = base.clone();
    st.endpoints.linkedin = base.clone();
    let store = st.connections.clone();
    let app = router(st);
    let t = paired(&app).await;
    let (a2, t2) = (app.clone(), t.clone());
    let pending = tokio::spawn(async move {
      send(
        &a2,
        req("POST", "/v1/connections/linkedin", Some(&t2), None),
      )
      .await
    });
    let url = loop {
      if let Some(u) = opened.lock().unwrap().first().cloned() {
        break u;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(url.starts_with(&format!(
      "{base}/oauth/linkedin/start?return=http%3A%2F%2F127.0.0.1%3A17333&state="
    )));
    let param = |k: &str| {
      url
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix(&format!("{k}=")))
        .unwrap()
        .to_string()
    };
    let (state, challenge) = (param("state"), param("code_challenge"));
    assert!(state.len() >= 32);
    // the Worker sends the browser to /oauth/callback (no Origin header)
    let cb = Request::builder()
      .uri(format!(
        "{RELAY_CALLBACK_PATH}?provider=linkedin&state={state}&code=c0de"
      ))
      .header("host", "127.0.0.1:17333")
      .body(Body::empty())
      .unwrap();
    assert_eq!(
      app.clone().oneshot(cb).await.unwrap().status(),
      StatusCode::OK
    );
    let (s, c) = pending.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["label"], "Mara Lin (LinkedIn)");
    let b = seen.lock().unwrap().clone();
    assert_eq!(b["state"], state.as_str());
    assert_eq!(b["code"], "c0de");
    let v = b["code_verifier"].as_str().unwrap();
    assert_eq!(
      URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())),
      challenge
    );
    let id = c["id"].as_str().unwrap();
    let secret = store.secret(id).unwrap();
    assert_eq!(secret["accessToken"], "li-tok");
    assert_eq!(secret["author"], "urn:li:person:m1");
    // the token never shows up in what the web sees
    assert!(!c.to_string().contains("li-tok"));
  }

  #[tokio::test]
  async fn connect_bluesky_needs_only_the_handle_and_the_servers_sign_in_page() {
    use crate::uploaders::atproto_oauth::tests::check_proof;
    use axum::extract::Form;
    use axum::http::HeaderMap;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = opened.clone();
    let mut st = test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(move |u: &str| o2.lock().unwrap().push(u.into())),
    );
    let base = Arc::new(Mutex::new(String::new()));
    let seen = Arc::new(Mutex::new(
      Vec::<(String, Value, HashMap<String, String>)>::new(),
    ));
    let (b1, b2, b3, s1, s2) = (
      base.clone(),
      base.clone(),
      base.clone(),
      seen.clone(),
      seen.clone(),
    );
    let fake = Router::new()
      .route(
        "/xrpc/com.atproto.identity.resolveHandle",
        get(|Query(q): Query<HashMap<String, String>>| async move {
          assert_eq!(q["handle"], "mara.bsky.social");
          Json(json!({ "did": "did:plc:mara" }))
        }),
      )
      .route(
        "/did:plc:mara",
        get(move || async move {
          let b = b1.lock().unwrap().clone();
          Json(json!({ "service": [{ "id": "#atproto_pds", "serviceEndpoint": b }] }))
        }),
      )
      .route(
        "/.well-known/oauth-protected-resource",
        get(move || async move {
          Json(json!({ "authorization_servers": [b2.lock().unwrap().clone()] }))
        }),
      )
      .route(
        "/.well-known/oauth-authorization-server",
        get(move || async move {
          let b = b3.lock().unwrap().clone();
          Json(json!({
            "issuer": b,
            "pushed_authorization_request_endpoint": format!("{b}/par"),
            "authorization_endpoint": format!("{b}/authorize"),
            "token_endpoint": format!("{b}/token"),
          }))
        }),
      )
      .route(
        "/v1/oauth/bluesky/assertion",
        post(|| async { Json(json!({ "assertion": "signed-by-worker" })) }),
      )
      .route(
        "/par",
        post(
          move |h: HeaderMap, Form(f): Form<HashMap<String, String>>| async move {
            let claims = check_proof(h["dpop"].to_str().unwrap());
            let first = claims.get("nonce").is_none();
            s1.lock().unwrap().push(("par".into(), claims, f));
            if first {
              // a real server asks for its nonce first
              return (
                StatusCode::BAD_REQUEST,
                [("dpop-nonce", "n1")],
                Json(json!({ "error": "use_dpop_nonce" })),
              );
            }
            (
              StatusCode::CREATED,
              [("dpop-nonce", "n2")],
              Json(json!({ "request_uri": "urn:ietf:params:oauth:request_uri:req-1" })),
            )
          },
        ),
      )
      .route(
        "/token",
        post(
          move |h: HeaderMap, Form(f): Form<HashMap<String, String>>| async move {
            let claims = check_proof(h["dpop"].to_str().unwrap());
            s2.lock().unwrap().push(("token".into(), claims, f));
            Json(json!({
              "access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600,
              "sub": "did:plc:mara", "scope": "atproto transition:generic",
            }))
          },
        ),
      );
    let url = serve(fake).await;
    *base.lock().unwrap() = url.clone();
    st.endpoints.worker = url.clone();
    st.endpoints.bsky_public = url.clone();
    st.endpoints.plc = url.clone();
    let store = st.connections.clone();
    let app = router(st);
    let t = paired(&app).await;
    let (a2, t2) = (app.clone(), t.clone());
    let pending = tokio::spawn(async move {
      send(
        &a2,
        req(
          "POST",
          "/v1/connections/bluesky",
          Some(&t2),
          Some(json!({ "fields": { "handle": "@Mara.bsky.social" } })),
        ),
      )
      .await
    });
    let opened = opened_url(&opened).await;
    assert!(opened.starts_with(&format!(
      "{url}/oauth/bluesky/start?return=http%3A%2F%2F127.0.0.1%3A17333&state="
    )));
    let param = |k: &str| {
      decode(
        opened
          .split(['?', '&'])
          .find_map(|p| p.strip_prefix(&format!("{k}=")))
          .unwrap(),
      )
    };
    let (state, authorize) = (param("state"), param("authorize"));
    assert_eq!(
      authorize,
      format!(
        "{url}/authorize?client_id={}&request_uri={}",
        crate::uploaders::ghost::urlencode(&format!("{url}/oauth/bluesky/client-metadata.json")),
        crate::uploaders::ghost::urlencode("urn:ietf:params:oauth:request_uri:req-1")
      )
    );
    // the Worker's callback sends the browser back with the code and the issuer
    let cb = Request::builder()
      .uri(format!(
        "{RELAY_CALLBACK_PATH}?provider=bluesky&state={state}&code=c0de&iss={}",
        crate::uploaders::ghost::urlencode(&url)
      ))
      .header("host", "127.0.0.1:17333")
      .body(Body::empty())
      .unwrap();
    assert_eq!(
      app.clone().oneshot(cb).await.unwrap().status(),
      StatusCode::OK
    );
    let (s, c) = pending.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["label"], "@mara.bsky.social");
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 3, "PAR, PAR with nonce, token");
    let (_, par, pf) = &calls[1];
    assert_eq!(par["nonce"], "n1");
    assert_eq!(par["htu"], format!("{url}/par"));
    assert_eq!(pf["state"], state);
    assert_eq!(pf["login_hint"], "mara.bsky.social");
    assert_eq!(pf["client_assertion"], "signed-by-worker");
    assert_eq!(pf["redirect_uri"], format!("{url}/oauth/bluesky/callback"));
    let (_, tok, tf) = &calls[2];
    assert_eq!(tok["nonce"], "n2");
    assert_eq!(tf["code"], "c0de");
    assert_eq!(
      URL_SAFE_NO_PAD.encode(Sha256::digest(tf["code_verifier"].as_bytes())),
      pf["code_challenge"]
    );
    let secret = store.secret(c["id"].as_str().unwrap()).unwrap();
    assert_eq!(secret["oauth"], true);
    assert_eq!(secret["did"], "did:plc:mara");
    assert_eq!(secret["refreshToken"], "rt-1");
    assert!(secret.get("appPassword").is_none());
    assert!(!c.to_string().contains("at-1"));
  }

  #[tokio::test]
  async fn connect_mastodon_signs_in_through_the_creators_browser() {
    let dir = tempfile::tempdir().unwrap();
    let opened = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = opened.clone();
    let st = test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(move |u: &str| o2.lock().unwrap().push(u.into())),
    );
    let store = st.connections.clone();
    let app = router(st);
    let t = paired(&app).await;
    let base = serve(fake_mastodon()).await;
    let a2 = app.clone();
    let t2 = t.clone();
    let pending = tokio::spawn(async move {
      send(
        &a2,
        req(
          "POST",
          "/v1/connections/mastodon",
          Some(&t2),
          Some(json!({ "fields": { "instance": base } })),
        ),
      )
      .await
    });
    let url = loop {
      if let Some(u) = opened.lock().unwrap().first().cloned() {
        break u;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let state = url.split("state=").nth(1).unwrap().to_string();
    // the browser comes back with no Origin header; a wrong state is refused
    let cb = |s: &str| {
      Request::builder()
        .uri(format!("{CALLBACK_PATH}?code=abc&state={s}"))
        .header("host", "127.0.0.1:17333")
        .body(Body::empty())
        .unwrap()
    };
    assert_eq!(
      app.clone().oneshot(cb("wrong")).await.unwrap().status(),
      StatusCode::BAD_REQUEST
    );
    assert_eq!(
      app.clone().oneshot(cb(&state)).await.unwrap().status(),
      StatusCode::OK
    );
    let (s, c) = pending.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["platform"], "mastodon");
    assert!(c["label"].as_str().unwrap().starts_with("@mara@"));
    assert!(
      c.get("token").is_none() && !c.to_string().contains("tok\""),
      "no credential in the answer"
    );
    assert_eq!(
      store.secret(c["id"].as_str().unwrap()).unwrap()["token"],
      "tok"
    );
    let (_, l) = send(&app, req("GET", "/v1/connections", Some(&t), None)).await;
    assert_eq!(l.as_array().unwrap().len(), 1);
    let (s, _) = send(
      &app,
      req(
        "DELETE",
        &format!("/v1/connections/{}", c["id"].as_str().unwrap()),
        Some(&t),
        None,
      ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
  }

  #[tokio::test]
  async fn connect_asks_for_missing_fields_and_unknown_platforms_honestly() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(test_state(
      dir.path(),
      Arc::new(|_: &str| {}),
      Arc::new(|_: &str| {}),
    ));
    let t = paired(&app).await;
    let (s, b) = send(
      &app,
      req(
        "POST",
        "/v1/connections/bluesky",
        Some(&t),
        Some(json!({ "fields": {} })),
      ),
    )
    .await;
    assert_eq!(
      (s, b["code"].as_str()),
      (StatusCode::BAD_REQUEST, Some("requiredChoiceMissing"))
    );
    assert!(b["message"].as_str().unwrap().contains("Bluesky handle"));
    let (s, b) = send(
      &app,
      req(
        "POST",
        "/v1/connections/snapchat",
        Some(&t),
        Some(json!({})),
      ),
    )
    .await;
    assert_eq!(
      (s, b["code"].as_str()),
      (StatusCode::BAD_REQUEST, Some("notSupported"))
    );
    let (s, _) = send(&app, req("GET", "/v1/connections", None, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
  }
}

#[cfg(test)]
mod telegram_http_tests {
  use super::*;
  use axum::{body::Body, http::Request};
  use http_body_util::BodyExt;
  use std::{
    io::Write,
    sync::{Arc, Mutex},
  };
  use tower::ServiceExt;

  #[derive(Clone, Default)]
  struct Capture(Arc<Mutex<Vec<u8>>>);
  impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
      self.0.lock().unwrap().extend_from_slice(b);
      Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
      Ok(())
    }
  }
  impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
      self.clone()
    }
  }
  async fn seed(
    st: &AppState,
    two_factor: bool,
  ) -> (String, tokio::sync::oneshot::Receiver<Connection>) {
    let state = new_state();
    let (tx, rx) = tokio::sync::oneshot::channel();
    st.connections.telegram.jobs.lock().await.insert(
      state.clone(),
      TelegramJob {
        flow: crate::uploaders::telegram_user::SignIn::new(
          crate::uploaders::telegram_user::flow_tests::local_test_api(two_factor),
        ),
        done: tx,
        created: std::time::Instant::now(),
      },
    );
    (state, rx)
  }
  async fn step(app: &Router, state: &str, stage: &str, value: &str) -> (StatusCode, Value) {
    let response = app
      .clone()
      .oneshot(
        Request::builder()
          .method("POST")
          .uri(TELEGRAM_STEP)
          .header("host", "127.0.0.1:17333")
          .header("origin", "http://127.0.0.1:17333")
          .header("authorization", format!("Bearer {state}"))
          .header("content-type", "application/json")
          .body(Body::from(json!({"stage":stage,"value":value}).to_string()))
          .unwrap(),
      )
      .await
      .unwrap();
    let status = response.status();
    assert!(response
      .headers()
      .get("access-control-allow-origin")
      .is_none());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
  }

  #[tokio::test]
  async fn telegram_local_http_sign_in_never_leaks_credentials_to_logs_errors_or_files() {
    for two_factor in [false, true] {
      let dir = tempfile::tempdir().unwrap();
      let st = crate::server::test_state(dir.path(), Arc::new(|_| {}), Arc::new(|_| {}));
      let (state, done) = seed(&st, two_factor).await;
      let app = crate::server::router(st.clone());
      let logs = Capture::default();
      let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_writer(logs.clone())
        .finish();
      let _capture = tracing::subscriber::set_default(subscriber);
      assert_eq!(
        step(&app, &state, "phone", "+15551234567").await,
        (StatusCode::OK, json!({"stage":"code","channels":[]}))
      );
      let (status, next) = step(&app, &state, "code", "123456").await;
      assert_eq!(status, StatusCode::OK);
      if two_factor {
        assert_eq!(next["stage"], "password");
        assert_eq!(
          step(&app, &state, "password", "two-factor-secret").await.1["stage"],
          "channel"
        );
      } else {
        assert_eq!(next["stage"], "channel");
      }
      assert_eq!(step(&app, &state, "channel", "7").await.1["stage"], "done");
      let connection = done.await.unwrap();
      let ledger = crate::posted::Posted::open(dir.path().join("posted.json"));
      let key = format!("telegram|{}|source|item-1", connection.account);
      assert!(matches!(
        ledger.reserve(&key, "t"),
        crate::posted::Seen::Clear
      ));
      ledger.finish(
        &key,
        Some(json!({"state":"publishedUnverified","destItemId":"42"})),
      );
      let replay = step(&app, &state, "password", "two-factor-secret").await;
      assert_eq!(replay.0, StatusCode::UNAUTHORIZED);
      let mut observable = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
      observable.push_str(&serde_json::to_string(&connection).unwrap());
      observable.push_str(&st.connections.secret(&connection.id).unwrap().to_string());
      observable.push_str(&replay.1.to_string());
      for file in std::fs::read_dir(dir.path()).unwrap().flatten() {
        if file.file_type().unwrap().is_file() {
          observable.push_str(&std::fs::read_to_string(file.path()).unwrap());
        }
      }
      for secret in ["+15551234567", "123456", "two-factor-secret"] {
        assert!(!observable.contains(secret), "sign-in credential leaked");
      }
      assert!(st.connections.telegram.jobs.lock().await.is_empty());
    }
  }

  #[tokio::test]
  async fn telegram_bootstrap_requires_capability_and_direct_browser_navigation() {
    let dir = tempfile::tempdir().unwrap();
    let st = crate::server::test_state(dir.path(), Arc::new(|_| {}), Arc::new(|_| {}));
    let (state, _done) = seed(&st, false).await;
    let app = crate::server::router(st);
    for (origin, site, mode, dest, cap, status) in [
      (None, "none", "navigate", "document", true, 200),
      (None, "cross-site", "navigate", "document", true, 403),
      (
        Some(crate::server::PROD_ORIGIN),
        "cross-site",
        "navigate",
        "document",
        true,
        403,
      ),
      (
        Some("https://elsewhere.example"),
        "cross-site",
        "navigate",
        "document",
        true,
        403,
      ),
      (None, "none", "cors", "empty", true, 403),
      (None, "", "", "", true, 403),
      (None, "none", "navigate", "document", false, 401),
    ] {
      let mut request = Request::builder()
        .uri(format!(
          "{TELEGRAM_PAGE}?state={}",
          if cap { &state } else { "invalid" }
        ))
        .header("host", "127.0.0.1:17333")
        .header("sec-fetch-site", site)
        .header("sec-fetch-mode", mode)
        .header("sec-fetch-dest", dest);
      if let Some(o) = origin {
        request = request.header("origin", o);
      }
      let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
      assert_eq!(
        response.status().as_u16(),
        status,
        "{origin:?} {site} {cap}"
      );
      if status == 200 {
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert!(response.headers()["content-security-policy"]
          .to_str()
          .unwrap()
          .contains("frame-ancestors 'none'"));
        let html = String::from_utf8(
          response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
        )
        .unwrap();
        assert!(html.contains("type=\"tel\""));
        assert!(!html.contains("api_hash") && !html.contains("api_id"));
      }
    }
  }

  #[tokio::test]
  async fn telegram_local_sign_in_rejects_wrong_host_expired_capability_and_website_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let st = crate::server::test_state(dir.path(), Arc::new(|_| {}), Arc::new(|_| {}));
    let (state, _done) = seed(&st, false).await;
    let app = crate::server::router(st.clone());
    for host in [
      "localhost:17333",
      "127.0.0.1:17334",
      "elsewhere.example:17333",
    ] {
      let response = app
        .clone()
        .oneshot(
          Request::builder()
            .method("POST")
            .uri(TELEGRAM_STEP)
            .header("host", host)
            .header("origin", "http://127.0.0.1:17333")
            .header("authorization", format!("Bearer {state}"))
            .header("content-type", "application/json")
            .body(Body::from("{} "))
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    st.connections
      .telegram
      .jobs
      .lock()
      .await
      .get_mut(&state)
      .unwrap()
      .created = std::time::Instant::now() - crate::uploaders::telegram_user::SIGN_IN_TTL;
    assert_eq!(
      step(&app, &state, "phone", "+15551234567").await.0,
      StatusCode::UNAUTHORIZED
    );
    let result = telegram_connect(
      &st,
      &HashMap::from([("phone".into(), "+15551234567".into())]),
    )
    .await
    .unwrap_err();
    assert!(!format!("{result:?}").contains("+15551234567"));
    assert_eq!(result.code, "notSupported");
  }
}

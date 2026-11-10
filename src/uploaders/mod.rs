//! Destination uploaders (PLAN §7.5, API path). Each one posts as the creator with the
//! creator's own credentials, through the platform's public API, at a human pace. None of them
//! spoof a browser, rotate identities or work around a platform's checks.

pub mod atproto_oauth;
pub mod bluesky;
pub mod discord;
pub mod facebook;
pub mod ghost;
pub mod instagram;
pub mod linkedin;
pub mod mastodon;
pub mod peertube;
pub mod pinterest;
pub mod telegram;
pub mod telegram_user;
pub mod threads;
pub mod tiktok;
pub mod tumblr;
pub mod wordpress;
pub mod youtube;

use crate::connections::Store;
use crate::hops::{Failure, Uploader, Uploaders};
use reqwest::{Body, StatusCode};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

pub const USER_AGENT: &str = concat!(
  "BunnieHop-Helper/",
  env!("CARGO_PKG_VERSION"),
  " (+https://bunniehop.party)"
);

pub fn client() -> reqwest::Client {
  reqwest::Client::builder()
    .user_agent(USER_AGENT)
    .connect_timeout(std::time::Duration::from_secs(20))
    .build()
    .unwrap_or_default()
}

/// Endpoints that tests point at a fake server.
#[derive(Clone, Debug)]
pub struct Endpoints {
  pub bsky_video: String,
  pub telegram: String,
  /// api.bunniehop.party: OAuth relay for LinkedIn, Dropbox and Vimeo (token exchange only).
  pub worker: String,
  pub linkedin: String,
  pub facebook: String,
  pub facebook_video: String,
  pub threads: String,
  /// Instagram's resumable upload host; the uploader sends the token only here.
  pub instagram_upload: String,
  pub pinterest: String,
  pub tiktok: String,
  pub tumblr: String,
  /// TikTok's upload host; chunks go only to addresses under it, with no token.
  pub tiktok_upload: String,
  /// Local provider upload handles; tests supply an isolated directory.
  pub upload_handles: std::path::PathBuf,
  pub dropbox_api: String,
  /// Bluesky's public AppView (handle → DID) and the PLC directory (DID → server).
  pub bsky_public: String,
  pub plc: String,
  pub wpcom_api: String,
  pub google_api: String,
  pub dropbox_content: String,
  /// Where an AWS bucket's region is asked for (the advanced S3 vault, O-004).
  pub aws_s3: String,
}

impl Default for Endpoints {
  fn default() -> Self {
    Self {
      bsky_video: "https://video.bsky.app".into(),
      telegram: "https://api.telegram.org".into(),
      worker: "https://api.bunniehop.party".into(),
      linkedin: "https://api.linkedin.com".into(),
      facebook: "https://graph.facebook.com/v24.0".into(),
      facebook_video: "https://graph-video.facebook.com/v24.0".into(),
      threads: "https://graph.threads.com/v1.0".into(),
      instagram_upload: "https://rupload.facebook.com".into(),
      pinterest: "https://api.pinterest.com/v5".into(),
      tiktok: "https://open.tiktokapis.com".into(),
      tumblr: "https://api.tumblr.com/v2".into(),
      tiktok_upload: "https://open-upload.tiktokapis.com".into(),
      upload_handles: crate::config::Paths::system()
        .data_dir
        .join("hops/upload-handles"),
      dropbox_api: "https://api.dropboxapi.com".into(),
      bsky_public: "https://public.api.bsky.app".into(),
      plc: "https://plc.directory".into(),
      wpcom_api: "https://public-api.wordpress.com".into(),
      google_api: "https://www.googleapis.com".into(),
      dropbox_content: "https://content.dropboxapi.com".into(),
      aws_s3: "https://s3.amazonaws.com".into(),
    }
  }
}

/// Builds the uploader for a hop destination from the stored connection.
pub fn registry(store: Arc<Store>, http: reqwest::Client, ep: Endpoints) -> Uploaders {
  Arc::new(move |platform: &str, conn_id: &str| {
    let c = store.find(platform, conn_id)?;
    let secret = store.secret(&c.id)?;
    let up: Arc<dyn Uploader> = match platform {
      "bluesky" => Arc::new(bluesky::Bluesky::new(
        http.clone(),
        &secret,
        &ep,
        store.clone(),
        &c.id,
      )?),
      "mastodon" | "pixelfed" => {
        Arc::new(mastodon::Mastodon::new(http.clone(), &secret, platform)?)
      }
      "peertube" => Arc::new(peertube::PeerTube::new(
        http.clone(),
        store.clone(),
        c.id.clone(),
        secret,
        c.choices.get("channel").cloned(),
      )?),
      "discord" => Arc::new(discord::Discord::new(http.clone(), &secret)?),
      "ghost" => Arc::new(ghost::Ghost::new(http.clone(), &secret)?),
      "wordpress" => Arc::new(wordpress::WordPress::new(http.clone(), &secret, &ep)?),
      "linkedin" => Arc::new(linkedin::LinkedIn::new(http.clone(), &secret, &ep)?),
      "facebook" => Arc::new(facebook::Facebook::new(
        http.clone(),
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "instagram" => Arc::new(instagram::Instagram::new(
        http.clone(),
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "pinterest" => Arc::new(pinterest::Pinterest::new(
        http.clone(),
        store.clone(),
        &c.id,
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "tumblr" => Arc::new(tumblr::Tumblr::new(
        http.clone(),
        store.clone(),
        &c.id,
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "tiktok" => Arc::new(tiktok::TikTok::new(
        http.clone(),
        store.clone(),
        &c.id,
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "threads" => Arc::new(threads::Threads::new(
        http.clone(),
        store.clone(),
        &c.id,
        &secret,
        &ep,
        ep.upload_handles.clone(),
      )?),
      "telegram" => Arc::new(telegram_user::Telegram::new(
        &secret,
        ep.upload_handles.clone(),
      )?),
      "youtube" => Arc::new(youtube::YouTube::new(http.clone(), &secret, &ep)?),
      _ => return None,
    };
    Some(up)
  })
}

/// An HTTP error answer, in the platform's own words (D12).
pub fn status_failure(platform: &str, status: StatusCode, body: &str) -> Failure {
  let (code, message) = match status.as_u16() {
    401 => (
      "tokenExpired",
      format!("{platform} signed BunnieHop out. Connect the account again."),
    ),
    403 => ("uploadRejected", format!("{platform} refused the post.")),
    404 => ("notFound404", format!("{platform} answered 404 Not Found.")),
    413 => (
      "itemTooLarge",
      format!("The file is larger than {platform} accepts."),
    ),
    429 => (
      "rateLimited429",
      format!("{platform} asked BunnieHop to slow down."),
    ),
    500..=599 => (
      "server5xx",
      format!("{platform} had a server error ({status})."),
    ),
    _ => (
      "uploadRejected",
      format!("{platform} refused the post ({status})."),
    ),
  };
  Failure {
    code,
    message,
    verbatim: Some(crate::ytdlp::tail_chars(body.trim(), 600)),
  }
}

pub fn net(platform: &str, e: reqwest::Error) -> Failure {
  Failure {
    code: "networkLost",
    message: format!("Couldn't reach {platform}."),
    verbatim: Some(e.without_url().to_string()),
  }
}

/// Reads a JSON answer, or turns an error status into a `Failure`.
pub async fn json_or_fail(
  platform: &str,
  r: Result<reqwest::Response, reqwest::Error>,
) -> Result<Value, Failure> {
  let r = r.map_err(|e| net(platform, e))?;
  let status = r.status();
  let text = r.text().await.map_err(|e| net(platform, e))?;
  if !status.is_success() {
    return Err(status_failure(platform, status, &text));
  }
  serde_json::from_str(&text).or_else(|_| {
    if text.trim().is_empty() {
      Ok(Value::Null)
    } else {
      Err(status_failure(platform, StatusCode::BAD_GATEWAY, &text))
    }
  })
}

/// D-069: the answers to a publishing request that prove nothing was posted. Every other
/// answer (408, 409, 429, any 5xx, an unreadable success, a timeout, a lost answer) may have
/// posted, so the item reads unverified and is never sent again (D11).
pub const NOTHING_POSTED: [u16; 7] = [400, 401, 403, 404, 413, 415, 422];

pub fn nothing_posted(status: Option<StatusCode>) -> bool {
  status.is_some_and(|s| NOTHING_POSTED.contains(&s.as_u16()))
}

/// The answer to the request that makes a post go live, sorted under D-069.
pub enum PublishAnswer {
  Posted(Value),
  /// Nothing was posted: the caller releases the item's handle and returns the failure.
  Refused(Failure),
  /// The post may exist: the caller keeps the handle and reports it unverified.
  Unknown(Failure),
}

pub async fn publish_answer(
  platform: &str,
  r: Result<reqwest::Response, reqwest::Error>,
) -> PublishAnswer {
  let status = r.as_ref().ok().map(|r| r.status());
  match json_or_fail(platform, r).await {
    Ok(v) => PublishAnswer::Posted(v),
    Err(e) if nothing_posted(status) => PublishAnswer::Refused(e),
    Err(e) => PublishAnswer::Unknown(e),
  }
}

/// The creator's note when a post may exist but was not confirmed.
pub fn unknown_note(platform: &str, e: &Failure, again: &str) -> String {
  let mut note = format!("{} Check {platform} before {again} again.", e.message);
  if let Some(v) = &e.verbatim {
    note.push('\n');
    note.push_str(v);
  }
  note
}

/// `instance` as typed by the creator ("mastodon.social", "https://video.example") → base URL.
/// Plain http is only accepted for loopback (tests and local instances).
pub fn base_url(instance: &str) -> Result<String, Failure> {
  let t = instance.trim().trim_end_matches('/');
  let bad = || {
    Failure::new(
      "unknown",
      "That doesn't look like a server address (for example mastodon.social).",
    )
  };
  let (scheme, rest) = match t.split_once("://") {
    Some((s, r)) => (s.to_ascii_lowercase(), r),
    None => ("https".to_string(), t),
  };
  let host = rest.split('/').next().unwrap_or("");
  let host_only = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
  let ok_chars = !host.is_empty()
    && host
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
  let loopback = host_only == "127.0.0.1" || host_only == "localhost";
  match (scheme.as_str(), ok_chars) {
    ("https", true) => Ok(format!("https://{}", host.to_ascii_lowercase())),
    ("http", true) if loopback => Ok(format!("http://{host}")),
    _ => Err(bad()),
  }
}

/// A site address that may live under a path ("example.com/blog" for WordPress or Ghost).
pub fn site_url(raw: &str) -> Result<String, Failure> {
  let t = raw.trim().trim_end_matches('/');
  let (head, path) = match t.split_once("://") {
    Some((sch, rest)) => match rest.split_once('/') {
      Some((h, p)) => (format!("{sch}://{h}"), p),
      None => (t.to_string(), ""),
    },
    None => match t.split_once('/') {
      Some((h, p)) => (h.to_string(), p),
      None => (t.to_string(), ""),
    },
  };
  let base = base_url(&head)?;
  let path_ok = path
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~'))
    && !path.split('/').any(|seg| seg == "..");
  if !path_ok {
    return Err(Failure::new(
      "unknown",
      "That doesn't look like a site address (for example example.com or example.com/blog).",
    ));
  }
  Ok(if path.is_empty() {
    base
  } else {
    format!("{base}/{path}")
  })
}

/// Streams a file as a request body (no whole-file buffering for big videos).
pub async fn file_body(path: &Path) -> std::io::Result<(Body, u64)> {
  let f = tokio::fs::File::open(path).await?;
  let len = f.metadata().await?.len();
  let stream = futures_util::stream::unfold(f, |mut f| async move {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 256 * 1024];
    match f.read(&mut buf).await {
      Ok(0) => None,
      Ok(n) => {
        buf.truncate(n);
        Some((Ok::<_, std::io::Error>(buf), f))
      }
      Err(e) => Some((Err(e), f)),
    }
  });
  Ok((Body::wrap_stream(stream), len))
}

pub fn mime_of(path: &Path) -> &'static str {
  match path
    .extension()
    .and_then(|e| e.to_str())
    .map(str::to_ascii_lowercase)
    .as_deref()
  {
    Some("mp4" | "m4v") => "video/mp4",
    Some("mov") => "video/quicktime",
    Some("webm") => "video/webm",
    Some("jpg" | "jpeg") => "image/jpeg",
    Some("png") => "image/png",
    Some("webp") => "image/webp",
    Some("gif") => "image/gif",
    Some("mp3") => "audio/mpeg",
    Some("m4a") => "audio/mp4",
    _ => "application/octet-stream",
  }
}

pub fn is_image(p: &Path) -> bool {
  mime_of(p).starts_with("image/")
}
pub fn is_video(p: &Path) -> bool {
  mime_of(p).starts_with("video/")
}

/// The post text the web app mapped (D-033), else the item's own title/description.
pub fn body_text(post: Option<&Value>, item: &Value) -> String {
  let f = |k: &str| {
    post
      .and_then(|p| p.pointer(&format!("/fields/{k}")))
      .and_then(Value::as_str)
  };
  if let Some(b) = f("body") {
    return b.to_string();
  }
  let title = item.get("title").and_then(Value::as_str).unwrap_or("");
  let desc = item
    .get("description")
    .and_then(Value::as_str)
    .unwrap_or("");
  match (title.is_empty(), desc.is_empty()) {
    (false, false) if !desc.starts_with(title) => format!("{title}\n\n{desc}"),
    (false, _) if desc.is_empty() => title.to_string(),
    _ => desc.to_string(),
  }
}

pub fn title_text(post: Option<&Value>, item: &Value) -> String {
  post
    .and_then(|p| p.pointer("/fields/title"))
    .and_then(Value::as_str)
    .or_else(|| item.get("title").and_then(Value::as_str))
    .unwrap_or("Untitled")
    .to_string()
}

pub fn thread(post: Option<&Value>) -> Vec<String> {
  post
    .and_then(|p| p.get("thread"))
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|t| t.as_str().map(String::from))
        .collect()
    })
    .unwrap_or_default()
}

pub fn tags(post: Option<&Value>, item: &Value) -> Vec<String> {
  post
    .and_then(|p| p.pointer("/fields/tags"))
    .or_else(|| item.get("tags"))
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|t| t.as_str().map(String::from))
        .collect()
    })
    .unwrap_or_default()
}

/// The original publish time, for destinations that can backdate.
pub fn created_at(post: Option<&Value>, item: &Value) -> Option<String> {
  post
    .and_then(|p| p.pointer("/fields/createdAt"))
    .or_else(|| item.get("publishedAt"))
    .and_then(Value::as_str)
    .map(String::from)
}

pub fn alt_texts(post: Option<&Value>) -> Vec<String> {
  post
    .and_then(|p| p.pointer("/fields/altText"))
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|t| t.as_str().map(String::from))
        .collect()
    })
    .unwrap_or_default()
}

/// Any ISO 8601 time ("2026-01-02T10:00:00-05:00") → UTC "2026-01-02T15:00:00Z".
pub fn utc_iso(s: &str) -> Option<String> {
  use time::format_description::well_known::Rfc3339;
  let t = time::OffsetDateTime::parse(s, &Rfc3339).ok()?;
  t.to_offset(time::UtcOffset::UTC)
    .replace_nanosecond(0)
    .ok()?
    .format(&Rfc3339)
    .ok()
}

pub fn escape_html(s: &str) -> String {
  let mut o = String::with_capacity(s.len());
  for c in s.chars() {
    match c {
      '&' => o.push_str("&amp;"),
      '<' => o.push_str("&lt;"),
      '>' => o.push_str("&gt;"),
      '"' => o.push_str("&quot;"),
      '\'' => o.push_str("&#39;"),
      _ => o.push(c),
    }
  }
  o
}

/// Plain post text → simple HTML: paragraphs on blank lines, `<br>` on single newlines, and
/// http(s) links made clickable. Everything else is escaped.
pub fn html_from_text(text: &str) -> String {
  let link = |w: &str| -> String {
    let trimmed = w.trim_end_matches(['.', ',', ')', '!', '?', ';', ':']);
    if (trimmed.starts_with("https://") || trimmed.starts_with("http://")) && trimmed.len() > 8 {
      let rest = &w[trimmed.len()..];
      let e = escape_html(trimmed);
      format!("<a href=\"{e}\">{e}</a>{}", escape_html(rest))
    } else {
      escape_html(w)
    }
  };
  text
    .replace("\r\n", "\n")
    .split("\n\n")
    .map(str::trim)
    .filter(|p| !p.is_empty())
    .map(|p| {
      let lines: Vec<String> = p
        .lines()
        .map(|l| l.split(' ').map(link).collect::<Vec<_>>().join(" "))
        .collect();
      format!("<p>{}</p>", lines.join("<br>"))
    })
    .collect::<Vec<_>>()
    .join("\n")
}

/// The article body: the source's own HTML for articles (Substack, Ghost, WordPress exports),
/// else the mapped text as HTML.
pub fn article_html(post: Option<&Value>, item: &Value) -> String {
  let as_article = post
    .and_then(|p| p.get("as"))
    .and_then(Value::as_str)
    .is_none_or(|k| k == "article");
  let mapped = post
    .and_then(|p| p.pointer("/fields/body"))
    .and_then(Value::as_str);
  match item.get("bodyHtml").and_then(Value::as_str) {
    Some(h) if as_article && !h.trim().is_empty() => h.to_string(),
    _ => html_from_text(
      &mapped
        .map(String::from)
        .unwrap_or_else(|| body_text(post, item)),
    ),
  }
}

/// `thumbnail.*` next to the media in the vault item folder.
pub fn thumbnail_of(media: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
  let dir = media.first()?.parent()?;
  std::fs::read_dir(dir)
    .ok()?
    .filter_map(|e| e.ok().map(|e| e.path()))
    .find(|p| {
      p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("thumbnail.") && is_image(p))
    })
}

#[cfg(test)]
pub mod testkit {
  use axum::Router;

  /// Serves `app` on an ephemeral loopback port; returns its base URL.
  pub async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
  }

  /// D-069's table: each answer to a publishing request, and whether it proves nothing was
  /// posted. `0` stands for a lost answer: a success status whose body never arrives.
  pub const REFUSAL_TABLE: [(u16, bool); 14] = [
    (400, true),
    (401, true),
    (403, true),
    (404, true),
    (413, true),
    (415, true),
    (422, true),
    (408, false),
    (409, false),
    (429, false),
    (500, false),
    (502, false),
    (503, false),
    (0, false),
  ];

  /// A fake platform's answer for one row of [`REFUSAL_TABLE`].
  pub fn table_answer(code: u16) -> axum::response::Response {
    use axum::{body::Body, http::StatusCode, response::IntoResponse};
    if code == 0 {
      let broken = futures_util::stream::once(async {
        Err::<axum::body::Bytes, std::io::Error>(std::io::Error::other("connection dropped"))
      });
      return (StatusCode::OK, Body::from_stream(broken)).into_response();
    }
    (
      StatusCode::from_u16(code).unwrap(),
      axum::Json(serde_json::json!({"error":{"message":format!("answer {code}")}})),
    )
      .into_response()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn d069_only_definite_refusals_prove_nothing_was_posted() {
    for (code, freed) in testkit::REFUSAL_TABLE.iter().filter(|(c, _)| *c != 0) {
      assert_eq!(
        nothing_posted(Some(StatusCode::from_u16(*code).unwrap())),
        *freed,
        "{code}"
      );
    }
    // A timeout or a dropped connection has no status: the post may exist.
    assert!(!nothing_posted(None));
    assert!(!nothing_posted(Some(StatusCode::OK)));
    assert!(
      !nothing_posted(Some(StatusCode::GONE)),
      "unlisted answers stay unverified"
    );
  }

  #[test]
  fn uploader_instance_addresses_are_https_except_loopback() {
    assert_eq!(
      base_url("mastodon.social").unwrap(),
      "https://mastodon.social"
    );
    assert_eq!(
      base_url("https://Video.Example/").unwrap(),
      "https://video.example"
    );
    assert_eq!(
      base_url("http://127.0.0.1:9000").unwrap(),
      "http://127.0.0.1:9000"
    );
    for bad in [
      "http://mastodon.social",
      "javascript:alert(1)",
      "",
      "a b",
      "ftp://x",
    ] {
      assert!(base_url(bad).is_err(), "{bad}");
    }
  }

  #[test]
  fn uploader_site_addresses_keep_a_subpath() {
    assert_eq!(
      site_url("Example.com/blog/").unwrap(),
      "https://example.com/blog"
    );
    assert_eq!(
      site_url("https://example.com").unwrap(),
      "https://example.com"
    );
    for bad in [
      "http://example.com",
      "example.com/../x",
      "example.com/a?b",
      "",
    ] {
      assert!(site_url(bad).is_err(), "{bad}");
    }
  }

  #[test]
  fn uploader_text_prefers_the_web_mapping() {
    let item = json!({ "title": "Hello", "description": "World", "tags": ["a"], "publishedAt": "2020-01-01T00:00:00Z" });
    assert_eq!(body_text(None, &item), "Hello\n\nWorld");
    let post = json!({ "fields": { "body": "Mapped", "tags": ["b"], "createdAt": "2019-01-01T00:00:00Z" }, "thread": ["2/2"] });
    assert_eq!(body_text(Some(&post), &item), "Mapped");
    assert_eq!(tags(Some(&post), &item), ["b"]);
    assert_eq!(
      created_at(Some(&post), &item).as_deref(),
      Some("2019-01-01T00:00:00Z")
    );
    assert_eq!(thread(Some(&post)), ["2/2"]);
  }

  #[test]
  fn uploader_dates_go_to_utc_and_text_becomes_safe_html() {
    assert_eq!(
      utc_iso("2026-01-02T10:00:00-05:00").as_deref(),
      Some("2026-01-02T15:00:00Z")
    );
    assert_eq!(utc_iso("nope"), None);
    assert_eq!(
      html_from_text("Hi <b>&\nsee https://x.example/a.\n\nBye"),
      "<p>Hi &lt;b&gt;&amp;<br>see <a href=\"https://x.example/a\">https://x.example/a</a>.</p>\n<p>Bye</p>"
    );
    assert_eq!(
      html_from_text("javascript:alert(1)"),
      "<p>javascript:alert(1)</p>"
    );
    let item = json!({ "title": "T", "description": "D", "bodyHtml": "<p>Real</p>" });
    assert_eq!(article_html(None, &item), "<p>Real</p>");
    let as_text = json!({ "as": "text", "fields": { "body": "Short" } });
    assert_eq!(article_html(Some(&as_text), &item), "<p>Short</p>");
  }

  #[test]
  fn uploader_errors_keep_the_platform_words() {
    let f = status_failure(
      "Bluesky",
      StatusCode::TOO_MANY_REQUESTS,
      "{\"error\":\"RateLimitExceeded\"}",
    );
    assert_eq!(f.code, "rateLimited429");
    assert!(f.verbatim.unwrap().contains("RateLimitExceeded"));
    assert_eq!(
      status_failure("X", StatusCode::UNAUTHORIZED, "").code,
      "tokenExpired"
    );
  }
}

/// An access token for a platform whose sign-in went through the Worker relay (D-040): only the
/// refresh token is kept; short-lived access tokens come from `/v1/oauth/<provider>/token`, where
/// the Worker adds the app secret and nothing else.
pub struct RelayToken {
  http: reqwest::Client,
  url: String,
  refresh: String,
  name: &'static str,
  access: std::sync::Mutex<Option<String>>,
}

impl RelayToken {
  pub fn new(
    http: reqwest::Client,
    ep: &Endpoints,
    provider: &str,
    refresh: &str,
    name: &'static str,
  ) -> Self {
    Self {
      http,
      url: format!("{}/v1/oauth/{provider}/token", ep.worker),
      refresh: refresh.to_string(),
      name,
      access: std::sync::Mutex::new(None),
    }
  }

  pub async fn get(&self, fresh: bool) -> Result<String, Failure> {
    if !fresh {
      if let Some(t) = self
        .access
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
      {
        return Ok(t);
      }
    }
    let r = self
      .http
      .post(&self.url)
      .json(&serde_json::json!({ "refresh_token": self.refresh }))
      .send()
      .await
      .map_err(|e| net("BunnieHop", e))?;
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    match v["access_token"].as_str().filter(|t| !t.is_empty()) {
      Some(t) if status.is_success() => {
        *self.access.lock().unwrap_or_else(|e| e.into_inner()) = Some(t.to_string());
        Ok(t.to_string())
      }
      _ if status.is_server_error() => Err(Failure {
        code: "server5xx",
        message: "BunnieHop's sign-in service didn't answer. Trying again later.".into(),
        verbatim: Some(v.to_string()),
      }),
      _ => Err(Failure {
        code: "tokenExpired",
        message: format!(
          "{} signed BunnieHop out. Connect {} again.",
          self.name, self.name
        ),
        verbatim: Some(v.to_string()),
      }),
    }
  }

  /// Sends a request built by `make` with a bearer token, refreshing it once on 401.
  pub async fn send(
    &self,
    make: impl Fn() -> reqwest::RequestBuilder,
  ) -> Result<reqwest::Response, Failure> {
    let t = self.get(false).await?;
    let r = make()
      .bearer_auth(&t)
      .send()
      .await
      .map_err(|e| net(self.name, e))?;
    if r.status() != StatusCode::UNAUTHORIZED {
      return Ok(r);
    }
    let t = self.get(true).await?;
    make()
      .bearer_auth(&t)
      .send()
      .await
      .map_err(|e| net(self.name, e))
  }
}

/// Google-style resumable upload: sends `path` to the session `url` in 8 MB chunks (a multiple
/// of 256 KiB) and returns the final answer, which the caller checks. 308 means "keep going".
pub async fn resumable_put(
  http: &reqwest::Client,
  url: &str,
  path: &Path,
  platform: &str,
) -> Result<reqwest::Response, Failure> {
  use tokio::io::AsyncReadExt;
  const CHUNK: usize = 8 * 1024 * 1024;
  let unreadable = |e: std::io::Error| Failure {
    code: "vaultUnavailable",
    message: "Couldn't read the file.".into(),
    verbatim: Some(e.to_string()),
  };
  let len = tokio::fs::metadata(path).await.map_err(unreadable)?.len();
  let mut f = tokio::fs::File::open(path).await.map_err(unreadable)?;
  let mut sent: u64 = 0;
  let mut buf = vec![0u8; CHUNK];
  loop {
    let mut n = 0;
    while n < CHUNK {
      let k = f.read(&mut buf[n..]).await.map_err(unreadable)?;
      if k == 0 {
        break;
      }
      n += k;
    }
    let end = sent + n as u64;
    // an empty file is one request with no range to send
    let range = if len == 0 {
      "bytes */0".to_string()
    } else if n == 0 {
      return Err(Failure::new(
        "uploadRejected",
        format!("{platform} didn't confirm the upload."),
      ));
    } else {
      format!("bytes {sent}-{}/{len}", end - 1)
    };
    let r = http
      .put(url)
      .header("Content-Length", n.to_string())
      .header("Content-Range", range)
      .body(buf[..n].to_vec())
      .send()
      .await
      .map_err(|e| net(platform, e))?;
    sent = end;
    if r.status().as_u16() != 308 || len == 0 {
      return Ok(r);
    }
  }
}

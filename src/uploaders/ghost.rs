//! Ghost, through a custom integration's Admin API key (Settings → Integrations → Add custom
//! integration). Posts keep their original publish date (`published_at`), tags and HTML; the
//! feature image and any video are uploaded to the site first. Posts are published without
//! sending a newsletter email: moving an archive never mails subscribers.
//!
//! D11: before creating a post, the site is searched for one with the same title and original
//! date, and that post is returned instead.

use super::{
  article_html, created_at, escape_html, file_body, is_image, is_video, json_or_fail, mime_of, net,
  site_url, tags, thumbnail_of, title_text, utc_iso,
};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader, With};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const P: &str = "Ghost";
const VERSION: &str = "v5.0";

pub struct Ghost {
  http: reqwest::Client,
  base: String,
  key_id: String,
  key: Vec<u8>,
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
  let mut k = if key.len() > 64 {
    Sha256::digest(key).to_vec()
  } else {
    key.to_vec()
  };
  k.resize(64, 0);
  let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
  let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
  let mut inner = Sha256::new();
  inner.update(&ipad);
  inner.update(msg);
  let inner = inner.finalize();
  let mut outer = Sha256::new();
  outer.update(&opad);
  outer.update(inner.as_slice());
  let mut out = [0u8; 32];
  out.copy_from_slice(outer.finalize().as_slice());
  out
}

/// Ghost Admin API token: a 5-minute HS256 JWT signed with the integration's secret.
pub fn token(key_id: &str, key: &[u8], now: i64) -> String {
  let h =
    URL_SAFE_NO_PAD.encode(json!({ "alg": "HS256", "typ": "JWT", "kid": key_id }).to_string());
  let p =
    URL_SAFE_NO_PAD.encode(json!({ "iat": now, "exp": now + 300, "aud": "/admin/" }).to_string());
  let sig = URL_SAFE_NO_PAD.encode(hmac_sha256(key, format!("{h}.{p}").as_bytes()));
  format!("{h}.{p}.{sig}")
}

/// "id:hexsecret" as Ghost shows it.
fn parse_key(raw: &str) -> Option<(String, Vec<u8>)> {
  let (id, sec) = raw.trim().split_once(':')?;
  let key = hex::decode(sec).ok()?;
  (!id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) && key.len() >= 16)
    .then(|| (id.to_string(), key))
}

fn unix_now() -> i64 {
  crate::pacing::now_ms() / 1000
}

/// Result of signing in to Ghost Admin with the creator's own email and password.
pub enum SignIn {
  /// Signed in; this Helper made a "BunnieHop" custom integration and holds its Admin key.
  Key { admin: String, key: String },
  /// Ghost emailed a verification code (staff device verification); the session cookie waits.
  NeedsCode { admin: String, cookie: String },
}

/// Where the Ghost admin lives (Ghost(Pro) custom domains redirect `/ghost/` to `*.ghost.io`).
async fn admin_base(http: &reqwest::Client, base: &str) -> String {
  let Ok(r) = http.get(format!("{base}/ghost/")).send().await else {
    return base.to_string();
  };
  let u = r.url();
  let Some(h) = u.host_str() else {
    return base.to_string();
  };
  if u.scheme() != "https" && h != "127.0.0.1" {
    return base.to_string();
  }
  let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
  let path = u
    .path()
    .split("/ghost")
    .next()
    .unwrap_or("")
    .trim_end_matches('/');
  format!("{}://{h}{port}{path}", u.scheme())
}

fn origin_of(admin: &str) -> String {
  match admin.split_once("://") {
    Some((sch, rest)) => format!("{sch}://{}", rest.split('/').next().unwrap_or("")),
    None => admin.to_string(),
  }
}

fn session_cookie(r: &reqwest::Response) -> Option<String> {
  r.headers()
    .get_all("set-cookie")
    .iter()
    .filter_map(|v| v.to_str().ok())
    .find(|c| c.starts_with("ghost-admin-api-session="))
    .and_then(|c| c.split(';').next())
    .map(str::to_string)
}

/// Signs in like Ghost Admin does (email + password, then the emailed code if Ghost asks), makes
/// a "BunnieHop" custom integration and signs out again. Only the integration's Admin key is
/// kept; the password is never stored. Needs an Owner or Administrator account.
pub async fn sign_in(
  http: &reqwest::Client,
  site: &str,
  email: &str,
  password: &str,
  pending: Option<(String, String)>,
  code: Option<&str>,
) -> Result<SignIn, Failure> {
  let base = site_url(site)?;
  let (admin, cookie) = match (pending, code) {
    (Some((admin, cookie)), Some(code)) => {
      let api = format!("{admin}/ghost/api/admin");
      let r = http
        .put(format!("{api}/session/verify/"))
        .header("origin", origin_of(&admin))
        .header("cookie", &cookie)
        .json(&json!({ "token": code.trim() }))
        .send()
        .await
        .map_err(|e| net(P, e))?;
      if !r.status().is_success() {
        let t = r.text().await.unwrap_or_default();
        return Err(
          Failure::new(
            "verificationCode",
            "That code didn't work. Check the newest email from Ghost.",
          )
          .with(t),
        );
      }
      (admin, cookie)
    }
    _ => {
      let admin = admin_base(http, &base).await;
      let api = format!("{admin}/ghost/api/admin");
      let r = http
        .post(format!("{api}/session/"))
        .header("origin", origin_of(&admin))
        .json(&json!({ "username": email.trim(), "password": password }))
        .send()
        .await
        .map_err(|e| net(P, e))?;
      let status = r.status();
      let cookie = session_cookie(&r);
      let text = r.text().await.unwrap_or_default();
      let needs_code = status.as_u16() == 403
        && (text.contains("2FA") || text.contains("erif") || text.contains("Needs2FA"));
      match (status.is_success(), needs_code, cookie) {
        (true, _, Some(c)) => (admin, c),
        (_, true, Some(c)) => return Ok(SignIn::NeedsCode { admin, cookie: c }),
        _ if matches!(status.as_u16(), 401 | 403 | 422) => {
          return Err(
            Failure::new(
              "signInRequired",
              "Ghost didn't accept that email and password.",
            )
            .with(text),
          )
        }
        _ => return Err(super::status_failure(P, status, &text)),
      }
    }
  };
  let api = format!("{admin}/ghost/api/admin");
  let r = http
    .post(format!("{api}/integrations/?include=api_keys"))
    .header("origin", origin_of(&admin))
    .header("cookie", &cookie)
    .json(&json!({ "integrations": [{
      "name": "BunnieHop",
      "description": "Moves your posts in with their original dates. Made when you connected Ghost on bunniehop.party; delete it to disconnect.",
    }] }))
    .send()
    .await;
  let made = json_or_fail(P, r).await.map_err(|f| {
    if f.code == "uploadRejected" {
      Failure {
        code: "signInRequired",
        message: "Only the site owner or an administrator can connect Ghost.".into(),
        verbatim: f.verbatim,
      }
    } else {
      f
    }
  });
  // sign the browser-style session out again either way
  let _ = http
    .delete(format!("{api}/session/"))
    .header("origin", origin_of(&admin))
    .header("cookie", &cookie)
    .send()
    .await;
  let made = made?;
  let key = made
    .pointer("/integrations/0/api_keys")
    .and_then(Value::as_array)
    .and_then(|ks| ks.iter().find(|k| k["type"] == "admin"))
    .and_then(|k| Some(format!("{}:{}", k["id"].as_str()?, k["secret"].as_str()?)))
    .ok_or_else(|| {
      Failure::new(
        "uploadRejected",
        "Ghost didn't make the BunnieHop integration.",
      )
    })?;
  Ok(SignIn::Key { admin, key })
}

/// Checks the key against the site. Returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  url: &str,
  admin_key: &str,
) -> Result<(String, Value), Failure> {
  let base = site_url(url)?;
  let (id, key) = parse_key(admin_key).ok_or_else(|| {
    Failure::new(
      "signInRequired",
      "That isn't an Admin API key. Copy the one under Settings → Integrations → your integration.",
    )
  })?;
  let g = Ghost {
    http: http.clone(),
    base: base.clone(),
    key_id: id,
    key,
  };
  g.get("posts/?limit=1&fields=id").await.map_err(|f| {
    if matches!(f.code, "tokenExpired" | "uploadRejected") {
      Failure {
        code: "signInRequired",
        message: "Ghost didn't accept that Admin API key.".into(),
        verbatim: f.verbatim,
      }
    } else {
      f
    }
  })?;
  let site = g.get("site/").await.unwrap_or(Value::Null);
  let label = site
    .pointer("/site/title")
    .and_then(Value::as_str)
    .map(String::from)
    .unwrap_or_else(|| base.trim_start_matches("https://").to_string());
  Ok((label, json!({ "url": base, "adminKey": admin_key.trim() })))
}

/// NQL string literal.
fn nql(s: &str) -> String {
  format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

impl Ghost {
  pub fn new(http: reqwest::Client, secret: &Value) -> Option<Self> {
    let (key_id, key) = parse_key(secret["adminKey"].as_str()?)?;
    Some(Self {
      http,
      base: secret["url"].as_str()?.to_string(),
      key_id,
      key,
    })
  }

  fn api(&self, path: &str) -> String {
    format!("{}/ghost/api/admin/{path}", self.base)
  }

  fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    r.header(
      "Authorization",
      format!("Ghost {}", token(&self.key_id, &self.key, unix_now())),
    )
    .header("Accept-Version", VERSION)
  }

  async fn get(&self, path: &str) -> Result<Value, Failure> {
    json_or_fail(P, self.auth(self.http.get(self.api(path))).send().await).await
  }

  async fn upload(&self, kind: &str, path: &Path) -> Result<String, Failure> {
    let (b, len) = file_body(path)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the file from the vault.").with(e))?;
    let name = path
      .file_name()
      .and_then(|n| n.to_str())
      .unwrap_or("file")
      .to_string();
    let part = reqwest::multipart::Part::stream_with_length(b, len)
      .file_name(name)
      .mime_str(mime_of(path))
      .map_err(|e| net(P, e))?;
    let form = reqwest::multipart::Form::new().part("file", part);
    let v = json_or_fail(
      P,
      self
        .auth(self.http.post(self.api(&format!("{kind}/upload/"))))
        .multipart(form)
        .send()
        .await,
    )
    .await?;
    v.pointer(&format!("/{kind}/0/url"))
      .and_then(Value::as_str)
      .map(String::from)
      .ok_or_else(|| Failure::new("uploadRejected", "Ghost didn't return the uploaded file."))
  }

  /// A post this hop (or an earlier run) already made: same title, same original date.
  async fn existing(&self, title: &str, date: Option<&str>) -> Result<Option<Value>, Failure> {
    let filter = format!("title:{}", nql(title));
    let q = format!(
      "posts/?limit=20&fields=id,title,url,published_at&filter={}",
      urlencode(&filter)
    );
    let v = self.get(&q).await?;
    let want = date.and_then(utc_iso);
    Ok(
      v["posts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| {
          p["title"] == title
            && match (&want, p["published_at"].as_str().and_then(utc_iso)) {
              (Some(a), Some(b)) => a[..16] == b[..16],
              (None, _) => true,
              _ => false,
            }
        })
        .cloned(),
    )
  }
}

pub fn urlencode(s: &str) -> String {
  let mut o = String::new();
  for b in s.bytes() {
    match b {
      b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
      _ => o.push_str(&format!("%{b:02X}")),
    }
  }
  o
}

impl Uploader for Ghost {
  fn safe_to_retry(&self) -> bool {
    true
  }

  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let title = title_text(u.post, u.item);
      let date = created_at(u.post, u.item);
      if let Some(p) = self.existing(&title, date.as_deref()).await? {
        return Ok(Published {
          note: None,
          dest_item_id: p["id"].as_str().unwrap_or("").to_string(),
          dest_url: p["url"].as_str().map(String::from),
          verified: true,
        });
      }
      let feature =
        match thumbnail_of(u.media).or_else(|| u.media.iter().find(|p| is_image(p)).cloned()) {
          Some(t) => Some(self.upload("images", &t).await?),
          None => None,
        };
      let mut html = String::new();
      if let Some(v) = u.media.iter().find(|p| is_video(p)) {
        let src = self.upload("media", v).await?;
        html.push_str(&format!(
          "<video controls preload=\"metadata\" src=\"{}\"></video>\n",
          escape_html(&src)
        ));
      }
      html.push_str(&article_html(u.post, u.item));
      let mut post = json!({
        "title": title,
        "html": html,
        "status": "published",
        "tags": tags(u.post, u.item).iter().map(|t| json!({ "name": t })).collect::<Vec<_>>(),
      });
      if let Some(d) = date.as_deref().and_then(utc_iso) {
        post["published_at"] = json!(d);
      }
      if let Some(f) = feature {
        post["feature_image"] = json!(f);
      }
      let v = json_or_fail(
        P,
        self
          .auth(self.http.post(self.api("posts/?source=html")))
          .json(&json!({ "posts": [post] }))
          .send()
          .await,
      )
      .await?;
      let id = v
        .pointer("/posts/0/id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
      let check = self.get(&format!("posts/{id}/?fields=id,url")).await;
      Ok(Published {
        note: None,
        dest_url: v
          .pointer("/posts/0/url")
          .and_then(Value::as_str)
          .map(String::from),
        verified: !id.is_empty() && check.is_ok(),
        dest_item_id: id,
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Query, State};
  use axum::http::HeaderMap;
  use axum::routing::{get, post};
  use axum::{Json, Router};
  use std::collections::HashMap;
  use std::sync::{Arc, Mutex};

  const KEY: &str =
    "6489e0c1a1b2c3d4e5f60718:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  #[test]
  fn ghost_hmac_matches_rfc_4231_and_tokens_have_the_admin_audience() {
    assert_eq!(
      hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let (id, key) = parse_key(KEY).unwrap();
    let t = token(&id, &key, 1_700_000_000);
    let parts: Vec<&str> = t.split('.').collect();
    let head: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let body: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(head["kid"], id);
    assert_eq!(body["aud"], "/admin/");
    assert_eq!(
      body["exp"].as_i64().unwrap() - body["iat"].as_i64().unwrap(),
      300
    );
    assert!(parse_key("not-a-key").is_none());
    assert_eq!(nql("It's"), "'It\\'s'");
  }

  #[derive(Default)]
  struct Site {
    posts: Vec<Value>,
    uploads: Vec<String>,
  }
  type S = Arc<Mutex<Site>>;

  fn authed(h: &HeaderMap) -> bool {
    h.get("authorization")
      .and_then(|v| v.to_str().ok())
      .is_some_and(|v| v.starts_with("Ghost ey"))
  }

  fn fake(s: S) -> Router {
    Router::new()
      .route(
        "/ghost/api/admin/site/",
        get(|| async { Json(json!({ "site": { "title": "Mara Writes" } })) }),
      )
      .route(
        "/ghost/api/admin/posts/",
        get(
          |State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
            assert!(authed(&h));
            let posts: Vec<Value> = s
              .lock()
              .unwrap()
              .posts
              .iter()
              .filter(|p| match q.get("filter") {
                Some(f) => f == &format!("title:{}", nql(p["title"].as_str().unwrap())),
                None => true,
              })
              .cloned()
              .collect();
            Json(json!({ "posts": posts }))
          },
        )
        .post(
          |State(s): State<S>, h: HeaderMap, Json(b): Json<Value>| async move {
            assert!(authed(&h));
            let mut p = b["posts"][0].clone();
            p["id"] = json!("p1");
            p["url"] = json!("https://mara.ghost.io/first/");
            s.lock().unwrap().posts.push(p.clone());
            Json(json!({ "posts": [p] }))
          },
        ),
      )
      .route(
        "/ghost/api/admin/posts/{id}/",
        get(|| async { Json(json!({ "posts": [{ "id": "p1" }] })) }),
      )
      .route(
        "/ghost/api/admin/images/upload/",
        post(|State(s): State<S>, _b: axum::body::Bytes| async move {
          s.lock().unwrap().uploads.push("image".into());
          Json(json!({ "images": [{ "url": "https://mara.ghost.io/content/images/t.jpg" }] }))
        }),
      )
      .with_state(s)
  }

  #[tokio::test]
  async fn ghost_publishes_with_the_original_date_and_never_twice() {
    let site: S = Arc::default();
    let base = serve(fake(site.clone())).await;
    let http = reqwest::Client::new();
    let (label, secret) = connect(&http, &base, KEY).await.unwrap();
    assert_eq!(label, "Mara Writes");
    let g = Ghost::new(http, &secret).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("thumbnail.jpg"), b"jpg").unwrap();
    let media = [dir.path().join("media.html")];
    let item = json!({ "id": "s1", "kind": "article", "title": "It's here", "bodyHtml": "<p>Body</p>", "tags": ["news"], "publishedAt": "2021-03-04T05:06:07-05:00" });
    let up = |k: &'static str| Upload {
      item: &item,
      post: None,
      media: &media,
      idempotency_key: k,
      options: &Value::Null,
    };
    let p = g.publish(up("h:s1:ghost")).await.unwrap();
    assert!(p.verified);
    assert_eq!(p.dest_url.as_deref(), Some("https://mara.ghost.io/first/"));
    {
      let s = site.lock().unwrap();
      let post = &s.posts[0];
      assert_eq!(post["published_at"], "2021-03-04T10:06:07Z");
      assert_eq!(post["html"], "<p>Body</p>");
      assert_eq!(post["tags"][0]["name"], "news");
      assert_eq!(
        post["feature_image"],
        "https://mara.ghost.io/content/images/t.jpg"
      );
      assert!(post.get("newsletter").is_none(), "no email to subscribers");
    }
    // a second run (crash after create, or a new hop) finds the post instead of making another
    let again = g.publish(up("h2:s1:ghost")).await.unwrap();
    assert_eq!(again.dest_item_id, "p1");
    let s = site.lock().unwrap();
    assert_eq!(s.posts.len(), 1);
    assert_eq!(s.uploads.len(), 1);
  }

  #[tokio::test]
  async fn ghost_rejects_a_malformed_key_before_calling_the_site() {
    let f = connect(&reqwest::Client::new(), "example.com", "abc")
      .await
      .unwrap_err();
    assert_eq!(f.code, "signInRequired");
  }
}

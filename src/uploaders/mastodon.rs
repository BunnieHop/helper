//! Mastodon (and Pixelfed, which speaks the same API). Signs in with OAuth in the creator's own
//! browser; the token stays in the keychain. D11: statuses carry an `Idempotency-Key`, and a
//! cell that already published is never sent again.

use super::{
  alt_texts, base_url, body_text, file_body, is_image, is_video, json_or_fail, mime_of, net, thread,
};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader};
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use std::time::Duration;

pub const SCOPES: &str = "read:accounts read:statuses write:media write:statuses";

pub struct Mastodon {
  http: reqwest::Client,
  base: String,
  token: String,
  name: &'static str,
  poll: Duration,
}

impl Mastodon {
  pub fn new(http: reqwest::Client, secret: &Value, platform: &str) -> Option<Self> {
    Some(Self {
      http,
      base: base_url(secret.get("instance")?.as_str()?).ok()?,
      token: secret.get("token")?.as_str()?.to_string(),
      name: if platform == "pixelfed" {
        "Pixelfed"
      } else {
        "Mastodon"
      },
      poll: Duration::from_secs(2),
    })
  }

  async fn upload(&self, path: &std::path::Path, alt: Option<&str>) -> Result<String, Failure> {
    let (body, len) = file_body(path).await.map_err(|e| Failure {
      code: "vaultUnavailable",
      message: "Couldn't read the media file.".into(),
      verbatim: Some(e.to_string()),
    })?;
    let name = path
      .file_name()
      .and_then(|n| n.to_str())
      .unwrap_or("media")
      .to_string();
    let part = Part::stream_with_length(body, len)
      .file_name(name)
      .mime_str(mime_of(path))
      .map_err(|e| net(self.name, e))?;
    let mut form = Form::new().part("file", part);
    if let Some(a) = alt.filter(|a| !a.is_empty()) {
      form = form.text("description", a.to_string());
    }
    let r = self
      .http
      .post(format!("{}/api/v2/media", self.base))
      .bearer_auth(&self.token)
      .multipart(form)
      .send()
      .await;
    let v = json_or_fail(self.name, r).await?;
    let id = v["id"]
      .as_str()
      .map(String::from)
      .or_else(|| v["id"].as_u64().map(|n| n.to_string()))
      .unwrap_or_default();
    // 202: still processing (video); the status can only attach it once `url` is set.
    let mut ready = !v["url"].is_null();
    for _ in 0..300 {
      if ready {
        break;
      }
      tokio::time::sleep(self.poll).await;
      let r = self
        .http
        .get(format!("{}/api/v1/media/{id}", self.base))
        .bearer_auth(&self.token)
        .send()
        .await
        .map_err(|e| net(self.name, e))?;
      if r.status().as_u16() == 200 {
        ready = !r
          .json::<Value>()
          .await
          .map(|m| m["url"].is_null())
          .unwrap_or(true);
      }
    }
    if !ready {
      return Err(Failure::new(
        "progressStalled",
        format!(
          "{} is still processing the video after 10 minutes.",
          self.name
        ),
      ));
    }
    Ok(id)
  }

  async fn status(
    &self,
    text: &str,
    media: &[String],
    reply_to: Option<&str>,
    key: &str,
    lang: Option<&str>,
  ) -> Result<Value, Failure> {
    let mut b = json!({ "status": text, "visibility": "public", "media_ids": media });
    if let Some(r) = reply_to {
      b["in_reply_to_id"] = json!(r);
    }
    if let Some(l) = lang {
      b["language"] = json!(l);
    }
    let r = self
      .http
      .post(format!("{}/api/v1/statuses", self.base))
      .bearer_auth(&self.token)
      .header("Idempotency-Key", key)
      .json(&b)
      .send()
      .await;
    json_or_fail(self.name, r).await
  }
}

impl Uploader for Mastodon {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let alts = alt_texts(u.post);
      let mut ids = Vec::new();
      if let Some(v) = u.media.iter().find(|p| is_video(p)) {
        ids.push(self.upload(v, alts.first().map(String::as_str)).await?);
      } else {
        for (k, p) in u.media.iter().filter(|p| is_image(p)).take(4).enumerate() {
          ids.push(self.upload(p, alts.get(k).map(String::as_str)).await?);
        }
      }
      let lang = u.item.get("language").and_then(Value::as_str);
      let root = self
        .status(
          &body_text(u.post, u.item),
          &ids,
          None,
          u.idempotency_key,
          lang,
        )
        .await?;
      let root_id = root["id"].as_str().unwrap_or("").to_string();
      let mut parent = root_id.clone();
      for (n, t) in thread(u.post).iter().enumerate() {
        let s = self
          .status(
            t,
            &[],
            Some(&parent),
            &format!("{}:{}", u.idempotency_key, n + 1),
            lang,
          )
          .await?;
        parent = s["id"].as_str().unwrap_or("").to_string();
      }
      let check = self
        .http
        .get(format!("{}/api/v1/statuses/{root_id}", self.base))
        .bearer_auth(&self.token)
        .send()
        .await;
      let verified = matches!(check, Ok(r) if r.status().is_success());
      Ok(Published {
        note: None,
        dest_item_id: root_id,
        dest_url: root["url"].as_str().map(String::from),
        verified,
      })
    })
  }
}

/// Step 1 of sign-in: register BunnieHop on the creator's server for this Helper's callback.
pub async fn register_app(
  http: &reqwest::Client,
  base: &str,
  redirect: &str,
) -> Result<(String, String), Failure> {
  let r = http
    .post(format!("{base}/api/v1/apps"))
    .json(&json!({ "client_name": "BunnieHop", "redirect_uris": redirect, "scopes": SCOPES, "website": "https://bunniehop.party" }))
    .send()
    .await;
  let v = json_or_fail("Mastodon", r).await?;
  Ok((
    v["client_id"].as_str().unwrap_or("").into(),
    v["client_secret"].as_str().unwrap_or("").into(),
  ))
}

pub fn authorize_url(base: &str, client_id: &str, redirect: &str, state: &str) -> String {
  let q = |s: &str| -> String {
    s.bytes()
      .map(|b| {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
          (b as char).to_string()
        } else {
          format!("%{b:02X}")
        }
      })
      .collect()
  };
  format!(
    "{base}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
    q(client_id),
    q(redirect),
    q(SCOPES),
    q(state)
  )
}

/// Step 3: trade the code for a token, then read the account it belongs to.
pub async fn finish(
  http: &reqwest::Client,
  base: &str,
  client: (&str, &str),
  redirect: &str,
  code: &str,
) -> Result<(String, String), Failure> {
  let r = http
    .post(format!("{base}/oauth/token"))
    .form(&[
      ("grant_type", "authorization_code"),
      ("code", code),
      ("client_id", client.0),
      ("client_secret", client.1),
      ("redirect_uri", redirect),
      ("scope", SCOPES),
    ])
    .send()
    .await;
  let token = json_or_fail("Mastodon", r).await?["access_token"]
    .as_str()
    .unwrap_or("")
    .to_string();
  let r = http
    .get(format!("{base}/api/v1/accounts/verify_credentials"))
    .bearer_auth(&token)
    .send()
    .await;
  let me = json_or_fail("Mastodon", r).await?;
  let host = base.split("://").nth(1).unwrap_or(base);
  Ok((
    token,
    format!("@{}@{host}", me["acct"].as_str().unwrap_or("me")),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::State;
  use axum::http::HeaderMap;
  use axum::routing::{get, post};
  use axum::{Json, Router};
  use std::collections::HashMap;
  use std::sync::{Arc, Mutex};

  #[derive(Default)]
  struct Inst {
    statuses: Mutex<HashMap<String, Value>>,
    polls: Mutex<u32>,
  }

  fn app(i: Arc<Inst>) -> Router {
    Router::new()
      .route("/api/v2/media", post(|_b: axum::body::Bytes| async { (axum::http::StatusCode::ACCEPTED, Json(json!({ "id": "m1", "url": null }))) }))
      .route(
        "/api/v1/media/{id}",
        get(|State(i): State<Arc<Inst>>| async move {
          let mut n = i.polls.lock().unwrap();
          *n += 1;
          if *n < 2 {
            (axum::http::StatusCode::PARTIAL_CONTENT, Json(json!({ "id": "m1", "url": null })))
          } else {
            (axum::http::StatusCode::OK, Json(json!({ "id": "m1", "url": "https://files/x.mp4" })))
          }
        }),
      )
      .route(
        "/api/v1/statuses",
        post(|State(i): State<Arc<Inst>>, h: HeaderMap, Json(b): Json<Value>| async move {
          let key = h["idempotency-key"].to_str().unwrap().to_string();
          let mut s = i.statuses.lock().unwrap();
          // Mastodon returns the same status for a repeated Idempotency-Key
          let n = s.len();
          let st = s.entry(key).or_insert_with(|| json!({ "id": format!("{}", 100 + n), "url": format!("https://m.example/@mara/{}", 100 + n), "body": b })).clone();
          Json(st)
        }),
      )
      .route("/api/v1/statuses/{id}", get(|| async { Json(json!({ "id": "100" })) }))
      .route("/api/v1/apps", post(|| async { Json(json!({ "client_id": "cid", "client_secret": "csec" })) }))
      .route("/oauth/token", post(|| async { Json(json!({ "access_token": "tok" })) }))
      .route("/api/v1/accounts/verify_credentials", get(|| async { Json(json!({ "acct": "mara" })) }))
      .with_state(i)
  }

  #[tokio::test]
  async fn mastodon_waits_for_video_processing_and_threads_with_idempotency_keys() {
    let i = Arc::new(Inst::default());
    let base = serve(app(i.clone())).await;
    let mut m = Mastodon::new(
      reqwest::Client::new(),
      &json!({ "instance": base, "token": "tok" }),
      "mastodon",
    )
    .unwrap();
    m.poll = Duration::from_millis(5);
    let dir = tempfile::tempdir().unwrap();
    let media = dir.path().join("media.mp4");
    std::fs::write(&media, b"v").unwrap();
    let item = json!({ "id": "a", "title": "Hello", "language": "en" });
    let post = json!({ "fields": { "body": "Hello from the vault" }, "thread": ["2/2"] });
    let up = || Upload {
      item: &item,
      post: Some(&post),
      media: std::slice::from_ref(&media),
      idempotency_key: "hop:a:mastodon",
      options: &Value::Null,
    };
    let p = m.publish(up()).await.unwrap();
    assert!(p.verified);
    assert_eq!(p.dest_url.as_deref(), Some("https://m.example/@mara/100"));
    {
      let s = i.statuses.lock().unwrap();
      assert_eq!(s.len(), 2);
      assert_eq!(s["hop:a:mastodon"]["body"]["media_ids"], json!(["m1"]));
      assert_eq!(s["hop:a:mastodon"]["body"]["language"], "en");
      assert_eq!(s["hop:a:mastodon:1"]["body"]["in_reply_to_id"], "100");
    }
    m.publish(up()).await.unwrap();
    assert_eq!(
      i.statuses.lock().unwrap().len(),
      2,
      "same keys → no second status"
    );
  }

  #[tokio::test]
  async fn mastodon_oauth_steps() {
    let base = serve(app(Arc::new(Inst::default()))).await;
    let http = reqwest::Client::new();
    let redirect = "http://127.0.0.1:17333/v1/oauth/callback";
    let (id, secret) = register_app(&http, &base, redirect).await.unwrap();
    let url = authorize_url(&base, &id, redirect, "st8");
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A17333%2Fv1%2Foauth%2Fcallback"));
    assert!(url.contains("scope=read%3Aaccounts%20"));
    let (tok, label) = finish(&http, &base, (&id, &secret), redirect, "code")
      .await
      .unwrap();
    assert_eq!(tok, "tok");
    assert!(label.starts_with("@mara@127.0.0.1"));
  }
}

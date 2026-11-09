//! PeerTube: password sign-in (the instance's own OAuth client), resumable upload in 8 MB
//! chunks, `originallyPublishedAt` keeps the original date. Only the refresh token is kept, in
//! the keychain; the password is never stored. D11: before uploading, the channel is checked for
//! a video this hop already made (same name and original date).

use super::{
  base_url, body_text, created_at, json_or_fail, mime_of, net, status_failure, tags, title_text,
};
use crate::connections::Store;
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

const P: &str = "PeerTube";
const CHUNK: usize = 8 * 1024 * 1024;

pub struct PeerTube {
  http: reqwest::Client,
  store: Arc<Store>,
  conn_id: String,
  base: String,
  secret: Mutex<Value>,
  channel: Option<String>,
}

pub struct Account {
  pub label: String,
  pub secret: Value,
  pub channels: Vec<(String, String)>,
}

/// Signs in with username + password and returns the account, its channels and the tokens.
pub async fn connect(
  http: &reqwest::Client,
  instance: &str,
  username: &str,
  password: &str,
) -> Result<Account, Failure> {
  let base = base_url(instance)?;
  let c = json_or_fail(
    P,
    http
      .get(format!("{base}/api/v1/oauth-clients/local"))
      .send()
      .await,
  )
  .await?;
  let (cid, csec) = (
    c["client_id"].as_str().unwrap_or(""),
    c["client_secret"].as_str().unwrap_or(""),
  );
  let r = http
    .post(format!("{base}/api/v1/users/token"))
    .form(&[
      ("client_id", cid),
      ("client_secret", csec),
      ("grant_type", "password"),
      ("username", username.trim()),
      ("password", password),
    ])
    .send()
    .await;
  let t = json_or_fail(P, r).await.map_err(|f| {
    if f.code == "uploadRejected" || f.code == "tokenExpired" {
      Failure {
        code: "signInRequired",
        message: "PeerTube didn't accept that username and password.".into(),
        verbatim: f.verbatim,
      }
    } else {
      f
    }
  })?;
  let access = t["access_token"].as_str().unwrap_or("").to_string();
  let me = json_or_fail(
    P,
    http
      .get(format!("{base}/api/v1/users/me"))
      .bearer_auth(&access)
      .send()
      .await,
  )
  .await?;
  let channels = me["videoChannels"]
    .as_array()
    .map(|a| {
      a.iter()
        .map(|c| {
          (
            c["id"].to_string(),
            c["displayName"]
              .as_str()
              .or(c["name"].as_str())
              .unwrap_or("")
              .to_string(),
          )
        })
        .collect()
    })
    .unwrap_or_default();
  let host = base.split("://").nth(1).unwrap_or(&base).to_string();
  Ok(Account {
    label: format!("{}@{host}", me["username"].as_str().unwrap_or(username)),
    secret: json!({ "instance": base, "clientId": cid, "clientSecret": csec, "accessToken": access, "refreshToken": t["refresh_token"] }),
    channels,
  })
}

impl PeerTube {
  pub fn new(
    http: reqwest::Client,
    store: Arc<Store>,
    conn_id: String,
    secret: Value,
    channel: Option<String>,
  ) -> Option<Self> {
    Some(Self {
      http,
      store,
      conn_id,
      base: base_url(secret.get("instance")?.as_str()?).ok()?,
      secret: Mutex::new(secret),
      channel,
    })
  }

  fn token(&self) -> String {
    self
      .secret
      .lock()
      .map(|s| s["accessToken"].as_str().unwrap_or("").to_string())
      .unwrap_or_default()
  }

  /// Access tokens last about a day; a 401 trades the refresh token for new ones, saved back.
  async fn refresh(&self) -> Result<(), Failure> {
    let s = self.secret.lock().map(|s| s.clone()).unwrap_or_default();
    let r = self
      .http
      .post(format!("{}/api/v1/users/token", self.base))
      .form(&[
        ("client_id", s["clientId"].as_str().unwrap_or("")),
        ("client_secret", s["clientSecret"].as_str().unwrap_or("")),
        ("grant_type", "refresh_token"),
        ("refresh_token", s["refreshToken"].as_str().unwrap_or("")),
      ])
      .send()
      .await;
    let t = json_or_fail(P, r).await.map_err(|f| Failure {
      code: "tokenExpired",
      message: "PeerTube signed BunnieHop out. Connect the account again.".into(),
      verbatim: f.verbatim,
    })?;
    let mut next = s;
    next["accessToken"] = t["access_token"].clone();
    next["refreshToken"] = t["refresh_token"].clone();
    let _ = self.store.set_secret(&self.conn_id, &next);
    if let Ok(mut g) = self.secret.lock() {
      *g = next;
    }
    Ok(())
  }

  /// Sends a request, refreshing the token once on 401.
  async fn send(
    &self,
    build: impl Fn(&str) -> reqwest::RequestBuilder,
  ) -> Result<reqwest::Response, Failure> {
    let r = build(&self.token()).send().await.map_err(|e| net(P, e))?;
    if r.status().as_u16() != 401 {
      return Ok(r);
    }
    self.refresh().await?;
    build(&self.token()).send().await.map_err(|e| net(P, e))
  }

  async fn existing(&self, name: &str, original: Option<&str>) -> Option<Value> {
    let r = self
      .send(|t| {
        self
          .http
          .get(format!("{}/api/v1/users/me/videos", self.base))
          .query(&[("search", name), ("count", "25")])
          .bearer_auth(t)
      })
      .await
      .ok()?;
    let v: Value = r.json().await.ok()?;
    let day = |s: &str| s.get(..10).map(String::from);
    v["data"]
      .as_array()?
      .iter()
      .find(|x| {
        x["name"] == name
          && original.and_then(day) == x["originallyPublishedAt"].as_str().and_then(day)
      })
      .cloned()
  }

  async fn channel_id(&self) -> Result<String, Failure> {
    if let Some(c) = &self.channel {
      return Ok(c.clone());
    }
    let r = self
      .send(|t| {
        self
          .http
          .get(format!("{}/api/v1/users/me", self.base))
          .bearer_auth(t)
      })
      .await?;
    let me: Value = r.json().await.map_err(|e| net(P, e))?;
    me.pointer("/videoChannels/0/id")
      .map(|v| v.to_string())
      .ok_or_else(|| {
        Failure::new(
          "requiredChoiceMissing",
          "This PeerTube account has no channel to upload to.",
        )
      })
  }

  async fn upload(&self, path: &PathBuf, meta: Value) -> Result<Value, Failure> {
    let len = tokio::fs::metadata(path)
      .await
      .map_err(|e| Failure {
        code: "vaultUnavailable",
        message: "Couldn't read the video.".into(),
        verbatim: Some(e.to_string()),
      })?
      .len();
    let mime = mime_of(path);
    let r = self
      .send(|t| {
        self
          .http
          .post(format!("{}/api/v1/videos/upload-resumable", self.base))
          .bearer_auth(t)
          .header("X-Upload-Content-Length", len.to_string())
          .header("X-Upload-Content-Type", mime)
          .json(&meta)
      })
      .await?;
    if !r.status().is_success() {
      let s = r.status();
      return Err(status_failure(P, s, &r.text().await.unwrap_or_default()));
    }
    let loc = r
      .headers()
      .get("location")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();
    let url = if loc.starts_with("//") {
      format!("{}:{loc}", self.base.split(':').next().unwrap_or("https"))
    } else if loc.starts_with('/') {
      format!("{}{loc}", self.base)
    } else {
      loc
    };
    let mut f = tokio::fs::File::open(path).await.map_err(|e| Failure {
      code: "vaultUnavailable",
      message: "Couldn't read the video.".into(),
      verbatim: Some(e.to_string()),
    })?;
    let mut sent: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
      let mut n = 0;
      while n < CHUNK {
        let k = f.read(&mut buf[n..]).await.map_err(|e| Failure {
          code: "vaultUnavailable",
          message: "Couldn't read the video.".into(),
          verbatim: Some(e.to_string()),
        })?;
        if k == 0 {
          break;
        }
        n += k;
      }
      if n == 0 && sent > 0 {
        return Err(Failure::new(
          "uploadRejected",
          "PeerTube didn't confirm the upload.",
        ));
      }
      let end = sent + n as u64;
      let chunk = buf[..n].to_vec();
      let r = self
        .send(|t| {
          self
            .http
            .put(&url)
            .bearer_auth(t)
            .header(
              "Content-Range",
              format!("bytes {sent}-{}/{len}", end.saturating_sub(1)),
            )
            .header("Content-Type", "application/octet-stream")
            .body(chunk.clone())
        })
        .await?;
      let status = r.status().as_u16();
      sent = end;
      match status {
        308 => continue,
        200 | 201 => return r.json::<Value>().await.map_err(|e| net(P, e)),
        _ => {
          return Err(status_failure(
            P,
            r.status(),
            &r.text().await.unwrap_or_default(),
          ))
        }
      }
    }
  }
}

/// PeerTube tags: at most 5, each 2–30 characters.
fn clean_tags(t: Vec<String>) -> Vec<String> {
  t.into_iter()
    .map(|s| {
      s.trim_start_matches('#')
        .chars()
        .take(30)
        .collect::<String>()
    })
    .filter(|s| s.chars().count() >= 2)
    .take(5)
    .collect()
}

impl Uploader for PeerTube {
  fn safe_to_retry(&self) -> bool {
    true
  }

  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let media = u
        .media
        .iter()
        .find(|p| super::is_video(p))
        .ok_or_else(|| Failure::new("notSupported", "PeerTube takes videos only."))?;
      let mut name: String = title_text(u.post, u.item).chars().take(120).collect();
      while name.chars().count() < 3 {
        name.push('.');
      }
      let original = created_at(u.post, u.item);
      let video = match self.existing(&name, original.as_deref()).await {
        Some(v) => v,
        None => {
          let mut meta = json!({
            "name": name,
            "channelId": self.channel_id().await?.parse::<u64>().unwrap_or(0),
            "filename": media.file_name().and_then(|n| n.to_str()).unwrap_or("media.mp4"),
            "privacy": 1,
            "description": body_text(u.post, u.item).chars().take(10_000).collect::<String>(),
            "tags": clean_tags(tags(u.post, u.item)),
            "commentsPolicy": 1,
            "downloadEnabled": true,
          });
          if let Some(o) = &original {
            meta["originallyPublishedAt"] = json!(o);
          }
          if let Some(l) = u.item.get("language").and_then(Value::as_str) {
            meta["language"] = json!(l);
          }
          let res = self.upload(media, meta).await?;
          res.get("video").cloned().unwrap_or(res)
        }
      };
      let uuid = video["uuid"]
        .as_str()
        .or(video["shortUUID"].as_str())
        .unwrap_or("")
        .to_string();
      let short = video["shortUUID"].as_str().unwrap_or(&uuid).to_string();
      let check = self
        .send(|t| {
          self
            .http
            .get(format!("{}/api/v1/videos/{uuid}", self.base))
            .bearer_auth(t)
        })
        .await;
      let verified = matches!(check, Ok(r) if r.status().is_success());
      Ok(Published {
        note: None,
        dest_item_id: uuid,
        dest_url: Some(format!("{}/w/{short}", self.base)),
        verified,
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::connections::MemorySecrets;
  use crate::uploaders::testkit::serve;
  use axum::extract::State;
  use axum::http::{HeaderMap, StatusCode};
  use axum::routing::{get, post, put};
  use axum::{Json, Router};

  #[derive(Default)]
  struct Inst {
    bytes: Mutex<Vec<u8>>,
    meta: Mutex<Option<Value>>,
    uploads: Mutex<u32>,
    expire_once: Mutex<bool>,
  }

  fn app(i: Arc<Inst>) -> Router {
    Router::new()
      .route("/api/v1/oauth-clients/local", get(|| async { Json(json!({ "client_id": "c", "client_secret": "s" })) }))
      .route(
        "/api/v1/users/token",
        post(|body: String| async move {
          if body.contains("grant_type=password") && !body.contains("password=right") {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid credentials" })));
          }
          (StatusCode::OK, Json(json!({ "access_token": if body.contains("refresh_token") { "a2" } else { "a1" }, "refresh_token": "r2" })))
        }),
      )
      .route("/api/v1/users/me", get(|| async { Json(json!({ "username": "mara", "videoChannels": [{ "id": 7, "displayName": "Mara" }] })) }))
      .route(
        "/api/v1/users/me/videos",
        get(|State(i): State<Arc<Inst>>, h: HeaderMap| async move {
          // first call after connect: the access token has expired
          if std::mem::replace(&mut *i.expire_once.lock().unwrap(), false) && h["authorization"] == "Bearer a1" {
            return (StatusCode::UNAUTHORIZED, Json(json!({})));
          }
          let data = if i.meta.lock().unwrap().is_some() && *i.uploads.lock().unwrap() > 0 {
            let m = i.meta.lock().unwrap().clone().unwrap();
            vec![json!({ "name": m["name"], "originallyPublishedAt": m["originallyPublishedAt"], "uuid": "u1", "shortUUID": "s1" })]
          } else {
            vec![]
          };
          (StatusCode::OK, Json(json!({ "data": data })))
        }),
      )
      .route(
        "/api/v1/videos/upload-resumable",
        post(|State(i): State<Arc<Inst>>, Json(b): Json<Value>| async move {
          *i.meta.lock().unwrap() = Some(b);
          (StatusCode::CREATED, [("location", "/api/v1/videos/upload-resumable?upload_id=x")])
        })
        .put(|State(i): State<Arc<Inst>>, h: HeaderMap, body: axum::body::Bytes| async move {
          i.bytes.lock().unwrap().extend_from_slice(&body);
          let range = h["content-range"].to_str().unwrap().to_string();
          let total: usize = range.rsplit('/').next().unwrap().parse().unwrap();
          if i.bytes.lock().unwrap().len() < total {
            (StatusCode::PERMANENT_REDIRECT, Json(json!({})))
          } else {
            *i.uploads.lock().unwrap() += 1;
            (StatusCode::OK, Json(json!({ "video": { "id": 1, "uuid": "u1", "shortUUID": "s1" } })))
          }
        }),
      )
      .route("/api/v1/videos/{id}", get(|| async { Json(json!({ "uuid": "u1" })) }))
      .route("/unused", put(|| async { "" }))
      .layer(axum::extract::DefaultBodyLimit::disable())
      .with_state(i)
  }

  #[tokio::test]
  async fn peertube_resumable_upload_keeps_the_date_refreshes_and_never_reuploads() {
    let i = Arc::new(Inst::default());
    let base = serve(app(i.clone())).await;
    let http = reqwest::Client::new();
    assert_eq!(
      connect(&http, &base, "mara", "wrong")
        .await
        .err()
        .unwrap()
        .code,
      "signInRequired"
    );
    let acct = connect(&http, &base, "mara", "right").await.unwrap();
    assert!(acct.label.starts_with("mara@127.0.0.1"));
    assert_eq!(acct.channels, [("7".to_string(), "Mara".to_string())]);
    assert!(
      acct.secret.get("password").is_none(),
      "password is not kept"
    );
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(
      dir.path().join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    store.set_secret("pt-1", &acct.secret).unwrap();
    let pt = PeerTube::new(
      http,
      store.clone(),
      "pt-1".into(),
      acct.secret,
      Some("7".into()),
    )
    .unwrap();
    let media = dir.path().join("media.mp4");
    let bytes: Vec<u8> = (0..(CHUNK + 1000)).map(|n| (n % 251) as u8).collect();
    std::fs::write(&media, &bytes).unwrap();
    *i.expire_once.lock().unwrap() = true;
    let item = json!({ "id": "a", "title": "My video", "description": "About it", "tags": ["#one", "x", "two"], "publishedAt": "2019-03-04T05:06:07Z" });
    let up = || Upload {
      item: &item,
      post: None,
      media: std::slice::from_ref(&media),
      idempotency_key: "hop:a:peertube",
      options: &Value::Null,
    };
    let p = pt.publish(up()).await.unwrap();
    assert!(p.verified);
    assert!(p.dest_url.unwrap().ends_with("/w/s1"));
    assert_eq!(
      *i.bytes.lock().unwrap(),
      bytes,
      "two chunks reassemble to the file"
    );
    let meta = i.meta.lock().unwrap().clone().unwrap();
    assert_eq!(meta["originallyPublishedAt"], "2019-03-04T05:06:07Z");
    assert_eq!(meta["channelId"], 7);
    assert_eq!(meta["tags"], json!(["one", "two"]));
    assert_eq!(
      store.secret("pt-1").unwrap()["accessToken"],
      "a2",
      "refreshed token saved to the keychain"
    );
    pt.publish(up()).await.unwrap();
    assert_eq!(
      *i.uploads.lock().unwrap(),
      1,
      "found on the channel → no second upload (D11)"
    );
  }
}

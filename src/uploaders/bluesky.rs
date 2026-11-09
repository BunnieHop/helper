//! Bluesky (AT Protocol), signed in through the creator's own server (`atproto_oauth`; an app
//! password still works as the advanced fallback). Posts keep their original date (`createdAt`,
//! PLAN "backdate"). D11: each post's record key is derived from the hop's idempotency key, so
//! a retry finds the post it already made instead of making a second one.

use super::atproto_oauth::{self as oauth, Body};
use super::{
  alt_texts, body_text, created_at, file_body, is_image, is_video, json_or_fail, mime_of, net,
  status_failure, thread, Endpoints,
};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader};
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const P: &str = "Bluesky";
const MAX_IMAGE: u64 = 1_000_000;

pub struct Bluesky {
  http: reqwest::Client,
  mode: Mode,
  video: String,
  poll: Duration,
}

enum Mode {
  Password {
    service: String,
    identifier: String,
    password: String,
  },
  OAuth {
    session: Arc<oauth::Session>,
    handle: String,
  },
}

enum Auth {
  Bearer(String),
  OAuth(Arc<oauth::Session>),
}

struct Session {
  auth: Auth,
  did: String,
  handle: String,
  pds: String,
}

impl Bluesky {
  pub fn new(
    http: reqwest::Client,
    secret: &Value,
    ep: &Endpoints,
    store: Arc<crate::connections::Store>,
    conn_id: &str,
  ) -> Option<Self> {
    let mode = if secret["oauth"] == true {
      Mode::OAuth {
        session: Arc::new(oauth::Session::new(
          http.clone(),
          ep,
          store,
          conn_id.to_string(),
          secret,
        )?),
        handle: secret["handle"].as_str().unwrap_or("").to_string(),
      }
    } else {
      Mode::Password {
        service: secret
          .get("service")
          .and_then(Value::as_str)
          .unwrap_or("https://bsky.social")
          .to_string(),
        identifier: secret.get("identifier")?.as_str()?.to_string(),
        password: secret.get("appPassword")?.as_str()?.to_string(),
      }
    };
    Some(Self {
      http,
      mode,
      video: ep.bsky_video.clone(),
      poll: Duration::from_secs(2),
    })
  }

  async fn session(&self) -> Result<Session, Failure> {
    match &self.mode {
      Mode::Password {
        service,
        identifier,
        password,
      } => login(&self.http, service, identifier, password).await,
      Mode::OAuth { session, handle } => Ok(Session {
        auth: Auth::OAuth(session.clone()),
        did: session.did.clone(),
        handle: if handle.is_empty() {
          session.did.clone()
        } else {
          handle.clone()
        },
        pds: session.pds.clone(),
      }),
    }
  }

  /// One XRPC call to the creator's PDS (bearer for app passwords, DPoP for OAuth).
  async fn call(
    &self,
    s: &Session,
    m: Method,
    url: &str,
    q: &[(&str, &str)],
    body: Body,
  ) -> Result<reqwest::Response, Failure> {
    match &s.auth {
      Auth::OAuth(o) => o.send(m, url, q, &body).await,
      Auth::Bearer(jwt) => {
        let rb = self.http.request(m, url).query(q).bearer_auth(jwt);
        let rb = match body {
          Body::None => rb,
          Body::Json(v) => rb.json(&v),
          Body::Bytes(b, ct) => rb.header("content-type", ct).body(b),
        };
        rb.send().await.map_err(|e| net(P, e))
      }
    }
  }

  /// A short service token from the PDS for Bluesky's video service.
  async fn service_token(&self, s: &Session, aud: &str, lxm: &str) -> Result<String, Failure> {
    let exp = (time::OffsetDateTime::now_utc().unix_timestamp() + 1800).to_string();
    let r = self
      .call(
        s,
        Method::GET,
        &format!("{}/xrpc/com.atproto.server.getServiceAuth", s.pds),
        &[("aud", aud), ("lxm", lxm), ("exp", &exp)],
        Body::None,
      )
      .await;
    Ok(
      json_or_fail(P, Ok(r?)).await?["token"]
        .as_str()
        .unwrap_or("")
        .to_string(),
    )
  }

  async fn get_record(&self, s: &Session, rkey: &str) -> Option<Value> {
    let r = self
      .call(
        s,
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", s.pds),
        &[
          ("repo", s.did.as_str()),
          ("collection", "app.bsky.feed.post"),
          ("rkey", rkey),
        ],
        Body::None,
      )
      .await
      .ok()?;
    if !r.status().is_success() {
      return None;
    }
    r.json::<Value>()
      .await
      .ok()
      .filter(|v| v.get("cid").is_some())
  }

  /// Creates the post at `rkey`, or returns the one already there (D11).
  async fn put_post(
    &self,
    s: &Session,
    rkey: &str,
    record: Value,
  ) -> Result<(String, String), Failure> {
    if let Some(v) = self.get_record(s, rkey).await {
      return Ok((
        v["uri"].as_str().unwrap_or("").into(),
        v["cid"].as_str().unwrap_or("").into(),
      ));
    }
    let r = self
      .call(
        s,
        Method::POST,
        &format!("{}/xrpc/com.atproto.repo.createRecord", s.pds),
        &[],
        Body::Json(json!({ "repo": s.did, "collection": "app.bsky.feed.post", "rkey": rkey, "record": record })),
      )
      .await;
    let v = json_or_fail(P, Ok(r?)).await?;
    Ok((
      v["uri"].as_str().unwrap_or("").into(),
      v["cid"].as_str().unwrap_or("").into(),
    ))
  }

  async fn upload_image(&self, s: &Session, path: &std::path::Path) -> Result<Value, Failure> {
    let body = tokio::fs::read(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the image.").with_verbatim(e))?;
    if body.len() as u64 > MAX_IMAGE {
      return Err(Failure::new(
        "itemTooLarge",
        "Bluesky takes images up to 1 MB.",
      ));
    }
    let r = self
      .call(
        s,
        Method::POST,
        &format!("{}/xrpc/com.atproto.repo.uploadBlob", s.pds),
        &[],
        Body::Bytes(body, mime_of(path)),
      )
      .await;
    Ok(json_or_fail(P, Ok(r?)).await?["blob"].clone())
  }

  /// Video goes through Bluesky's video service, then the post embeds the processed blob.
  async fn upload_video(&self, s: &Session, path: &std::path::Path) -> Result<Value, Failure> {
    let host = s
      .pds
      .split("://")
      .nth(1)
      .unwrap_or("")
      .split('/')
      .next()
      .unwrap_or("")
      .to_string();
    let token = self
      .service_token(s, &format!("did:web:{host}"), "com.atproto.repo.uploadBlob")
      .await?;
    let (body, _) = file_body(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with_verbatim(e))?;
    let name = format!("{}.mp4", uuid::Uuid::new_v4().simple());
    let r = self
      .http
      .post(format!("{}/xrpc/app.bsky.video.uploadVideo", self.video))
      .query(&[("did", s.did.as_str()), ("name", name.as_str())])
      .bearer_auth(&token)
      .header("content-type", mime_of(path))
      .body(body)
      .send()
      .await
      .map_err(|e| net(P, e))?;
    let status = r.status();
    let text = r.text().await.map_err(|e| net(P, e))?;
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let job = v.get("jobStatus").unwrap_or(&v);
    // 409: this exact file was uploaded before; its job id comes back and is reused.
    if !status.is_success() && status.as_u16() != 409 {
      return Err(status_failure(P, status, &text));
    }
    if let Some(b) = job.get("blob").filter(|b| !b.is_null()) {
      return Ok(b.clone());
    }
    let job_id = job
      .get("jobId")
      .and_then(Value::as_str)
      .ok_or_else(|| status_failure(P, status, &text))?
      .to_string();
    let status_token = match &s.auth {
      Auth::Bearer(jwt) => jwt.clone(),
      Auth::OAuth(_) => {
        let video_host = self
          .video
          .split("://")
          .nth(1)
          .unwrap_or("video.bsky.app")
          .to_string();
        self
          .service_token(
            s,
            &format!("did:web:{video_host}"),
            "app.bsky.video.getJobStatus",
          )
          .await?
      }
    };
    for _ in 0..450 {
      let r = self
        .http
        .get(format!("{}/xrpc/app.bsky.video.getJobStatus", self.video))
        .query(&[("jobId", job_id.as_str())])
        .bearer_auth(&status_token)
        .send()
        .await;
      let v = json_or_fail(P, r).await?;
      let j = v.get("jobStatus").unwrap_or(&v);
      match j.get("state").and_then(Value::as_str) {
        Some("JOB_STATE_COMPLETED") => {
          return j.get("blob").cloned().ok_or_else(|| {
            Failure::new(
              "uploadRejected",
              "Bluesky finished the video without a file.",
            )
          });
        }
        Some("JOB_STATE_FAILED") => {
          let words = j
            .get("error")
            .or(j.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
          return Err(Failure {
            code: "uploadRejected",
            message: "Bluesky couldn't process the video.".into(),
            verbatim: Some(words),
          });
        }
        _ => tokio::time::sleep(self.poll).await,
      }
    }
    Err(Failure::new(
      "progressStalled",
      "Bluesky is still processing the video after 15 minutes.",
    ))
  }
}

async fn login(
  http: &reqwest::Client,
  service: &str,
  identifier: &str,
  password: &str,
) -> Result<Session, Failure> {
  let r = http
    .post(format!("{service}/xrpc/com.atproto.server.createSession"))
    .json(&json!({ "identifier": identifier, "password": password }))
    .send()
    .await;
  let v = json_or_fail(P, r).await.map_err(|f| {
    if f.code == "tokenExpired" || f.code == "uploadRejected" {
      Failure {
        code: "signInRequired",
        message: "Bluesky didn't accept that handle and app password.".into(),
        verbatim: f.verbatim,
      }
    } else {
      f
    }
  })?;
  let pds = v
    .pointer("/didDoc/service")
    .and_then(Value::as_array)
    .and_then(|a| {
      a.iter().find(|s| {
        s["id"]
          .as_str()
          .is_some_and(|i| i.ends_with("#atproto_pds"))
      })
    })
    .and_then(|s| s["serviceEndpoint"].as_str())
    .unwrap_or(service)
    .trim_end_matches('/')
    .to_string();
  Ok(Session {
    auth: Auth::Bearer(v["accessJwt"].as_str().unwrap_or("").into()),
    did: v["did"].as_str().unwrap_or("").into(),
    handle: v["handle"].as_str().unwrap_or(identifier).into(),
    pds,
  })
}

/// Checks the app password and returns `(did, handle)` for the connection.
pub async fn connect(
  http: &reqwest::Client,
  service: &str,
  identifier: &str,
  password: &str,
) -> Result<(String, String), Failure> {
  let s = login(
    http,
    service,
    identifier.trim().trim_start_matches('@'),
    password.trim(),
  )
  .await?;
  Ok((s.did, s.handle))
}

const TID_CHARS: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";

/// A record key (TID) fixed by the original post time and the idempotency key, so the same
/// cell always lands on the same key. Without an original time the key alone picks a moment in
/// 2023, so a retry still finds the first post (D11).
pub fn tid_for(created_at: Option<&str>, key: &str, index: u64) -> String {
  let hash = u64::from_be_bytes(
    Sha256::digest(key.as_bytes())[..8]
      .try_into()
      .unwrap_or([0; 8]),
  );
  const Y2023_MICROS: u64 = 1_672_531_200_000_000;
  const YEAR_MICROS: u64 = 365 * 24 * 3600 * 1_000_000;
  let micros = created_at
    .and_then(|c| {
      time::OffsetDateTime::parse(c, &time::format_description::well_known::Rfc3339).ok()
    })
    .map(|d| (d.unix_timestamp_nanos() / 1000) as u64)
    .unwrap_or(Y2023_MICROS + (hash >> 10) % YEAR_MICROS)
    + index;
  let clock = hash & 0x3ff;
  let v = ((micros & ((1 << 53) - 1)) << 10) | clock;
  (0..13)
    .rev()
    .map(|i| TID_CHARS[((v >> (i * 5)) & 31) as usize] as char)
    .collect()
}

/// Link and hashtag facets with UTF-8 byte offsets.
pub fn facets(text: &str) -> Vec<Value> {
  let mut out = Vec::new();
  let mut i = 0;
  for tok in text.split_inclusive(char::is_whitespace) {
    let word = tok.trim_end();
    let start = i;
    i += tok.len();
    let trimmed = word.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '\'']);
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
      out.push(json!({ "index": { "byteStart": start, "byteEnd": start + trimmed.len() }, "features": [{ "$type": "app.bsky.richtext.facet#link", "uri": trimmed }] }));
    } else if let Some(tag) = trimmed.strip_prefix('#') {
      if !tag.is_empty() && !tag.chars().all(|c| c.is_ascii_digit()) && !tag.contains('#') {
        out.push(json!({ "index": { "byteStart": start, "byteEnd": start + trimmed.len() }, "features": [{ "$type": "app.bsky.richtext.facet#tag", "tag": tag }] }));
      }
    }
  }
  out
}

fn record(
  text: &str,
  created: &str,
  embed: Option<Value>,
  reply: Option<Value>,
  lang: Option<&str>,
) -> Value {
  let mut r = json!({ "$type": "app.bsky.feed.post", "text": text, "createdAt": created });
  let f = facets(text);
  if !f.is_empty() {
    r["facets"] = Value::Array(f);
  }
  if let Some(e) = embed {
    r["embed"] = e;
  }
  if let Some(rp) = reply {
    r["reply"] = rp;
  }
  if let Some(l) = lang {
    r["langs"] = json!([l]);
  }
  r
}

impl Uploader for Bluesky {
  fn safe_to_retry(&self) -> bool {
    true
  }

  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let s = self.session().await?;
      let created = created_at(u.post, u.item)
        .and_then(|c| {
          time::OffsetDateTime::parse(&c, &time::format_description::well_known::Rfc3339).ok()
        })
        .and_then(|d| {
          d.format(&time::format_description::well_known::Rfc3339)
            .ok()
        })
        .unwrap_or_else(|| crate::server::iso(std::time::SystemTime::now()));
      let original = created_at(u.post, u.item);
      let rkey = tid_for(original.as_deref(), u.idempotency_key, 0);
      let text = body_text(u.post, u.item);
      let lang = u.item.get("language").and_then(Value::as_str);
      // the root post may already exist from an earlier attempt: then no media is uploaded again
      let embed = if self.get_record(&s, &rkey).await.is_some() {
        None
      } else if let Some(v) = u.media.iter().find(|p| is_video(p)) {
        let blob = self.upload_video(&s, v).await?;
        let mut e = json!({ "$type": "app.bsky.embed.video", "video": blob });
        if let (Some(w), Some(h)) = (
          u.item.get("width").and_then(Value::as_u64),
          u.item.get("height").and_then(Value::as_u64),
        ) {
          e["aspectRatio"] = json!({ "width": w, "height": h });
        }
        Some(e)
      } else {
        let alts = alt_texts(u.post);
        let mut images = Vec::new();
        for (k, p) in u.media.iter().filter(|p| is_image(p)).take(4).enumerate() {
          let blob = self.upload_image(&s, p).await?;
          images.push(json!({ "image": blob, "alt": alts.get(k).cloned().unwrap_or_default() }));
        }
        (!images.is_empty()).then(|| json!({ "$type": "app.bsky.embed.images", "images": images }))
      };
      let (uri, cid) = self
        .put_post(&s, &rkey, record(&text, &created, embed, None, lang))
        .await?;
      // F4 overflow thread: replies get their own fixed keys too.
      let (mut parent_uri, mut parent_cid) = (uri.clone(), cid.clone());
      for (n, t) in thread(u.post).iter().enumerate() {
        let k = tid_for(original.as_deref(), u.idempotency_key, n as u64 + 1);
        let reply = json!({ "root": { "uri": uri, "cid": cid }, "parent": { "uri": parent_uri, "cid": parent_cid } });
        let (pu, pc) = self
          .put_post(&s, &k, record(t, &created, None, Some(reply), lang))
          .await?;
        parent_uri = pu;
        parent_cid = pc;
      }
      let verified = self.get_record(&s, &rkey).await.is_some();
      Ok(Published {
        note: None,
        dest_item_id: uri,
        dest_url: Some(format!("https://bsky.app/profile/{}/post/{rkey}", s.handle)),
        verified,
      })
    })
  }
}

trait WithV {
  fn with_verbatim(self, e: impl std::fmt::Display) -> Self;
}
impl WithV for Failure {
  fn with_verbatim(mut self, e: impl std::fmt::Display) -> Self {
    self.verbatim = Some(e.to_string());
    self
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Query, State};
  use axum::routing::{get, post};
  use axum::{Json, Router};
  use std::collections::HashMap;
  use std::path::PathBuf;
  use std::sync::{Arc, Mutex};

  #[derive(Default)]
  struct Pds {
    records: Mutex<HashMap<String, Value>>,
    creates: Mutex<u32>,
    videos: Mutex<u32>,
  }

  fn app(pds: Arc<Pds>) -> Router {
    Router::new()
      .route(
        "/xrpc/com.atproto.server.createSession",
        post(|Json(b): Json<Value>| async move {
          if b["password"] == "app-pass-1234" {
            (axum::http::StatusCode::OK, Json(json!({ "accessJwt": "jwt", "did": "did:plc:mara", "handle": "mara.test" })))
          } else {
            (axum::http::StatusCode::UNAUTHORIZED, Json(json!({ "error": "AuthenticationRequired", "message": "Invalid identifier or password" })))
          }
        }),
      )
      .route("/xrpc/com.atproto.server.getServiceAuth", get(|| async { Json(json!({ "token": "svc" })) }))
      .route(
        "/xrpc/app.bsky.video.uploadVideo",
        // Reads the whole upload before answering, like the real service; answering early made
        // the client's send fail on fast runners.
        post(|State(p): State<Arc<Pds>>, _body: axum::body::Bytes| async move {
          *p.videos.lock().unwrap() += 1;
          Json(json!({ "jobStatus": { "jobId": "job1", "state": "JOB_STATE_CREATED" } }))
        }),
      )
      .route("/xrpc/app.bsky.video.getJobStatus", get(|| async { Json(json!({ "jobStatus": { "jobId": "job1", "state": "JOB_STATE_COMPLETED", "blob": { "$type": "blob", "ref": { "$link": "bafyvid" }, "mimeType": "video/mp4", "size": 5 } } })) }))
      .route(
        "/xrpc/com.atproto.repo.getRecord",
        get(|State(p): State<Arc<Pds>>, Query(q): Query<HashMap<String, String>>| async move {
          match p.records.lock().unwrap().get(&q["rkey"]) {
            Some(r) => (axum::http::StatusCode::OK, Json(json!({ "uri": format!("at://did:plc:mara/app.bsky.feed.post/{}", q["rkey"]), "cid": "cid1", "value": r }))),
            None => (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": "RecordNotFound" }))),
          }
        }),
      )
      .route(
        "/xrpc/com.atproto.repo.createRecord",
        post(|State(p): State<Arc<Pds>>, Json(b): Json<Value>| async move {
          *p.creates.lock().unwrap() += 1;
          let k = b["rkey"].as_str().unwrap().to_string();
          p.records.lock().unwrap().insert(k.clone(), b["record"].clone());
          Json(json!({ "uri": format!("at://did:plc:mara/app.bsky.feed.post/{k}"), "cid": "cid1" }))
        }),
      )
      .with_state(pds)
  }

  async fn fixture() -> (Bluesky, Arc<Pds>, tempfile::TempDir, PathBuf) {
    let pds = Arc::new(Pds::default());
    let base = serve(app(pds.clone())).await;
    let mut b = Bluesky::new(
      reqwest::Client::new(),
      &json!({ "service": base, "identifier": "did:plc:mara", "appPassword": "app-pass-1234" }),
      &Endpoints {
        bsky_video: base.clone(),
        ..Endpoints::default()
      },
      Arc::new(crate::connections::Store::open(
        std::path::PathBuf::from("/nonexistent/c.json"),
        Box::new(crate::connections::MemorySecrets::default()),
      )),
      "bluesky-1",
    )
    .unwrap();
    b.poll = Duration::from_millis(5);
    let dir = tempfile::tempdir().unwrap();
    let media = dir.path().join("media.mp4");
    std::fs::write(&media, b"video").unwrap();
    (b, pds, dir, media)
  }

  #[tokio::test]
  async fn bluesky_posts_video_with_the_original_date_and_never_twice() {
    let (b, pds, _d, media) = fixture().await;
    let item = json!({ "id": "a", "title": "Hi", "publishedAt": "2021-06-01T12:00:00-04:00", "width": 1080, "height": 1920 });
    let post =
      json!({ "fields": { "body": "Hi #bunny https://example.org/x." }, "thread": ["part 2"] });
    let up = || Upload {
      item: &item,
      post: Some(&post),
      media: std::slice::from_ref(&media),
      idempotency_key: "hop:a:bluesky",
      options: &Value::Null,
    };
    let p = b.publish(up()).await.unwrap();
    assert!(p.verified);
    assert!(p
      .dest_url
      .unwrap()
      .starts_with("https://bsky.app/profile/mara.test/post/"));
    let recs = pds.records.lock().unwrap().clone();
    assert_eq!(recs.len(), 2, "root + one thread reply");
    let root = recs.values().find(|r| r.get("reply").is_none()).unwrap();
    assert_eq!(root["createdAt"], "2021-06-01T12:00:00-04:00");
    assert_eq!(root["embed"]["$type"], "app.bsky.embed.video");
    assert_eq!(root["embed"]["aspectRatio"]["height"], 1920);
    let f = root["facets"].as_array().unwrap();
    assert_eq!(f[0]["features"][0]["tag"], "bunny");
    assert_eq!(f[1]["features"][0]["uri"], "https://example.org/x");
    // retry (D11): same keys → the existing posts are found, nothing new is created or uploaded
    b.publish(up()).await.unwrap();
    assert_eq!(*pds.creates.lock().unwrap(), 2);
    assert_eq!(*pds.videos.lock().unwrap(), 1);
  }

  #[tokio::test]
  async fn bluesky_wrong_app_password_says_so() {
    let (_b, _pds, _d, _m) = fixture().await;
    let pds = Arc::new(Pds::default());
    let base = serve(app(pds)).await;
    let e = connect(&reqwest::Client::new(), &base, "@mara.test", "nope")
      .await
      .err()
      .unwrap();
    assert_eq!(e.code, "signInRequired");
    assert!(e
      .verbatim
      .unwrap()
      .contains("Invalid identifier or password"));
  }

  #[test]
  fn bluesky_record_keys_are_stable_tids() {
    let a = tid_for(Some("2021-06-01T12:00:00Z"), "hop:a:bluesky", 0);
    assert_eq!(a.len(), 13);
    assert_eq!(a, tid_for(Some("2021-06-01T12:00:00Z"), "hop:a:bluesky", 0));
    assert_ne!(a, tid_for(Some("2021-06-01T12:00:00Z"), "hop:b:bluesky", 0));
    // no original date: still the same key on every retry, a different one per item (D11)
    assert_eq!(tid_for(None, "k-a", 0), tid_for(None, "k-a", 0));
    assert_ne!(tid_for(None, "k-a", 0), tid_for(None, "k-b", 0));
    assert!(matches!(tid_for(None, "k-a", 0).as_bytes()[0], b'2'..=b'7' | b'a'..=b'j'));
    assert!(
      tid_for(Some("2021-06-01T12:00:00Z"), "k", 1) > tid_for(Some("2021-06-01T12:00:00Z"), "k", 0)
    );
    assert!(a.chars().all(|c| TID_CHARS.contains(&(c as u8))));
    assert!(
      !a.starts_with(|c: char| "kmnpqrstuvwxyz".contains(c)),
      "top bit is zero"
    );
  }

  #[test]
  fn bluesky_facets_use_utf8_byte_offsets() {
    let f = facets("café #tag https://a.example");
    assert_eq!(f[0]["index"]["byteStart"], 6);
    assert_eq!(f[0]["index"]["byteEnd"], 10);
    assert_eq!(f[1]["index"]["byteStart"], 11);
  }
}

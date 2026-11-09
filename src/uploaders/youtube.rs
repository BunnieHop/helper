//! YouTube: the creator signs in on Google's own page (Worker relay `youtube`, PKCE, D-045);
//! only the refresh token is kept, in the keychain. Videos go up through the resumable upload API
//! in 8 MB chunks. YouTube can't backdate, so the original date becomes `recordingDate`.
//!
//! D11: before uploading, the channel's latest uploads are checked for a video with the same
//! title (and, when known, the same recording day), and that video is returned instead.

use super::{
  body_text, created_at, mime_of, net, resumable_put, status_failure, tags, title_text, Endpoints,
  RelayToken,
};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader};
use serde_json::{json, Value};
use std::path::Path;

const P: &str = "YouTube";

pub struct YouTube {
  http: reqwest::Client,
  ep: Endpoints,
  uploads: Option<String>,
  token: RelayToken,
  /// Wait between read-backs while YouTube is still processing a new upload.
  recheck: std::time::Duration,
}

/// Read-backs after an upload before reporting "still processing" (6 × 10 s).
const RECHECKS: u32 = 6;

/// YouTube's own reason for a refusal ("quotaExceeded", "uploadLimitExceeded", …).
fn reason(body: &str) -> String {
  serde_json::from_str::<Value>(body)
    .ok()
    .and_then(|v| {
      v.pointer("/error/errors/0/reason")
        .and_then(Value::as_str)
        .map(String::from)
    })
    .unwrap_or_default()
}

fn failure(status: reqwest::StatusCode, body: &str) -> Failure {
  let mut f = status_failure(P, status, body);
  match reason(body).as_str() {
    "quotaExceeded" | "dailyLimitExceeded" => {
      f.code = "quotaExceeded";
      f.message = "YouTube's daily upload allowance for BunnieHop is used up. The rest waits until midnight Pacific.".into();
    }
    "uploadLimitExceeded" => {
      f.code = "quotaExceeded";
      f.message = "YouTube says this channel has uploaded as much as it can today.".into();
    }
    "youtubeSignupRequired" => {
      f.code = "signInRequired";
      f.message = "This Google account has no YouTube channel yet. Create one on youtube.com, then connect again.".into();
    }
    _ => {}
  }
  f
}

async fn read_json(r: reqwest::Response) -> Result<Value, Failure> {
  let status = r.status();
  let text = r.text().await.map_err(|e| net(P, e))?;
  if !status.is_success() {
    return Err(failure(status, &text));
  }
  serde_json::from_str(&text)
    .map_err(|_| status_failure(P, reqwest::StatusCode::BAD_GATEWAY, &text))
}

/// After Google's sign-in page: finds the channel. Returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let (Some(access), Some(refresh)) = (
    tokens["access_token"].as_str(),
    tokens["refresh_token"].as_str().filter(|t| !t.is_empty()),
  ) else {
    return Err(Failure::new(
      "signInRequired",
      "Google didn't finish the sign-in. Try again and allow uploads.",
    ));
  };
  let scope = tokens["scope"].as_str().unwrap_or("");
  if !scope.is_empty() && !scope.contains("youtube.upload") {
    return Err(Failure::new(
      "signInRequired",
      "Google signed in without upload permission. Try again and tick \"Manage your YouTube videos\".",
    ));
  }
  let r = http
    .get(format!("{}/youtube/v3/channels", ep.google_api))
    .query(&[("part", "snippet,contentDetails"), ("mine", "true")])
    .bearer_auth(access)
    .send()
    .await
    .map_err(|e| net(P, e))?;
  let v = read_json(r).await?;
  let Some(ch) = v["items"].get(0) else {
    return Err(Failure::new(
      "signInRequired",
      "This Google account has no YouTube channel yet. Create one on youtube.com, then connect again.",
    ));
  };
  let label = ch
    .pointer("/snippet/title")
    .and_then(Value::as_str)
    .unwrap_or("YouTube channel")
    .to_string();
  Ok((
    label,
    json!({
      "refreshToken": refresh,
      "channelId": ch["id"],
      "uploads": ch.pointer("/contentDetails/relatedPlaylists/uploads"),
    }),
  ))
}

impl YouTube {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints) -> Option<Self> {
    Some(Self {
      token: RelayToken::new(
        http.clone(),
        ep,
        "youtube",
        secret["refreshToken"].as_str()?,
        P,
      ),
      http,
      ep: ep.clone(),
      recheck: std::time::Duration::from_secs(10),
      uploads: secret["uploads"].as_str().map(String::from),
    })
  }

  fn api(&self, path: &str) -> String {
    format!("{}/youtube/v3/{path}", self.ep.google_api)
  }

  /// A video this hop already uploaded: same title among the latest 50 uploads, same day.
  async fn existing(&self, title: &str, original: Option<&str>) -> Result<Option<String>, Failure> {
    let Some(pl) = &self.uploads else {
      return Ok(None);
    };
    let r = self
      .token
      .send(|| {
        self.http.get(self.api("playlistItems")).query(&[
          ("part", "snippet"),
          ("playlistId", pl),
          ("maxResults", "50"),
        ])
      })
      .await?;
    // a brand-new channel has no uploads playlist yet
    if r.status() == reqwest::StatusCode::NOT_FOUND {
      return Ok(None);
    }
    let v = read_json(r).await?;
    let ids: Vec<String> = v["items"]
      .as_array()
      .into_iter()
      .flatten()
      .filter(|i| i.pointer("/snippet/title").and_then(Value::as_str) == Some(title))
      .filter_map(|i| {
        i.pointer("/snippet/resourceId/videoId")
          .and_then(Value::as_str)
          .map(String::from)
      })
      .collect();
    if ids.is_empty() {
      return Ok(None);
    }
    let Some(day) = original.and_then(|o| o.get(..10)) else {
      return Ok(ids.into_iter().next());
    };
    let joined = ids.join(",");
    let r = self
      .token
      .send(|| {
        self
          .http
          .get(self.api("videos"))
          .query(&[("part", "recordingDetails"), ("id", joined.as_str())])
      })
      .await?;
    let v = read_json(r).await?;
    Ok(
      v["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|x| {
          x.pointer("/recordingDetails/recordingDate")
            .and_then(Value::as_str)
            .and_then(|d| d.get(..10))
            == Some(day)
        })
        .and_then(|x| x["id"].as_str().map(String::from)),
    )
  }

  async fn upload(&self, path: &Path, meta: &Value) -> Result<Value, Failure> {
    let unreadable = |e: std::io::Error| Failure {
      code: "vaultUnavailable",
      message: "Couldn't read the video.".into(),
      verbatim: Some(e.to_string()),
    };
    let len = tokio::fs::metadata(path).await.map_err(unreadable)?.len();
    let mime = mime_of(path);
    let r = self
      .token
      .send(|| {
        self
          .http
          .post(format!("{}/upload/youtube/v3/videos", self.ep.google_api))
          .query(&[
            ("uploadType", "resumable"),
            ("part", "snippet,status,recordingDetails"),
            ("notifySubscribers", "false"),
          ])
          .header("X-Upload-Content-Length", len.to_string())
          .header("X-Upload-Content-Type", mime)
          .json(meta)
      })
      .await?;
    if !r.status().is_success() {
      let s = r.status();
      return Err(failure(s, &r.text().await.unwrap_or_default()));
    }
    let url = r
      .headers()
      .get("location")
      .and_then(|v| v.to_str().ok())
      .filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1:"))
      .ok_or_else(|| Failure::new("uploadRejected", "YouTube didn't start the upload."))?
      .to_string();
    // the session URL itself authorizes the upload; no token needed
    let r = resumable_put(&self.http, &url, path, P).await?;
    if r.status().is_success() {
      read_json(r).await
    } else {
      let s = r.status();
      Err(failure(s, &r.text().await.unwrap_or_default()))
    }
  }
}

/// YouTube tags: no angle brackets, 500 characters in total.
fn clean_tags(t: Vec<String>) -> Vec<String> {
  let mut out = Vec::new();
  let mut total = 0;
  for s in t {
    let s: String = s
      .trim_start_matches('#')
      .chars()
      .filter(|c| *c != '<' && *c != '>')
      .collect();
    let cost = s.chars().count() + if s.contains(' ') { 2 } else { 0 } + 1;
    if s.is_empty() || total + cost > 500 {
      continue;
    }
    total += cost;
    out.push(s);
  }
  out
}

impl Uploader for YouTube {
  /// No: the uploads playlist can lag behind a brand-new upload, so a check after a crash can
  /// miss the first copy and upload the whole video twice. A cut-off upload comes back
  /// `publishedUnverified` for the creator to check (D11).
  fn safe_to_retry(&self) -> bool {
    false
  }

  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let media = u
        .media
        .iter()
        .find(|p| super::is_video(p))
        .ok_or_else(|| Failure::new("notSupported", "YouTube takes videos only."))?;
      let title: String = title_text(u.post, u.item)
        .replace('<', "‹")
        .replace('>', "›")
        .chars()
        .take(100)
        .collect();
      let title = if title.trim().is_empty() {
        "Untitled".to_string()
      } else {
        title
      };
      let original = created_at(u.post, u.item);
      let kids = u
        .post
        .and_then(|p| p.pointer("/fields/choices/madeForKids"))
        .and_then(Value::as_bool)
        .ok_or_else(|| {
          Failure::new(
            "requiredChoiceMissing",
            "YouTube needs an answer: is this made for kids?",
          )
        })?;
      if let Some(id) = self.existing(&title, original.as_deref()).await? {
        // same title (and day, when known) already on the channel: never uploaded twice, but a
        // title match can't prove it is this item, so the creator checks
        return Ok(Published {
          note: Some(
            "A video with this title is already on your channel, so BunnieHop didn't upload it again. Check it's this one."
              .into(),
          ),
          dest_url: Some(format!("https://www.youtube.com/watch?v={id}")),
          verified: false,
          dest_item_id: id,
        });
      }
      let id = {
        let description: String = body_text(u.post, u.item)
          .replace('<', "‹")
          .replace('>', "›")
          .chars()
          .take(5000)
          .collect();
        let mut meta = json!({
          "snippet": {
            "title": title,
            "description": description,
            "tags": clean_tags(tags(u.post, u.item)),
          },
          "status": {
            "privacyStatus": "public",
            "selfDeclaredMadeForKids": kids,
            "embeddable": true,
          },
        });
        if let Some(o) = &original {
          meta["recordingDetails"] = json!({ "recordingDate": o });
        }
        if let Some(l) = u.item.get("language").and_then(Value::as_str) {
          meta["snippet"]["defaultLanguage"] = json!(l);
          meta["snippet"]["defaultAudioLanguage"] = json!(l);
        }
        let v = self.upload(media, &meta).await?;
        v["id"].as_str().unwrap_or("").to_string()
      };
      if id.is_empty() {
        return Err(Failure::new(
          "uploadRejected",
          "YouTube didn't say which video it made.",
        ));
      }
      // D12: published only when YouTube says the video is public and processed
      let mut tries = 0;
      let (note, verified) = loop {
        tries += 1;
        let check = self
          .token
          .send(|| {
            self
              .http
              .get(self.api("videos"))
              .query(&[("part", "status"), ("id", id.as_str())])
          })
          .await;
        let status = match check {
          Ok(r) => read_json(r).await.ok(),
          Err(_) => None,
        };
        let st = status.as_ref().and_then(|s| s.pointer("/items/0/status"));
        let get = |k: &str| st.and_then(|s| s.get(k)).and_then(Value::as_str);
        match (get("uploadStatus"), get("privacyStatus")) {
          (Some("rejected" | "failed" | "deleted"), _) => {
            let why = get("rejectionReason")
              .or(get("failureReason"))
              .unwrap_or("no reason given");
            return Err(Failure {
              code: "uploadRejected",
              message: format!("YouTube refused the video ({why})."),
              verbatim: st.map(Value::to_string),
            });
          }
          (_, Some("private")) => break (Some("YouTube has this video set to private."), false),
          (Some("processed"), Some(_)) => break (None, true),
          (Some(_), Some(_)) if tries < RECHECKS => tokio::time::sleep(self.recheck).await,
          (Some(_), Some(_)) => {
            break (
              Some("YouTube is still processing this video. Check it on YouTube later."),
              false,
            )
          }
          _ => {
            break (
              Some("BunnieHop couldn't read the video back from YouTube."),
              false,
            )
          }
        }
      };
      Ok(Published {
        note: note.map(String::from),
        dest_url: Some(format!("https://www.youtube.com/watch?v={id}")),
        verified,
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
  use axum::http::{HeaderMap, StatusCode};
  use axum::routing::{get, post, put};
  use axum::{Json, Router};
  use std::collections::HashMap;
  use std::sync::{Arc, Mutex};

  #[derive(Default)]
  struct Yt {
    base: Mutex<String>,
    bytes: Mutex<Vec<u8>>,
    meta: Mutex<Option<Value>>,
    videos: Mutex<Vec<Value>>,
    refreshes: Mutex<u32>,
    token: Mutex<String>,
    quota: Mutex<bool>,
    /// The `status` YouTube reports for the next upload (default: public and processed).
    next_status: Mutex<Option<Value>>,
  }
  type S = Arc<Yt>;

  fn ok(s: &S, h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok())
      == Some(&format!("Bearer {}", s.token.lock().unwrap()))
  }

  fn app(s: S) -> Router {
    Router::new()
      .route(
        "/v1/oauth/youtube/token",
        post(|State(s): State<S>, Json(b): Json<Value>| async move {
          if b["refresh_token"] != "ref-1" {
            // what the Worker passes back from Google for a revoked grant
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
          }
          let mut n = s.refreshes.lock().unwrap();
          *n += 1;
          let t = format!("acc-{n}");
          *s.token.lock().unwrap() = t.clone();
          (StatusCode::OK, Json(json!({ "access_token": t, "expires_in": 3599 })))
        }),
      )
      .route(
        "/youtube/v3/channels",
        get(|State(s): State<S>, h: HeaderMap| async move {
          assert!(ok(&s, &h));
          Json(json!({ "items": [{ "id": "UC1", "snippet": { "title": "Mara Makes" }, "contentDetails": { "relatedPlaylists": { "uploads": "UU1" } } }] }))
        }),
      )
      .route(
        "/youtube/v3/playlistItems",
        get(|State(s): State<S>, h: HeaderMap| async move {
          if !ok(&s, &h) {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": { "code": 401 } })));
          }
          let items: Vec<Value> = s.videos.lock().unwrap().iter().map(|v| json!({ "snippet": { "title": v["snippet"]["title"], "resourceId": { "videoId": v["id"] } } })).collect();
          (StatusCode::OK, Json(json!({ "items": items })))
        }),
      )
      .route(
        "/youtube/v3/videos",
        get(|State(s): State<S>, Query(q): Query<HashMap<String, String>>| async move {
          let ids: Vec<&str> = q["id"].split(',').collect();
          let items: Vec<Value> = s.videos.lock().unwrap().iter().filter(|v| ids.contains(&v["id"].as_str().unwrap())).cloned().collect();
          Json(json!({ "items": items }))
        }),
      )
      .route(
        "/upload/youtube/v3/videos",
        post(|State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>, Json(meta): Json<Value>| async move {
          assert!(ok(&s, &h));
          assert_eq!(q["uploadType"], "resumable");
          if *s.quota.lock().unwrap() {
            return (StatusCode::FORBIDDEN, HeaderMap::new(), r#"{"error":{"code":403,"errors":[{"reason":"quotaExceeded"}]}}"#.to_string());
          }
          *s.meta.lock().unwrap() = Some(meta);
          let mut hm = HeaderMap::new();
          hm.insert("location", format!("{}/session/1", s.base.lock().unwrap()).parse().unwrap());
          (StatusCode::OK, hm, String::new())
        }),
      )
      .route(
        "/session/1",
        put(|State(s): State<S>, h: HeaderMap, body: axum::body::Bytes| async move {
          let range = h["content-range"].to_str().unwrap().to_string();
          let total: usize = range.rsplit('/').next().unwrap().parse().unwrap();
          let mut b = s.bytes.lock().unwrap();
          b.extend_from_slice(&body);
          if b.len() < total {
            return (StatusCode::PERMANENT_REDIRECT, Json(Value::Null));
          }
          let meta = s.meta.lock().unwrap().clone().unwrap();
          let status = s.next_status.lock().unwrap().clone().unwrap_or(json!({ "privacyStatus": "public", "uploadStatus": "processed" }));
          let n = s.videos.lock().unwrap().len() + 1;
          let v = json!({ "id": format!("vid{n}"), "snippet": meta["snippet"], "recordingDetails": meta["recordingDetails"], "status": status });
          s.videos.lock().unwrap().push(v.clone());
          (StatusCode::OK, Json(v))
        }),
      )
      .layer(axum::extract::DefaultBodyLimit::disable())
      .with_state(s)
  }

  fn post_for(kids: Option<bool>) -> Value {
    let mut p = json!({ "fields": { "title": "My <best> video", "body": "Hello", "tags": ["#cats", "a b"] } });
    if let Some(k) = kids {
      p["fields"]["choices"] = json!({ "madeForKids": k });
    }
    p
  }

  #[tokio::test]
  async fn youtube_uploads_in_chunks_keeps_the_date_and_never_twice() {
    let s: S = Arc::default();
    let base = serve(app(s.clone())).await;
    *s.base.lock().unwrap() = base.clone();
    let ep = Endpoints {
      worker: base.clone(),
      google_api: base.clone(),
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    *s.token.lock().unwrap() = "first".into();
    let (label, secret) = connect(
      &http,
      &ep,
      &json!({ "access_token": "first", "refresh_token": "ref-1", "scope": "https://www.googleapis.com/auth/youtube.upload" }),
    )
    .await
    .unwrap();
    assert_eq!(label, "Mara Makes");
    assert_eq!(secret["uploads"], "UU1");
    let dir = tempfile::tempdir().unwrap();
    let video = dir.path().join("clip.mp4");
    let data: Vec<u8> = (0..(8 * 1024 * 1024 + 1000))
      .map(|i| (i % 251) as u8)
      .collect();
    std::fs::write(&video, &data).unwrap();
    let yt = YouTube::new(http, &secret, &ep).unwrap();
    let item = json!({ "publishedAt": "2019-04-02T10:00:00Z" });
    let media = [video];
    let opts = json!({});
    let up = |post: &'static Value| Upload {
      item: &item,
      post: Some(post),
      media: &media,
      idempotency_key: "k",
      options: &opts,
    };
    let no_answer: &'static Value = Box::leak(Box::new(post_for(None)));
    let e = yt.publish(up(no_answer)).await.unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    let p: &'static Value = Box::leak(Box::new(post_for(Some(false))));
    let r = yt.publish(up(p)).await.unwrap();
    assert_eq!(r.dest_item_id, "vid1");
    assert_eq!(
      r.dest_url.as_deref(),
      Some("https://www.youtube.com/watch?v=vid1")
    );
    assert!(r.verified);
    assert_eq!(*s.bytes.lock().unwrap(), data, "two chunks, byte for byte");
    let meta = s.meta.lock().unwrap().clone().unwrap();
    assert_eq!(meta["snippet"]["title"], "My ‹best› video");
    assert_eq!(meta["snippet"]["tags"], json!(["cats", "a b"]));
    assert_eq!(meta["status"]["selfDeclaredMadeForKids"], false);
    assert_eq!(
      meta["recordingDetails"]["recordingDate"],
      "2019-04-02T10:00:00Z"
    );
    assert_eq!(
      *s.refreshes.lock().unwrap(),
      1,
      "one token refresh covers the whole run"
    );
    // the same title again finds the video instead of uploading, but can't prove it's this item
    let again = yt.publish(up(p)).await.unwrap();
    assert_eq!(again.dest_item_id, "vid1");
    assert!(!again.verified);
    assert!(again.note.unwrap().contains("already on your channel"));
    assert_eq!(s.videos.lock().unwrap().len(), 1);
    assert!(
      !yt.safe_to_retry(),
      "a cut-off upload is never retried on its own (D11)"
    );
  }

  #[tokio::test]
  async fn youtube_publishes_only_a_public_processed_video() {
    let s: S = Arc::default();
    let base = serve(app(s.clone())).await;
    *s.base.lock().unwrap() = base.clone();
    let ep = Endpoints {
      worker: base.clone(),
      google_api: base.clone(),
      ..Endpoints::default()
    };
    *s.token.lock().unwrap() = "acc-1".into();
    let secret = json!({ "refreshToken": "ref-1", "channelId": "UC1", "uploads": "UU1" });
    let mut yt = YouTube::new(reqwest::Client::new(), &secret, &ep).unwrap();
    yt.recheck = std::time::Duration::ZERO;
    let dir = tempfile::tempdir().unwrap();
    let video = dir.path().join("clip.mp4");
    std::fs::write(&video, b"v").unwrap();
    let media = [video];
    let opts = json!({});
    let go = |title: &str, status: Value| {
      *s.next_status.lock().unwrap() = Some(status);
      s.bytes.lock().unwrap().clear();
      let item = json!({ "title": title });
      let post = json!({ "fields": { "title": title, "choices": { "madeForKids": false } } });
      let yt = &yt;
      let media = &media;
      let opts = &opts;
      async move {
        yt.publish(Upload {
          item: &item,
          post: Some(&post),
          media,
          idempotency_key: "k",
          options: opts,
        })
        .await
      }
    };
    let r = go(
      "one",
      json!({ "privacyStatus": "private", "uploadStatus": "processed" }),
    )
    .await
    .unwrap();
    assert!(!r.verified);
    assert_eq!(
      r.note.as_deref(),
      Some("YouTube has this video set to private.")
    );
    let r = go(
      "two",
      json!({ "privacyStatus": "public", "uploadStatus": "uploaded" }),
    )
    .await
    .unwrap();
    assert!(!r.verified);
    assert!(r.note.unwrap().contains("still processing"));
    let e = go("three", json!({ "privacyStatus": "public", "uploadStatus": "rejected", "rejectionReason": "duplicate" }))
      .await
      .unwrap_err();
    assert_eq!(e.code, "uploadRejected");
    assert!(e.message.contains("duplicate"));
    let r = go(
      "four",
      json!({ "privacyStatus": "public", "uploadStatus": "processed" }),
    )
    .await
    .unwrap();
    assert!(r.verified && r.note.is_none());
  }

  #[tokio::test]
  async fn youtube_quota_is_its_own_error_and_a_dead_sign_in_says_so() {
    let s: S = Arc::default();
    let base = serve(app(s.clone())).await;
    *s.base.lock().unwrap() = base.clone();
    *s.quota.lock().unwrap() = true;
    let ep = Endpoints {
      worker: base.clone(),
      google_api: base.clone(),
      ..Endpoints::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let video = dir.path().join("clip.mp4");
    std::fs::write(&video, b"x").unwrap();
    let secret = json!({ "refreshToken": "ref-1", "uploads": "UU1" });
    let yt = YouTube::new(reqwest::Client::new(), &secret, &ep).unwrap();
    let p = post_for(Some(true));
    let media = [video];
    let e = yt
      .publish(Upload {
        item: &json!({}),
        post: Some(&p),
        media: &media,
        idempotency_key: "k",
        options: &json!({}),
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "quotaExceeded");
    let dead = YouTube::new(
      reqwest::Client::new(),
      &json!({ "refreshToken": "revoked" }),
      &ep,
    )
    .unwrap();
    let e = dead.token.get(true).await.unwrap_err();
    assert_eq!(e.code, "tokenExpired");
    assert!(e.verbatim.unwrap().contains("invalid_grant"));
    assert!(clean_tags(vec!["x".repeat(600)]).is_empty());
  }
}

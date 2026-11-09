//! LinkedIn, as the member, through the Posts API (`/rest/posts`) with the `w_member_social`
//! scope. Sign-in goes through api.bunniehop.party's OAuth relay because LinkedIn needs a client
//! secret; the access token comes back to this Helper and lives in the keychain (D8).
//!
//! Videos use the multi-part Videos API (initialize → PUT each part → finalize), images the
//! Images API. A link the mapper moved to `fields.firstComment` is posted as the first comment.
//!
//! D11: LinkedIn has no idempotency key and no way to search one's own posts by text, so
//! `safe_to_retry` stays false and a post sent but not read back is `publishedUnverified`.

use super::{body_text, is_image, is_video, json_or_fail, net, status_failure, title_text};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader, With};
use crate::uploaders::ghost::urlencode;
use crate::uploaders::Endpoints;
use serde_json::{json, Value};
use std::io::SeekFrom;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const P: &str = "LinkedIn";
/// LinkedIn's dated API version (they keep each for about a year).
pub const VERSION: &str = "202609";
const MAX_VIDEO: u64 = 5_000_000_000;
const MAX_IMAGES: usize = 20;

pub struct LinkedIn {
  http: reqwest::Client,
  api: String,
  token: String,
  expires_at: i64,
  author: String,
  /// How long to wait between video status checks (short in tests).
  poll: Duration,
}

/// Exchanges nothing itself: takes the relay's token answer, reads the member's id and name.
/// Returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let Some(token) = tokens["access_token"].as_str().filter(|t| !t.is_empty()) else {
    return Err(Failure {
      code: "signInRequired",
      message: "LinkedIn didn't finish the sign-in. Try again.".into(),
      verbatim: tokens["error_description"]
        .as_str()
        .or(tokens["error"].as_str())
        .map(str::to_string),
    });
  };
  let me = json_or_fail(
    P,
    http
      .get(format!("{}/v2/userinfo", ep.linkedin))
      .bearer_auth(token)
      .send()
      .await,
  )
  .await?;
  let sub = me["sub"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "LinkedIn didn't say who signed in."))?;
  let name = me["name"].as_str().unwrap_or("LinkedIn member");
  let expires_in = tokens["expires_in"].as_i64().unwrap_or(60 * 24 * 3600);
  let expires_at = crate::pacing::now_ms() + expires_in * 1000;
  Ok((
    format!("{name} (LinkedIn)"),
    json!({ "accessToken": token, "expiresAt": expires_at, "author": format!("urn:li:person:{sub}") }),
  ))
}

/// LinkedIn's "little text" format reserves these characters; `#word` becomes a hashtag.
pub fn commentary(text: &str) -> String {
  let mut out = String::with_capacity(text.len() + 16);
  let chars: Vec<char> = text.chars().collect();
  let mut i = 0;
  while i < chars.len() {
    let c = chars[i];
    let at_word_start = i == 0 || chars[i - 1].is_whitespace();
    if c == '#' && at_word_start {
      let tag: String = chars[i + 1..]
        .iter()
        .take_while(|c| c.is_alphanumeric() || **c == '_')
        .collect();
      if !tag.is_empty() {
        out.push_str(&format!("{{hashtag|\\#|{}}}", escape(&tag)));
        i += 1 + tag.chars().count();
        continue;
      }
    }
    out.push_str(&escape(&c.to_string()));
    i += 1;
  }
  out
}

fn escape(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  for c in s.chars() {
    if matches!(
      c,
      '\\' | '|' | '{' | '}' | '@' | '[' | ']' | '(' | ')' | '<' | '>' | '#' | '*' | '_' | '~'
    ) {
      out.push('\\');
    }
    out.push(c);
  }
  out
}

fn clip(s: &str, n: usize) -> String {
  s.chars().take(n).collect()
}

impl LinkedIn {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints) -> Option<Self> {
    Some(Self {
      http,
      api: ep.linkedin.clone(),
      token: secret["accessToken"].as_str()?.to_string(),
      expires_at: secret["expiresAt"].as_i64().unwrap_or(i64::MAX),
      author: secret["author"].as_str()?.to_string(),
      poll: Duration::from_secs(5),
    })
  }

  #[cfg(test)]
  fn fast(mut self) -> Self {
    self.poll = Duration::from_millis(5);
    self
  }

  fn rest(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
    self
      .http
      .request(method, format!("{}/rest/{path}", self.api))
      .bearer_auth(&self.token)
      .header("LinkedIn-Version", VERSION)
      .header("X-Restli-Protocol-Version", "2.0.0")
  }

  async fn upload_image(&self, p: &Path) -> Result<String, Failure> {
    let init = json_or_fail(
      P,
      self
        .rest(reqwest::Method::POST, "images?action=initializeUpload")
        .json(&json!({ "initializeUploadRequest": { "owner": self.author } }))
        .send()
        .await,
    )
    .await?;
    let (Some(url), Some(urn)) = (
      init.pointer("/value/uploadUrl").and_then(Value::as_str),
      init.pointer("/value/image").and_then(Value::as_str),
    ) else {
      return Err(Failure::new(
        "uploadRejected",
        "LinkedIn didn't take the image.",
      ));
    };
    let bytes = tokio::fs::read(p)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the image from the vault.").with(e))?;
    let r = self
      .http
      .put(url)
      .bearer_auth(&self.token)
      .body(bytes)
      .send()
      .await
      .map_err(|e| net(P, e))?;
    if !r.status().is_success() {
      let s = r.status();
      return Err(status_failure(P, s, &r.text().await.unwrap_or_default()));
    }
    Ok(urn.to_string())
  }

  async fn upload_video(&self, p: &Path) -> Result<String, Failure> {
    let size = tokio::fs::metadata(p)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the video from the vault.").with(e))?
      .len();
    if size > MAX_VIDEO {
      return Err(Failure::new(
        "itemTooLarge",
        "The video is larger than LinkedIn's 5 GB limit.",
      ));
    }
    let init = json_or_fail(
      P,
      self
        .rest(reqwest::Method::POST, "videos?action=initializeUpload")
        .json(&json!({ "initializeUploadRequest": {
          "owner": self.author, "fileSizeBytes": size,
          "uploadCaptions": false, "uploadThumbnail": false,
        } }))
        .send()
        .await,
    )
    .await?;
    let v = &init["value"];
    let urn = v["video"]
      .as_str()
      .ok_or_else(|| Failure::new("uploadRejected", "LinkedIn didn't take the video."))?
      .to_string();
    let parts = v["uploadInstructions"]
      .as_array()
      .cloned()
      .unwrap_or_default();
    if parts.is_empty() {
      return Err(Failure::new(
        "uploadRejected",
        "LinkedIn didn't take the video.",
      ));
    }
    let mut f = tokio::fs::File::open(p)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the video from the vault.").with(e))?;
    let mut etags = Vec::with_capacity(parts.len());
    for part in &parts {
      let (Some(url), Some(first), Some(last)) = (
        part["uploadUrl"].as_str(),
        part["firstByte"].as_u64(),
        part["lastByte"].as_u64(),
      ) else {
        return Err(Failure::new(
          "uploadRejected",
          "LinkedIn sent a bad upload plan.",
        ));
      };
      if last < first || last >= size {
        return Err(Failure::new(
          "uploadRejected",
          "LinkedIn sent a bad upload plan.",
        ));
      }
      let mut buf = vec![0u8; (last - first + 1) as usize];
      f.seek(SeekFrom::Start(first))
        .await
        .and(f.read_exact(&mut buf).await.map(|_| ()))
        .map_err(|e| Failure::new("unknown", "Couldn't read the video from the vault.").with(e))?;
      let r = self
        .http
        .put(url)
        .header("content-type", "application/octet-stream")
        .body(buf)
        .send()
        .await
        .map_err(|e| net(P, e))?;
      if !r.status().is_success() {
        let s = r.status();
        return Err(status_failure(P, s, &r.text().await.unwrap_or_default()));
      }
      let etag = r
        .headers()
        .get("etag")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
      etags.push(etag);
    }
    json_or_fail(
      P,
      self
        .rest(reqwest::Method::POST, "videos?action=finalizeUpload")
        .json(&json!({ "finalizeUploadRequest": {
          "video": urn, "uploadToken": v["uploadToken"].as_str().unwrap_or(""),
          "uploadedPartIds": etags,
        } }))
        .send()
        .await,
    )
    .await?;
    // a post can only point at a video LinkedIn has finished processing
    for _ in 0..240 {
      let s = json_or_fail(
        P,
        self
          .rest(reqwest::Method::GET, &format!("videos/{}", urlencode(&urn)))
          .send()
          .await,
      )
      .await?;
      match s["status"].as_str().unwrap_or("") {
        "AVAILABLE" => return Ok(urn),
        "PROCESSING_FAILED" => {
          return Err(Failure {
            code: "uploadRejected",
            message: "LinkedIn couldn't process the video.".into(),
            verbatim: s["processingFailureReason"].as_str().map(str::to_string),
          })
        }
        _ => tokio::time::sleep(self.poll).await,
      }
    }
    Err(Failure::new(
      "server5xx",
      "LinkedIn is still processing the video after 20 minutes.",
    ))
  }
}

impl Uploader for LinkedIn {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      if crate::pacing::now_ms() >= self.expires_at {
        return Err(Failure::new(
          "tokenExpired",
          "LinkedIn sign-ins last 60 days and this one has ended. Connect LinkedIn again.",
        ));
      }
      let text = commentary(&body_text(u.post, u.item));
      let title = clip(&title_text(u.post, u.item), 200);
      let content = if let Some(v) = u.media.iter().find(|p| is_video(p)) {
        let urn = self.upload_video(v).await?;
        Some(json!({ "media": { "id": urn, "title": title } }))
      } else {
        let imgs: Vec<_> = u
          .media
          .iter()
          .filter(|p| is_image(p))
          .take(MAX_IMAGES)
          .collect();
        let mut urns = Vec::with_capacity(imgs.len());
        for p in imgs {
          urns.push(self.upload_image(p).await?);
        }
        match urns.len() {
          0 => None,
          1 => Some(json!({ "media": { "id": urns[0], "altText": clip(&title, 4086) } })),
          _ => Some(json!({ "multiImage": { "images":
            urns.iter().map(|u| json!({ "id": u })).collect::<Vec<_>>() } })),
        }
      };
      let mut post = json!({
        "author": self.author,
        "commentary": text,
        "visibility": "PUBLIC",
        "distribution": { "feedDistribution": "MAIN_FEED", "targetEntities": [], "thirdPartyDistributionChannels": [] },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": false,
      });
      if let Some(c) = content {
        post["content"] = c;
      }
      let r = self
        .rest(reqwest::Method::POST, "posts")
        .json(&post)
        .send()
        .await
        .map_err(|e| net(P, e))?;
      let status = r.status();
      let urn = r
        .headers()
        .get("x-restli-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
      let body = r.text().await.unwrap_or_default();
      if !status.is_success() {
        return Err(status_failure(P, status, &body));
      }
      let Some(urn) = urn.filter(|u| u.starts_with("urn:li:")) else {
        return Ok(Published {
          note: None,
          dest_item_id: String::new(),
          dest_url: None,
          verified: false,
        });
      };
      let verified = matches!(
        self.rest(reqwest::Method::GET, &format!("posts/{}", urlencode(&urn))).send().await,
        Ok(r) if r.status().is_success()
      );
      if let Some(c) = u
        .post
        .and_then(|p| p.pointer("/fields/firstComment"))
        .and_then(Value::as_str)
        .filter(|c| !c.trim().is_empty())
      {
        // the post exists either way; a failed comment must not make the hop post again (D11)
        let r = self
          .rest(
            reqwest::Method::POST,
            &format!("socialActions/{}/comments", urlencode(&urn)),
          )
          .json(
            &json!({ "actor": self.author, "object": urn, "message": { "text": clip(c, 1250) } }),
          )
          .send()
          .await;
        if !matches!(&r, Ok(r) if r.status().is_success()) {
          tracing::warn!("LinkedIn first comment wasn't accepted");
        }
      }
      Ok(Published {
        note: None,
        dest_url: Some(format!("https://www.linkedin.com/feed/update/{urn}")),
        dest_item_id: urn,
        verified,
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Path as AxPath, State};
  use axum::http::{HeaderMap, StatusCode};
  use axum::response::IntoResponse;
  use axum::routing::{get, post, put};
  use axum::{Json, Router};
  use std::sync::{Arc, Mutex};

  type Log = Arc<Mutex<Vec<(String, Value)>>>;

  fn fake(log: Log, base: Arc<Mutex<String>>) -> Router {
    let rec = |log: &Log, k: &str, v: Value| log.lock().unwrap().push((k.to_string(), v));
    Router::new()
      .route(
        "/v2/userinfo",
        get(|h: HeaderMap| async move {
          assert_eq!(h["authorization"], "Bearer tok-1");
          Json(json!({ "sub": "abc", "name": "Mara Lin" }))
        }),
      )
      .route(
        "/rest/videos",
        post({
          let (log, base) = (log.clone(), base.clone());
          move |h: HeaderMap, Json(b): Json<Value>| async move {
            assert_eq!(h["linkedin-version"], VERSION);
            assert_eq!(h["x-restli-protocol-version"], "2.0.0");
            rec(&log, "video", b.clone());
            let base = base.lock().unwrap().clone();
            if b.get("initializeUploadRequest").is_some() {
              Json(json!({ "value": { "video": "urn:li:video:V1", "uploadToken": "",
                "uploadInstructions": [
                  { "uploadUrl": format!("{base}/up/1"), "firstByte": 0, "lastByte": 3 },
                  { "uploadUrl": format!("{base}/up/2"), "firstByte": 4, "lastByte": 5 },
                ] } }))
            } else {
              Json(json!({}))
            }
          }
        }),
      )
      .route(
        "/rest/videos/{urn}",
        get(|AxPath(urn): AxPath<String>| async move {
          assert_eq!(urn, "urn:li:video:V1");
          Json(json!({ "status": "AVAILABLE" }))
        }),
      )
      .route(
        "/up/{n}",
        put({
          let log = log.clone();
          move |AxPath(n): AxPath<String>, b: axum::body::Bytes| async move {
            rec(&log, "part", json!(String::from_utf8_lossy(&b)));
            ([("etag", format!("etag-{n}"))], "").into_response()
          }
        }),
      )
      .route(
        "/rest/posts",
        post({
          let log = log.clone();
          move |Json(b): Json<Value>| async move {
            rec(&log, "post", b);
            (StatusCode::CREATED, [("x-restli-id", "urn:li:share:77")], "").into_response()
          }
        }),
      )
      .route(
        "/rest/posts/{urn}",
        get(|AxPath(urn): AxPath<String>| async move { Json(json!({ "id": urn })) }),
      )
      .route(
        "/rest/socialActions/{urn}/comments",
        post(
          move |State(log): State<Log>, AxPath(urn): AxPath<String>, Json(b): Json<Value>| async move {
            rec(&log, "comment", json!({ "urn": urn, "body": b }));
            (StatusCode::CREATED, Json(json!({})))
          },
        ),
      )
      .with_state(log)
  }

  #[test]
  fn linkedin_commentary_escapes_little_text_and_keeps_hashtags() {
    assert_eq!(
      commentary("Edit (fast) @you #tag_1 a#b"),
      "Edit \\(fast\\) \\@you {hashtag|\\#|tag\\_1} a\\#b"
    );
  }

  #[tokio::test]
  async fn linkedin_uploads_the_video_in_parts_posts_and_adds_the_link_comment() {
    let log: Log = Arc::default();
    let base_cell = Arc::new(Mutex::new(String::new()));
    let base = serve(fake(log.clone(), base_cell.clone())).await;
    *base_cell.lock().unwrap() = base.clone();
    let ep = Endpoints {
      linkedin: base.clone(),
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    let (label, secret) = connect(
      &http,
      &ep,
      &json!({ "access_token": "tok-1", "expires_in": 5_184_000 }),
    )
    .await
    .unwrap();
    assert_eq!(label, "Mara Lin (LinkedIn)");
    assert_eq!(secret["author"], "urn:li:person:abc");
    let li = LinkedIn::new(http, &secret, &ep).unwrap().fast();
    let dir = tempfile::tempdir().unwrap();
    let v = dir.path().join("media.mp4");
    std::fs::write(&v, b"abcdef").unwrap();
    let item = json!({ "id": "v1", "title": "My edit", "description": "x" });
    let post = json!({ "as": "video", "fields": { "title": "My edit", "body": "Workflow #editing",
      "firstComment": "https://example.com/gear" } });
    let p = li
      .publish(Upload {
        item: &item,
        post: Some(&post),
        media: &[v],
        idempotency_key: "h:v1:linkedin",
        options: &json!({}),
      })
      .await
      .unwrap();
    assert!(p.verified);
    assert_eq!(p.dest_item_id, "urn:li:share:77");
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://www.linkedin.com/feed/update/urn:li:share:77")
    );
    let log = log.lock().unwrap().clone();
    let kinds: Vec<&str> = log.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(kinds, ["video", "part", "part", "video", "post", "comment"]);
    assert_eq!(log[0].1["initializeUploadRequest"]["fileSizeBytes"], 6);
    assert_eq!(log[1].1, "abcd");
    assert_eq!(log[2].1, "ef");
    assert_eq!(
      log[3].1["finalizeUploadRequest"]["uploadedPartIds"],
      json!(["etag-1", "etag-2"])
    );
    let body = &log[4].1;
    assert_eq!(body["author"], "urn:li:person:abc");
    assert_eq!(body["commentary"], "Workflow {hashtag|\\#|editing}");
    assert_eq!(body["content"]["media"]["id"], "urn:li:video:V1");
    assert_eq!(body["visibility"], "PUBLIC");
    assert_eq!(log[5].1["urn"], "urn:li:share:77");
    assert_eq!(
      log[5].1["body"]["message"]["text"],
      "https://example.com/gear"
    );
  }

  #[tokio::test]
  async fn linkedin_refuses_to_post_with_an_expired_sign_in() {
    let li = LinkedIn::new(
      reqwest::Client::new(),
      &json!({ "accessToken": "t", "expiresAt": 1, "author": "urn:li:person:a" }),
      &Endpoints {
        linkedin: "http://127.0.0.1:9".into(),
        ..Endpoints::default()
      },
    )
    .unwrap();
    let e = li
      .publish(Upload {
        item: &json!({ "id": "1", "title": "t" }),
        post: None,
        media: &[],
        idempotency_key: "k",
        options: &json!({}),
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "tokenExpired");
  }
}

//! TikTok Direct Post for videos (D-062, D-066, O-015). The file goes up from this computer
//! in chunks (`FILE_UPLOAD`); no URL is ever exposed. Contracts: TikTok's Content Posting API
//! reference (Query Creator Info, Direct Post, Media Transfer Guide, Get Post Status) and the
//! Content Sharing Guidelines. Every post carries the choices the creator made in the TikTok
//! panel; nothing has a default audience.
use super::{body_text, is_video, json_or_fail, mime_of, net, nothing_posted, Endpoints};
use crate::{
  connections::Store,
  hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader, With},
  posted::UploadHandles,
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};

const P: &str = "TikTok";
/// TikTok's documented cap for a video file.
const VIDEO_MAX: u64 = 4_000_000_000;
/// Caption limit, counted in UTF-16 units like the schema's `counting`.
const CAPTION_MAX: usize = 2200;
/// Chunk size for files of 20 MB and over. TikTok accepts 5 MB to 64 MB chunks, a final chunk
/// up to 128 MB, and 1 to 1,000 chunks; smaller files go up whole.
const CHUNK: u64 = 10_000_000;
/// Status checks: TikTok allows 30 a minute per token, so one every 5 s for 10 minutes.
const STATUS_TRIES: usize = 120;
/// TikTok access tokens last about a day; renew through the relay with under 10 minutes left.
const REFRESH_WITHIN_MS: i64 = 10 * 60000;

/// What TikTok says this creator may choose right now (Query Creator Info).
#[derive(Debug, Clone, PartialEq)]
pub struct Creator {
  pub username: String,
  pub nickname: String,
  pub privacy: Vec<String>,
  pub comment_disabled: bool,
  pub duet_disabled: bool,
  pub stitch_disabled: bool,
  pub max_duration_sec: Option<u64>,
}

impl Creator {
  /// The shape the web panel reads (`GET /v1/connections/{id}/publish-options`).
  pub fn to_json(&self) -> Value {
    json!({
      "username": self.username,
      "nickname": self.nickname,
      "privacyOptions": self.privacy,
      "commentDisabled": self.comment_disabled,
      "duetDisabled": self.duet_disabled,
      "stitchDisabled": self.stitch_disabled,
      "maxDurationSec": self.max_duration_sec,
    })
  }
}

/// The creator's answers from the TikTok panel (`options.tiktok`).
#[derive(Debug, Clone, PartialEq)]
struct Choice {
  privacy: String,
  comment: bool,
  duet: bool,
  stitch: bool,
  brand_organic: bool,
  brand_content: bool,
}

fn choice(options: &Value) -> Result<Choice, Failure> {
  let t = &options["tiktok"];
  if t["consent"] != true {
    return Err(Failure::new(
      "requiredChoiceMissing",
      "Open the TikTok panel and confirm before posting to TikTok.",
    ));
  }
  let privacy = t["privacy"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| {
      Failure::new(
        "requiredChoiceMissing",
        "Choose who can see this video in the TikTok panel.",
      )
    })?
    .to_string();
  let on = |k: &str| t[k] == true;
  if on("brandContent") && privacy == "SELF_ONLY" {
    return Err(Failure::new(
      "requiredChoiceMissing",
      "TikTok doesn't allow branded content to be private. Choose another audience.",
    ));
  }
  Ok(Choice {
    privacy,
    comment: on("comment"),
    duet: on("duet"),
    stitch: on("stitch"),
    brand_organic: on("brandOrganic"),
    brand_content: on("brandContent"),
  })
}

/// TikTok wraps answers as `{data, error: {code, message, log_id}}`; anything but `ok` fails.
fn data(v: Value, what: &str) -> Result<Value, Failure> {
  match v.pointer("/error/code").and_then(Value::as_str) {
    None | Some("ok") => Ok(v["data"].clone()),
    Some(_) => {
      Err(Failure::new("uploadRejected", format!("TikTok refused {what}.")).with(&v["error"]))
    }
  }
}

/// `(chunk_size, [start, end) ranges)` for a file of `size` bytes, as TikTok counts them:
/// `total_chunk_count = floor(size / chunk_size)`, the remainder riding on the final chunk.
fn chunks(size: u64, chunk: u64) -> (u64, Vec<(u64, u64)>) {
  if size < 2 * chunk {
    return (size, vec![(0, size)]);
  }
  let n = size / chunk;
  let ranges = (0..n)
    .map(|i| (i * chunk, if i + 1 == n { size } else { (i + 1) * chunk }))
    .collect();
  (chunk, ranges)
}

async fn creator_info(
  http: &reqwest::Client,
  ep: &Endpoints,
  token: &str,
) -> Result<Creator, Failure> {
  let v = json_or_fail(
    P,
    http
      .post(format!("{}/v2/post/publish/creator_info/query/", ep.tiktok))
      .bearer_auth(token)
      .header("content-type", "application/json; charset=UTF-8")
      .send()
      .await,
  )
  .await?;
  let d = data(v, "to share this account's posting settings")?;
  let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
  let privacy: Vec<String> = d["privacy_level_options"]
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(|p| p.as_str().map(str::to_string))
    .collect();
  if privacy.is_empty() {
    return Err(Failure::new(
      "uploadRejected",
      "TikTok says this account can't post from other apps right now.",
    ));
  }
  Ok(Creator {
    username: s("creator_username"),
    nickname: s("creator_nickname"),
    privacy,
    comment_disabled: d["comment_disabled"] == true,
    duet_disabled: d["duet_disabled"] == true,
    stitch_disabled: d["stitch_disabled"] == true,
    max_duration_sec: d["max_video_post_duration_sec"].as_u64(),
  })
}

pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let s = |k: &str| tokens[k].as_str().filter(|s| !s.is_empty());
  let (Some(token), Some(refresh), Some(open_id)) =
    (s("access_token"), s("refresh_token"), s("open_id"))
  else {
    return Err(Failure::new(
      "signInRequired",
      "TikTok didn't finish sign-in.",
    ));
  };
  if !tokens["scope"]
    .as_str()
    .unwrap_or("")
    .split(',')
    .any(|x| x.trim() == "video.publish")
  {
    return Err(Failure::new(
      "signInRequired",
      "TikTok sign-in didn't allow posting videos. Connect again and allow it.",
    ));
  }
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|n| *n > 0)
    .ok_or_else(|| Failure::new("signInRequired", "TikTok did not return a token lifetime."))?;
  let c = creator_info(http, ep, token)
    .await
    .map_err(|e| Failure::new("signInRequired", e.message).with(e.verbatim.unwrap_or_default()))?;
  let now = crate::pacing::now_ms();
  let label = if c.username.is_empty() {
    c.nickname.clone()
  } else {
    format!("@{}", c.username)
  };
  let mut secret = json!({"openId":open_id,"username":c.username,"accessToken":token,
    "refreshToken":refresh,"expiresAt":now+expires*1000});
  if let Some(r) = tokens["refresh_expires_in"].as_i64() {
    secret["refreshExpiresAt"] = json!(now + r * 1000);
  }
  Ok((label, secret))
}

pub struct TikTok {
  http: reqwest::Client,
  ep: Endpoints,
  store: Arc<Store>,
  connection: String,
  secret: tokio::sync::Mutex<Value>,
  handles: UploadHandles,
  poll: Duration,
  chunk: u64,
}

impl TikTok {
  pub fn new(
    http: reqwest::Client,
    store: Arc<Store>,
    connection: &str,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    secret["openId"].as_str().filter(|s| !s.is_empty())?;
    secret["refreshToken"].as_str()?;
    Some(Self {
      http,
      ep: ep.clone(),
      store,
      connection: connection.into(),
      secret: tokio::sync::Mutex::new(secret.clone()),
      handles: UploadHandles::new(handles),
      poll: Duration::from_secs(5),
      chunk: CHUNK,
    })
  }

  #[cfg(test)]
  fn fast(mut self, chunk: u64) -> Self {
    self.poll = Duration::from_millis(1);
    self.chunk = chunk;
    self
  }

  /// The current access token, renewed through the relay (which adds the app secret and keeps
  /// nothing). TikTok may rotate the refresh token; the new one replaces the old in the keychain.
  async fn access(&self) -> Result<String, Failure> {
    let mut s = self.secret.lock().await;
    let now = crate::pacing::now_ms();
    let token = s["accessToken"].as_str().unwrap_or("").to_string();
    if !token.is_empty() && s["expiresAt"].as_i64().unwrap_or(0) - now > REFRESH_WITHIN_MS {
      return Ok(token);
    }
    let refresh = s["refreshToken"].as_str().unwrap_or("").to_string();
    let v = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/v1/oauth/tiktok/token", self.ep.worker))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await,
    )
    .await
    .map_err(|e| {
      Failure::new(
        "tokenExpired",
        "TikTok sign-in expired. Connect TikTok again.",
      )
      .with(e.verbatim.unwrap_or(e.message))
    })?;
    let new = v["access_token"]
      .as_str()
      .filter(|t| !t.is_empty())
      .ok_or_else(|| {
        Failure::new(
          "tokenExpired",
          "TikTok sign-in expired. Connect TikTok again.",
        )
        .with(&v)
      })?;
    if v["open_id"].as_str().is_some_and(|o| o != s["openId"]) {
      return Err(Failure::new(
        "signInRequired",
        "TikTok renewed a different account. Connect TikTok again.",
      ));
    }
    let lifetime = v["expires_in"]
      .as_i64()
      .filter(|n| *n > 0)
      .ok_or_else(|| Failure::new("tokenExpired", "TikTok did not return a token lifetime."))?;
    let mut next = s.clone();
    next["accessToken"] = json!(new);
    next["expiresAt"] = json!(now + lifetime * 1000);
    if let Some(r) = v["refresh_token"].as_str().filter(|r| !r.is_empty()) {
      next["refreshToken"] = json!(r);
    }
    if let Some(r) = v["refresh_expires_in"].as_i64() {
      next["refreshExpiresAt"] = json!(now + r * 1000);
    }
    self
      .store
      .set_secret(&self.connection, &next)
      .map_err(|e| {
        Failure::new(
          "vaultUnavailable",
          "Couldn't save the renewed TikTok sign-in.",
        )
        .with(e)
      })?;
    *s = next;
    Ok(new.to_string())
  }

  /// Fresh posting settings for the TikTok panel, asked every time it opens (Content Sharing
  /// Guidelines: the latest creator info when rendering the post screen).
  pub async fn creator(&self) -> Result<Creator, Failure> {
    let token = self.access().await?;
    creator_info(&self.http, &self.ep, &token).await
  }

  fn save(&self, key: &str, v: &Value) -> Result<(), Failure> {
    self.handles.save(key, v).map_err(|e| {
      Failure::new("vaultUnavailable", "Couldn't save TikTok's upload handle.").with(e)
    })
  }

  /// Checks the panel's choices against what TikTok offers now, starts the post and uploads
  /// every chunk but the last. Nothing appears on TikTok until the final chunk lands, so Stop
  /// is checked once more right before it. Returns the saved handle, and why the final chunk
  /// may not have arrived when its request failed.
  async fn prepare(
    &self,
    u: &Upload<'_>,
    pick: &Choice,
    token: &str,
    control: &PublishControl,
  ) -> Result<(Value, Option<String>), Failure> {
    let c = creator_info(&self.http, &self.ep, token).await?;
    if !c.privacy.contains(&pick.privacy) {
      return Err(Failure::new(
        "requiredChoiceMissing",
        "TikTok no longer offers the audience you chose for this account. Open the TikTok panel and choose again.",
      ));
    }
    if let (Some(max), Some(d)) = (c.max_duration_sec, u.item["durationSec"].as_f64()) {
      if d > max as f64 {
        return Err(Failure::new(
          "notSupported",
          format!(
            "TikTok lets this account post videos up to {} min.",
            max.div_ceil(60)
          ),
        ));
      }
    }
    let path = &u.media[0];
    let size = tokio::fs::metadata(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
      .len();
    let (chunk_size, ranges) = chunks(size, self.chunk);
    let body = json!({
      "post_info": {
        "title": body_text(u.post, u.item),
        "privacy_level": pick.privacy,
        // The creator's own "No one" settings always win (Query Creator Info).
        "disable_comment": !pick.comment || c.comment_disabled,
        "disable_duet": !pick.duet || c.duet_disabled,
        "disable_stitch": !pick.stitch || c.stitch_disabled,
        "brand_organic_toggle": pick.brand_organic,
        "brand_content_toggle": pick.brand_content,
      },
      "source_info": {
        "source": "FILE_UPLOAD",
        "video_size": size,
        "chunk_size": chunk_size,
        "total_chunk_count": ranges.len(),
      },
    });
    let v = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/v2/post/publish/video/init/", self.ep.tiktok))
        .bearer_auth(token)
        .header("content-type", "application/json; charset=UTF-8")
        .json(&body)
        .send()
        .await,
    )
    .await?;
    let d = data(v, "to start this post")?;
    let id = d["publish_id"]
      .as_str()
      .filter(|s| !s.is_empty())
      .ok_or_else(|| Failure::new("uploadRejected", "TikTok did not start the post."))?
      .to_string();
    let mut handle =
      json!({"kind":"video","stage":"uploading","publishId":id,"username":c.username});
    self.save(u.idempotency_key, &handle)?;
    let target = d["upload_url"]
      .as_str()
      .filter(|s| s.starts_with(&format!("{}/", self.ep.tiktok_upload)) && !s.contains('#'))
      .ok_or_else(|| {
        Failure::new(
          "uploadRejected",
          "TikTok returned an unusable upload address.",
        )
      })?
      .to_string();
    let file = tokio::fs::read(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?;
    let last = ranges.len() - 1;
    for (i, (start, end)) in ranges.into_iter().enumerate() {
      if i == last {
        handle["stage"] = json!("publishing");
        self.save(u.idempotency_key, &handle)?;
        control.start_publish()?;
        // From here the post may go live: an error is reported, never retried (D11), unless
        // the answer is a refusal (D-069), which frees the item for a later hop.
        let r = self
          .send_chunk(&target, &file, start, end, size, path)
          .await;
        let status = r.as_ref().ok().map(|r| r.status());
        return match Self::chunk_answer(r).await {
          Ok(()) => Ok((handle, None)),
          Err(e) if nothing_posted(status) => Err(e),
          Err(e) => Ok((handle, Some(e.message))),
        };
      }
      Self::chunk_answer(
        self
          .send_chunk(&target, &file, start, end, size, path)
          .await,
      )
      .await?;
    }
    Err(Failure::new("uploadRejected", "This video is empty."))
  }

  /// One chunk, in order, with its byte range. No TikTok token goes to the upload address.
  async fn send_chunk(
    &self,
    target: &str,
    file: &[u8],
    start: u64,
    end: u64,
    size: u64,
    path: &std::path::Path,
  ) -> Result<reqwest::Response, reqwest::Error> {
    self
      .http
      .put(target)
      .header("content-type", mime_of(path))
      .header("content-range", format!("bytes {start}-{}/{size}", end - 1))
      .body(file[start as usize..end as usize].to_vec())
      .send()
      .await
  }

  async fn chunk_answer(r: Result<reqwest::Response, reqwest::Error>) -> Result<(), Failure> {
    let r = r.map_err(|e| net(P, e))?;
    if r.status().is_success() {
      return Ok(());
    }
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    Err(
      Failure::new(
        "uploadRejected",
        format!("TikTok's upload host refused the video ({status})."),
      )
      .with(text),
    )
  }

  /// Follows a publish ID to TikTok's final word. Pending, failed, private and complete stay
  /// distinct; only a public post ID counts as verified (D12).
  async fn settle(&self, key: &str, handle: &Value, token: &str) -> Result<Published, Failure> {
    let id = handle["publishId"].as_str().unwrap_or("").to_string();
    let unverified = |note: &str| Published {
      dest_item_id: id.clone(),
      dest_url: None,
      verified: false,
      note: Some(format!("{note} Check TikTok before posting it again.")),
    };
    if id.is_empty() {
      return Ok(unverified(
        "TikTok may have started this post, but its ID was not saved.",
      ));
    }
    for tries in 1..=STATUS_TRIES {
      let v = json_or_fail(
        P,
        self
          .http
          .post(format!("{}/v2/post/publish/status/fetch/", self.ep.tiktok))
          .bearer_auth(token)
          .header("content-type", "application/json; charset=UTF-8")
          .json(&json!({ "publish_id": id }))
          .send()
          .await,
      )
      .await
      .and_then(|v| data(v, "to report this post"));
      let d = match v {
        Ok(d) => d,
        Err(_) => {
          return Ok(unverified(
            "BunnieHop couldn't get TikTok's answer for this post.",
          ))
        }
      };
      match d["status"].as_str() {
        Some("PUBLISH_COMPLETE") => {
          let post = d["publicaly_available_post_id"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|p| {
              p.as_str()
                .map(str::to_string)
                .or_else(|| p.as_u64().map(|n| n.to_string()))
            });
          return Ok(match post {
            Some(post) => {
              let user = handle["username"].as_str().unwrap_or("");
              Published {
                dest_url: Some(if user.is_empty() {
                  format!("https://www.tiktok.com/video/{post}")
                } else {
                  format!("https://www.tiktok.com/@{user}/video/{post}")
                }),
                dest_item_id: post,
                verified: true,
                note: None,
              }
            }
            None => unverified(
              "TikTok finished this post, but it is private or still in TikTok's review, so it can't be confirmed publicly.",
            ),
          });
        }
        Some("FAILED") => {
          // TikTok's final word that nothing was posted: a later hop may try again.
          self.handles.release(key);
          let reason = d["fail_reason"].as_str().unwrap_or("").to_string();
          let code = match reason.as_str() {
            "auth_removed" => "signInRequired",
            "spam_risk_too_many_posts" => "dailyCapReached",
            _ => "uploadRejected",
          };
          return Err(
            Failure::new(
              code,
              "TikTok did not post this video. Nothing was published.",
            )
            .with(reason),
          );
        }
        Some("PROCESSING_UPLOAD" | "PROCESSING_DOWNLOAD") if tries < STATUS_TRIES => {
          tokio::time::sleep(self.poll).await
        }
        _ => break,
      }
    }
    Ok(unverified("TikTok is still processing this video."))
  }
}

impl Uploader for TikTok {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    self.publish_controlled(u, PublishControl::new(tokio::sync::watch::channel(false).1))
  }

  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let path = match u.media {
        [p] if is_video(p) => p,
        _ => {
          return Err(Failure::new(
            "notSupported",
            "TikTok takes one video per post here. TikTok photo posts are not ready yet.",
          ))
        }
      };
      let pick = choice(u.options)?;
      let n = tokio::fs::metadata(path)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
        .len();
      if n == 0 || n > VIDEO_MAX {
        return Err(Failure::new(
          "itemTooLarge",
          "This video is empty or over TikTok's 4 GB limit.",
        ));
      }
      if body_text(u.post, u.item).encode_utf16().count() > CAPTION_MAX {
        return Err(Failure::new(
          "textOverLimit",
          "TikTok captions are limited to 2,200 characters.",
        ));
      }
      let token = self.access().await?;
      let fresh = self
        .handles
        .begin(u.idempotency_key, "video")
        .map_err(|e| {
          Failure::new(
            "vaultUnavailable",
            "Couldn't reserve the TikTok upload. Nothing was sent.",
          )
          .with(e)
        })?;
      if !fresh {
        // A publish ID already exists for this item: follow it, never start a second post.
        let h = self
          .handles
          .load(u.idempotency_key)
          .ok()
          .flatten()
          .unwrap_or(Value::Null);
        return self.settle(u.idempotency_key, &h, &token).await;
      }
      // An unfinished upload never appears on TikTok, so failures before the final chunk
      // release the reservation for a later deliberate hop.
      let (h, lost) = match self.prepare(&u, &pick, &token, &control).await {
        Ok(r) => r,
        Err(e) => {
          self.handles.release(u.idempotency_key);
          return Err(e);
        }
      };
      match (self.settle(u.idempotency_key, &h, &token).await, lost) {
        (Ok(mut p), Some(why)) if !p.verified => {
          p.note = Some(format!(
            "{why} The last part of the upload may not have arrived. Check TikTok before posting it again."
          ));
          Ok(p)
        }
        (other, _) => other,
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::connections::{Connection, MemorySecrets};
  use crate::uploaders::testkit::serve;
  use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{post, put},
    Json, Router,
  };
  use std::{collections::HashMap, sync::Mutex};

  #[derive(Default)]
  struct Log {
    calls: Vec<&'static str>,
    inits: Vec<Value>,
    puts: Vec<(String, Vec<u8>)>,
    statuses: usize,
    refreshes: usize,
  }

  struct Fake {
    privacy: Value,
    comment_disabled: bool,
    /// What status/fetch answers, in order; the last answer repeats.
    statuses: Vec<Value>,
    /// How the upload host answers the last chunk: a row of the D-069 table, or 201.
    last_chunk: Option<u16>,
  }

  fn complete() -> Value {
    json!({"data":{"status":"PUBLISH_COMPLETE","publicaly_available_post_id":[7300]},"error":{"code":"ok"}})
  }

  fn status(s: &str) -> Value {
    json!({"data":{"status":s},"error":{"code":"ok"}})
  }

  async fn fake(f: Fake) -> (String, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let base = Arc::new(Mutex::new(String::new()));
    let seq = Arc::new(Mutex::new(f.statuses));
    let (privacy, cd, last_chunk) = (f.privacy, f.comment_disabled, f.last_chunk);
    let app = Router::new()
      .route("/v2/post/publish/creator_info/query/", post({ let log = log.clone(); move |h: HeaderMap| {
        let log = log.clone(); let privacy = privacy.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          log.lock().unwrap().calls.push("creator");
          Json(json!({"data":{"creator_username":"artist","creator_nickname":"Artist","privacy_level_options":privacy,
            "comment_disabled":cd,"duet_disabled":false,"stitch_disabled":true,"max_video_post_duration_sec":600},
            "error":{"code":"ok","message":"","log_id":"l"}}))
        }
      }}))
      .route("/v2/post/publish/video/init/", post({ let log = log.clone(); let base = base.clone(); move |h: HeaderMap, Json(b): Json<Value>| {
        let log = log.clone(); let base = base.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          let mut l = log.lock().unwrap();
          l.calls.push("init");
          l.inits.push(b);
          Json(json!({"data":{"publish_id":"v_pub_file~v2.1","upload_url":format!("{}/upload/?upload_id=1&upload_token=x", base.lock().unwrap())},"error":{"code":"ok"}}))
        }
      }}))
      .route("/upload/", put({ let log = log.clone(); move |h: HeaderMap, b: axum::body::Bytes| {
        let log = log.clone(); async move {
          assert!(h.get("authorization").is_none(), "no TikTok token goes to the upload host");
          assert_eq!(h["content-type"], "video/mp4");
          let mut l = log.lock().unwrap();
          l.calls.push("put");
          let range = h["content-range"].to_str().unwrap().to_string();
          let last = range.rsplit_once('/').is_some_and(|(r, total)| r.rsplit('-').next().and_then(|e| e.parse::<u64>().ok()).map(|e| e + 1) == total.parse().ok());
          l.puts.push((range, b.to_vec()));
          match last_chunk.filter(|_| last) { Some(code) => crate::uploaders::testkit::table_answer(code), None => StatusCode::CREATED.into_response() }
        }
      }}))
      .route("/v2/post/publish/status/fetch/", post({ let log = log.clone(); move |Json(b): Json<Value>| {
        let log = log.clone(); let seq = seq.clone(); async move {
          assert_eq!(b, json!({"publish_id":"v_pub_file~v2.1"}));
          log.lock().unwrap().statuses += 1;
          let mut s = seq.lock().unwrap();
          let v = if s.len() > 1 { s.remove(0) } else { s[0].clone() };
          if v.is_null() { (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))) } else { (StatusCode::OK, Json(v)) }
        }
      }}))
      .route("/v1/oauth/tiktok/token", post({ let log = log.clone(); move |Json(b): Json<Value>| {
        let log = log.clone(); async move {
          assert_eq!(b, json!({"refresh_token":"r1"}));
          log.lock().unwrap().refreshes += 1;
          Json(json!({"open_id":"open-1","access_token":"t","expires_in":86400,"refresh_token":"r2","refresh_expires_in":31536000}))
        }
      }}));
    let url = serve(app).await;
    *base.lock().unwrap() = url.clone();
    (url, log)
  }

  fn ep(base: &str) -> Endpoints {
    Endpoints {
      tiktok: base.into(),
      tiktok_upload: base.into(),
      worker: base.into(),
      ..Endpoints::default()
    }
  }

  fn setup(base: &str, dir: &std::path::Path, expires_at: i64) -> (TikTok, Arc<Store>) {
    let store = Arc::new(Store::open(
      dir.join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    let secret = json!({"openId":"open-1","username":"artist","accessToken":"t","refreshToken":"r1","expiresAt":expires_at});
    let c = store
      .save(
        Connection {
          id: "tiktok-1".into(),
          platform: "tiktok".into(),
          label: "@artist".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    let up = TikTok::new(
      reqwest::Client::new(),
      store.clone(),
      &c.id,
      &secret,
      &ep(base),
      dir.join("handles"),
    )
    .unwrap()
    .fast(4);
    (up, store)
  }

  fn later() -> i64 {
    crate::pacing::now_ms() + 20 * 3600000
  }

  fn picked(privacy: &str) -> Value {
    json!({"tiktok":{"privacy":privacy,"comment":true,"duet":true,"stitch":true,"brandOrganic":true,"consent":true}})
  }

  async fn run(
    up: &TikTok,
    dir: &std::path::Path,
    name: &str,
    options: &Value,
    control: Option<PublishControl>,
  ) -> Result<Published, Failure> {
    let p = dir.join(name);
    std::fs::write(&p, b"0123456789").unwrap();
    let media = [p];
    let item = json!({"kind":"short","title":"Sunset","durationSec":42});
    let post = json!({"fields":{"body":"Mapped caption #sunset"}});
    let u = Upload {
      item: &item,
      post: Some(&post),
      media: &media,
      idempotency_key: "tt|1|src|1",
      options,
    };
    match control {
      Some(c) => up.publish_controlled(u, c).await,
      None => up.publish(u).await,
    }
  }

  fn default_fake(statuses: Vec<Value>) -> Fake {
    Fake {
      privacy: json!(["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"]),
      comment_disabled: true,
      statuses,
      last_chunk: None,
    }
  }

  #[tokio::test]
  async fn tiktok_queries_creator_before_presenting_publish_choices() {
    let (base, log) = fake(default_fake(vec![complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let c = up.creator().await.unwrap();
    assert_eq!(
      c.to_json(),
      json!({"username":"artist","nickname":"Artist","privacyOptions":["PUBLIC_TO_EVERYONE","MUTUAL_FOLLOW_FRIENDS","SELF_ONLY"],
        "commentDisabled":true,"duetDisabled":false,"stitchDisabled":true,"maxDurationSec":600})
    );
    // Publishing asks again, before the post starts, in case the account changed since.
    run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
      .await
      .unwrap();
    let calls = log.lock().unwrap().calls.clone();
    assert_eq!(&calls[..3], ["creator", "creator", "init"]);
  }

  #[tokio::test]
  async fn tiktok_rejects_missing_consent_or_unoffered_privacy() {
    let (base, log) = fake(Fake {
      privacy: json!(["SELF_ONLY"]),
      comment_disabled: false,
      statuses: vec![complete()],
      last_chunk: None,
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let mut no_consent = picked("SELF_ONLY");
    no_consent["tiktok"]["consent"] = json!(false);
    let no_audience = json!({"tiktok":{"consent":true}});
    let mut branded_private = picked("SELF_ONLY");
    branded_private["tiktok"]["brandContent"] = json!(true);
    for bad in [json!({}), no_consent, no_audience, branded_private] {
      let e = run(&up, dir.path(), "a.mp4", &bad, None).await.unwrap_err();
      assert_eq!(e.code, "requiredChoiceMissing", "{bad}");
    }
    assert!(
      log.lock().unwrap().calls.is_empty(),
      "nothing reaches TikTok"
    );
    let e = run(
      &up,
      dir.path(),
      "a.mp4",
      &picked("PUBLIC_TO_EVERYONE"),
      None,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    assert!(e.message.contains("no longer offers"));
    assert_eq!(log.lock().unwrap().calls, ["creator"], "never started");
    // The refused choice left no reservation behind: a corrected hop posts.
    assert!(
      run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
        .await
        .unwrap()
        .verified
    );
  }

  #[test]
  fn tiktok_chunks_follow_the_documented_count() {
    assert_eq!(chunks(4_000_000, CHUNK), (4_000_000, vec![(0, 4_000_000)]));
    assert_eq!(chunks(19_999_999, CHUNK).1.len(), 1);
    let (size, r) = chunks(4_000_000_000, CHUNK);
    assert_eq!((size, r.len()), (CHUNK, 400));
    let (size, r) = chunks(25_000_000, CHUNK);
    assert_eq!((size, r), (CHUNK, vec![(0, CHUNK), (CHUNK, 25_000_000)]));
  }

  #[tokio::test]
  async fn tiktok_video_uploads_exact_chunks_directly() {
    let (base, log) = fake(default_fake(vec![status("PROCESSING_UPLOAD"), complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(
      &up,
      dir.path(),
      "a.mp4",
      &picked("PUBLIC_TO_EVERYONE"),
      None,
    )
    .await
    .unwrap();
    assert!(p.verified);
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://www.tiktok.com/@artist/video/7300")
    );
    let l = log.lock().unwrap();
    assert_eq!(
      l.inits,
      [json!({
        "post_info":{"title":"Mapped caption #sunset","privacy_level":"PUBLIC_TO_EVERYONE",
          "disable_comment":true,"disable_duet":false,"disable_stitch":true,
          "brand_organic_toggle":true,"brand_content_toggle":false},
        "source_info":{"source":"FILE_UPLOAD","video_size":10,"chunk_size":4,"total_chunk_count":2}
      })]
    );
    assert_eq!(
      l.puts,
      [
        ("bytes 0-3/10".to_string(), b"0123".to_vec()),
        ("bytes 4-9/10".to_string(), b"456789".to_vec())
      ]
    );
  }

  #[tokio::test]
  async fn tiktok_status_pending_failed_private_and_complete_stay_distinct() {
    let failed = json!({"data":{"status":"FAILED","fail_reason":"file_format_check_failed"},"error":{"code":"ok"}});
    let private = status("PUBLISH_COMPLETE");
    for (answer, want) in [
      (status("PROCESSING_DOWNLOAD"), "pending"),
      (failed, "failed"),
      (private, "private"),
      (complete(), "complete"),
    ] {
      let (base, log) = fake(default_fake(vec![answer])).await;
      let dir = tempfile::tempdir().unwrap();
      let (up, _) = setup(&base, dir.path(), later());
      let r = run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None).await;
      match want {
        "pending" => {
          let p = r.unwrap();
          assert!(!p.verified && p.note.unwrap().contains("still processing"));
          assert_eq!(log.lock().unwrap().statuses, STATUS_TRIES);
        }
        "failed" => {
          let e = r.unwrap_err();
          assert_eq!(e.code, "uploadRejected");
          assert_eq!(e.verbatim.as_deref(), Some("file_format_check_failed"));
          assert!(e.message.contains("Nothing was published"));
        }
        "private" => {
          let p = r.unwrap();
          assert!(!p.verified && p.dest_url.is_none());
          assert!(p
            .note
            .unwrap()
            .contains("private or still in TikTok's review"));
        }
        _ => assert!(r.unwrap().verified),
      }
    }
  }

  #[tokio::test]
  async fn tiktok_unknown_publish_id_never_reinitializes() {
    let (base, log) = fake(default_fake(vec![Value::Null, complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let first = run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
      .await
      .unwrap();
    assert!(!first.verified);
    assert!(first
      .note
      .unwrap()
      .contains("Check TikTok before posting it again"));
    let again = run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
      .await
      .unwrap();
    assert!(again.verified, "the saved publish ID is followed");
    let l = log.lock().unwrap();
    assert_eq!(l.inits.len(), 1, "never a second post");
    assert_eq!(l.puts.len(), 2);
  }

  #[tokio::test]
  async fn tiktok_stop_before_final_chunk_never_publishes() {
    let (base, log) = fake(default_fake(vec![complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let e = run(
      &up,
      dir.path(),
      "a.mp4",
      &picked("SELF_ONLY"),
      Some(PublishControl::new(rx)),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "stopped");
    assert_eq!(
      log.lock().unwrap().puts.len(),
      1,
      "the final chunk never left"
    );
    // An unfinished upload never shows on TikTok, so a later hop starts fresh.
    assert!(
      run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().inits.len(), 2);
  }

  #[tokio::test]
  async fn tiktok_photos_wait_before_any_call() {
    let (base, log) = fake(default_fake(vec![complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let e = run(&up, dir.path(), "a.jpg", &picked("SELF_ONLY"), None)
      .await
      .unwrap_err();
    assert_eq!(e.code, "notSupported");
    assert!(e.message.contains("photo posts are not ready yet"));
    assert!(log.lock().unwrap().calls.is_empty());
  }

  #[tokio::test]
  async fn tiktok_refreshes_through_the_relay_and_keeps_the_rotated_token_in_keychain() {
    let (base, log) = fake(default_fake(vec![complete()])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, store) = setup(&base, dir.path(), crate::pacing::now_ms() + 60000);
    assert!(
      run(&up, dir.path(), "a.mp4", &picked("SELF_ONLY"), None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().refreshes, 1);
    let s = store.secret("tiktok-1").unwrap();
    assert_eq!(s["refreshToken"], "r2");
    assert!(s["refreshExpiresAt"].as_i64().unwrap() > crate::pacing::now_ms());
  }

  #[tokio::test]
  async fn tiktok_connect_requires_the_posting_scope_and_names_the_account() {
    let (base, _) = fake(default_fake(vec![complete()])).await;
    let http = reqwest::Client::new();
    let tokens = json!({"open_id":"open-1","scope":"user.info.basic","access_token":"t","expires_in":86400,"refresh_token":"r"});
    let e = connect(&http, &ep(&base), &tokens).await.unwrap_err();
    assert_eq!(e.code, "signInRequired");
    let mut ok = tokens.clone();
    ok["scope"] = json!("user.info.basic,video.publish");
    let (label, secret) = connect(&http, &ep(&base), &ok).await.unwrap();
    assert_eq!(label, "@artist");
    assert_eq!(secret["openId"], "open-1");
    assert_eq!(secret["refreshToken"], "r");
  }

  #[tokio::test]
  async fn tiktok_refusals_free_the_item_and_other_answers_never_repeat() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let mut f = default_fake(vec![status("PROCESSING_UPLOAD")]);
      f.last_chunk = Some(code);
      let (base, log) = fake(f).await;
      let dir = tempfile::tempdir().unwrap();
      let (up, _) = setup(&base, dir.path(), later());
      let first = run(&up, dir.path(), "v.mp4", &picked("SELF_ONLY"), None).await;
      if freed {
        assert!(first.is_err(), "{code} is a refusal");
      } else {
        let p = first.unwrap_or_else(|e| panic!("{code} may have posted: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check TikTok before posting it again"),
          "{code}"
        );
      }
      let again = run(&up, dir.path(), "v.mp4", &picked("SELF_ONLY"), None).await;
      let inits = log.lock().unwrap().inits.len();
      if freed {
        assert_eq!(inits, 2, "{code}: a refused upload can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(inits, 1, "{code}: never a second post");
      }
    }
  }
}

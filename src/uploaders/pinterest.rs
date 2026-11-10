//! Pinterest Pins (D-062, D-065). Photos go inline as base64; videos go through Pinterest's
//! registered media upload. Contracts: Pinterest's official OpenAPI v5.28.0
//! (`pinterest/api-description`, `v5/openapi.yaml`).
use super::{
  body_text, is_image, is_video, json_or_fail, mime_of, net, publish_answer, title_text,
  unknown_note, Endpoints, PublishAnswer,
};
use crate::{
  connections::Store,
  hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader, With},
  posted::UploadHandles,
};
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};

const P: &str = "Pinterest";
/// Unverified Pinterest limits, kept conservative until the live check (backlog).
const IMAGE_MAX: u64 = 20_000_000;
const VIDEO_MAX: u64 = 2_000_000_000;
const STATUS_TRIES: usize = 100;
/// Refresh through the relay when the 30-day access token has under a day left.
const REFRESH_WITHIN_MS: i64 = 24 * 3600000;

fn numeric(s: &str) -> bool {
  !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Boards this sign-in can pin to: the creator's own public boards. Secret and ad-only
/// (protected) boards need scopes BunnieHop does not request.
fn writable(board: &Value, username: &str) -> bool {
  board["id"].as_str().is_some_and(numeric)
    && board.pointer("/owner/username").and_then(Value::as_str) == Some(username)
    && board["privacy"].as_str().unwrap_or("PUBLIC") == "PUBLIC"
    && board["is_ads_only"] != true
}

pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
  wanted: Option<&str>,
) -> Result<(String, Value), Failure> {
  let token = tokens["access_token"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Pinterest didn't finish sign-in."))?;
  let refresh = tokens["refresh_token"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| {
      Failure::new(
        "signInRequired",
        "Pinterest did not return a renewable sign-in.",
      )
    })?;
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|n| *n > 0)
    .ok_or_else(|| {
      Failure::new(
        "signInRequired",
        "Pinterest did not return a token lifetime.",
      )
    })?;
  let me = json_or_fail(
    P,
    http
      .get(format!("{}/user_account", ep.pinterest))
      .bearer_auth(token)
      .send()
      .await,
  )
  .await?;
  let user = me["id"]
    .as_str()
    .filter(|s| numeric(s))
    .ok_or_else(|| Failure::new("signInRequired", "Pinterest did not identify this account."))?;
  let username = me["username"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Pinterest did not name this account."))?;
  let mut boards = Vec::new();
  let mut bookmark: Option<String> = None;
  loop {
    let mut req = http
      .get(format!("{}/boards", ep.pinterest))
      .bearer_auth(token)
      .query(&[("page_size", "100")]);
    if let Some(b) = bookmark.as_deref() {
      req = req.query(&[("bookmark", b)]);
    }
    let v = json_or_fail(P, req.send().await).await?;
    boards.extend(
      v["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| writable(b, username))
        .cloned(),
    );
    match v["bookmark"].as_str().filter(|s| !s.is_empty()) {
      Some(next) if bookmark.as_deref() == Some(next) || boards.len() > 2000 => {
        return Err(Failure::new(
          "signInRequired",
          "Pinterest's board list did not finish.",
        ))
      }
      Some(next) => bookmark = Some(next.to_string()),
      None => break,
    }
  }
  let board = match wanted {
    Some(w) => boards.iter().find(|b| b["id"] == w || b["name"] == w),
    None if boards.len() == 1 => boards.first(),
    None => None,
  };
  let board = board.ok_or_else(|| {
    Failure::new(
      "requiredChoiceMissing",
      if boards.is_empty() {
        "Pinterest needs a public board of your own to pin to. Create one on Pinterest, then connect again.".to_string()
      } else {
        format!(
          "Choose the Pinterest board to pin to: {}.",
          boards
            .iter()
            .filter_map(|b| b["name"].as_str())
            .collect::<Vec<_>>()
            .join(", ")
        )
      },
    )
  })?;
  let name = board["name"].as_str().unwrap_or("board");
  let now = crate::pacing::now_ms();
  Ok((
    format!("{username} · {name}"),
    json!({"userId":user,"username":username,"boardId":board["id"],"boardName":name,
      "accessToken":token,"refreshToken":refresh,"expiresAt":now+expires*1000}),
  ))
}

pub struct Pinterest {
  http: reqwest::Client,
  ep: Endpoints,
  board: String,
  store: Arc<Store>,
  connection: String,
  secret: tokio::sync::Mutex<Value>,
  handles: UploadHandles,
  poll: Duration,
}

impl Pinterest {
  pub fn new(
    http: reqwest::Client,
    store: Arc<Store>,
    connection: &str,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    let board = secret["boardId"].as_str().filter(|s| numeric(s))?;
    secret["refreshToken"].as_str()?;
    Some(Self {
      http,
      ep: ep.clone(),
      board: board.into(),
      store,
      connection: connection.into(),
      secret: tokio::sync::Mutex::new(secret.clone()),
      handles: UploadHandles::new(handles),
      poll: Duration::from_secs(3),
    })
  }

  #[cfg(test)]
  fn fast(mut self) -> Self {
    self.poll = Duration::from_millis(1);
    self
  }

  /// The current access token, renewed through the relay (which adds the app secret and
  /// keeps nothing) when it is close to expiry. A rotated refresh token is saved first.
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
        .post(format!("{}/v1/oauth/pinterest/token", self.ep.worker))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await,
    )
    .await
    .map_err(|e| {
      Failure::new(
        "tokenExpired",
        "Pinterest sign-in expired. Connect Pinterest again.",
      )
      .with(e.verbatim.unwrap_or(e.message))
    })?;
    let new = v["access_token"]
      .as_str()
      .filter(|t| !t.is_empty())
      .ok_or_else(|| Failure::new("tokenExpired", "Pinterest did not renew sign-in."))?;
    let lifetime = v["expires_in"]
      .as_i64()
      .filter(|n| *n > 0)
      .ok_or_else(|| Failure::new("tokenExpired", "Pinterest did not return a token lifetime."))?;
    let mut next = s.clone();
    next["accessToken"] = json!(new);
    next["expiresAt"] = json!(now + lifetime * 1000);
    if let Some(r) = v["refresh_token"].as_str().filter(|r| !r.is_empty()) {
      next["refreshToken"] = json!(r);
    }
    self
      .store
      .set_secret(&self.connection, &next)
      .map_err(|e| {
        Failure::new(
          "vaultUnavailable",
          "Couldn't save the renewed Pinterest sign-in.",
        )
        .with(e)
      })?;
    *s = next;
    Ok(new.to_string())
  }

  fn save(&self, key: &str, v: &Value) -> Result<(), Failure> {
    self.handles.save(key, v).map_err(|e| {
      Failure::new(
        "vaultUnavailable",
        "Couldn't save Pinterest's upload handle.",
      )
      .with(e)
    })
  }

  /// Registers and uploads a video, then waits until Pinterest has processed it.
  async fn video(&self, u: &Upload<'_>, token: &str) -> Result<String, Failure> {
    let reg = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/media", self.ep.pinterest))
        .bearer_auth(token)
        .json(&json!({"media_type":"video"}))
        .send()
        .await,
    )
    .await?;
    let id = reg["media_id"]
      .as_str()
      .filter(|s| numeric(s))
      .ok_or_else(|| Failure::new("uploadRejected", "Pinterest did not register the video."))?
      .to_string();
    let target = reg["upload_url"]
      .as_str()
      .and_then(|s| reqwest::Url::parse(s).ok())
      .filter(|u| {
        u.scheme() == "https" || u.as_str().starts_with(&format!("{}/", self.ep.pinterest))
      })
      .ok_or_else(|| {
        Failure::new(
          "uploadRejected",
          "Pinterest returned an unusable upload address.",
        )
      })?;
    self.save(
      u.idempotency_key,
      &json!({"kind":"video","stage":"uploading","mediaId":id}),
    )?;
    // The upload address takes a signed form: every given parameter, then the file last.
    // No Pinterest token is sent to it.
    let mut form = Form::new();
    for (k, v) in reg["upload_parameters"].as_object().into_iter().flatten() {
      let v = v
        .as_str()
        .ok_or_else(|| Failure::new("uploadRejected", "Pinterest sent an invalid upload form."))?;
      form = form.text(k.clone(), v.to_string());
    }
    let path = &u.media[0];
    let file = tokio::fs::File::open(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?;
    let len = file
      .metadata()
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
      .len();
    let part = Part::stream_with_length(reqwest::Body::from(file), len)
      .file_name("video")
      .mime_str(mime_of(path))
      .map_err(|e| net(P, e))?;
    let r = self
      .http
      .post(target)
      .multipart(form.part("file", part))
      .send()
      .await
      .map_err(|e| net(P, e))?;
    if !r.status().is_success() {
      return Err(Failure::new(
        "uploadRejected",
        format!(
          "Pinterest's upload host refused the video ({}).",
          r.status()
        ),
      ));
    }
    let mut tries = 0;
    loop {
      let m = json_or_fail(
        P,
        self
          .http
          .get(format!("{}/media/{id}", self.ep.pinterest))
          .bearer_auth(token)
          .send()
          .await,
      )
      .await?;
      tries += 1;
      if m["media_id"] != id.as_str() {
        return Err(Failure::new(
          "uploadRejected",
          "Pinterest described a different upload.",
        ));
      }
      match m["status"].as_str() {
        Some("succeeded") => return Ok(id),
        Some("registered" | "processing") if tries < STATUS_TRIES => {
          tokio::time::sleep(self.poll).await
        }
        Some("registered" | "processing") => {
          return Err(Failure::new(
            "uploadRejected",
            "Pinterest is still processing the video. Nothing was pinned; hop it again later.",
          ))
        }
        _ => {
          return Err(
            Failure::new(
              "uploadRejected",
              "Pinterest refused the video. Nothing was pinned.",
            )
            .with(m),
          )
        }
      }
    }
  }

  /// Everything before the Pin exists: returns the Pin body, after Stop was last checked.
  async fn prepare(
    &self,
    u: &Upload<'_>,
    token: &str,
    control: &PublishControl,
  ) -> Result<Value, Failure> {
    let path = &u.media[0];
    let source = if is_video(path) {
      let id = self.video(u, token).await?;
      json!({"source_type":"video_id","media_id":id,"cover_image_key_frame_time":0})
    } else {
      use base64::Engine;
      let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the photo.").with(e))?;
      json!({"source_type":"image_base64","content_type":mime_of(path),
        "data":base64::engine::general_purpose::STANDARD.encode(bytes)})
    };
    let title: String = title_text(u.post, u.item).chars().take(100).collect();
    let mut pin =
      json!({"board_id":self.board,"description":body_text(u.post, u.item),"media_source":source});
    if !title.is_empty() {
      pin["title"] = json!(title);
    }
    let kind = if is_video(path) { "video" } else { "image" };
    self.save(
      u.idempotency_key,
      &json!({"kind":kind,"stage":"publishing"}),
    )?;
    control.start_publish()?;
    Ok(pin)
  }

  async fn readback(&self, handle: &Value, token: &str) -> Published {
    let id = handle["id"].as_str().unwrap_or("").to_string();
    let mut verified = false;
    if numeric(&id) {
      if let Ok(v) = json_or_fail(
        P,
        self
          .http
          .get(format!("{}/pins/{id}", self.ep.pinterest))
          .bearer_auth(token)
          .send()
          .await,
      )
      .await
      {
        verified = v["id"] == id.as_str()
          && v["board_id"] == self.board.as_str()
          && v.pointer("/media/media_type") == Some(&handle["kind"]);
      }
    }
    Published {
      dest_url: verified.then(|| format!("https://www.pinterest.com/pin/{id}/")),
      dest_item_id: id,
      verified,
      note: (!verified).then(|| {
        "Pinterest has not confirmed this Pin. Check Pinterest before pinning again.".into()
      }),
    }
  }
}

impl Uploader for Pinterest {
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
        [p] if is_video(p) || matches!(mime_of(p), "image/jpeg" | "image/png") => p,
        [p] if is_image(p) => {
          return Err(Failure::new(
            "notSupported",
            "Pinterest takes JPEG or PNG photos.",
          ))
        }
        _ => {
          return Err(Failure::new(
            "notSupported",
            "Pinterest takes one photo or one video per Pin. Multi-photo Pins are not ready yet.",
          ))
        }
      };
      let n = tokio::fs::metadata(path)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the media.").with(e))?
        .len();
      if n == 0 || n > if is_video(path) { VIDEO_MAX } else { IMAGE_MAX } {
        return Err(Failure::new(
          "itemTooLarge",
          "This file is empty or over Pinterest's upload limit.",
        ));
      }
      if body_text(u.post, u.item).chars().count() > 800 {
        return Err(Failure::new(
          "uploadRejected",
          "Pinterest descriptions are limited to 800 characters.",
        ));
      }
      let token = self.access().await?;
      let fresh = self
        .handles
        .begin(
          u.idempotency_key,
          if is_video(path) { "video" } else { "image" },
        )
        .map_err(|e| {
          Failure::new(
            "vaultUnavailable",
            "Couldn't reserve the Pinterest upload. Nothing was sent.",
          )
          .with(e)
        })?;
      if !fresh {
        let h = self
          .handles
          .load(u.idempotency_key)
          .ok()
          .flatten()
          .unwrap_or(Value::Null);
        return Ok(self.readback(&h, &token).await);
      }
      // An uploaded video that is never pinned shows nowhere, so failures before the Pin
      // request release the reservation for a later deliberate hop.
      let pin = match self.prepare(&u, &token, &control).await {
        Ok(p) => p,
        Err(e) => {
          self.handles.release(u.idempotency_key);
          return Err(e);
        }
      };
      let kind = if is_video(path) { "video" } else { "image" };
      let result = publish_answer(
        P,
        self
          .http
          .post(format!("{}/pins", self.ep.pinterest))
          .bearer_auth(&token)
          .json(&pin)
          .send()
          .await,
      )
      .await;
      match result {
        PublishAnswer::Posted(v) => {
          let handle = json!({"kind":kind,"stage":"published","id":v["id"]});
          if self.save(u.idempotency_key, &handle).is_err() {
            return Ok(Published {
              dest_item_id: v["id"].as_str().unwrap_or("").into(),
              dest_url: None,
              verified: false,
              note: Some("Pinterest may have created this Pin, but its ID could not be saved. Check Pinterest before pinning again.".into()),
            });
          }
          Ok(self.readback(&handle, &token).await)
        }
        // A refusal (D-069): no Pin was made, so a later hop may try again.
        PublishAnswer::Refused(e) => {
          self.handles.release(u.idempotency_key);
          Err(e)
        }
        // 408, 409, 429, a server error or no answer: the Pin may exist. Never sent again (D11).
        PublishAnswer::Unknown(e) => Ok(Published {
          dest_item_id: String::new(),
          dest_url: None,
          verified: false,
          note: Some(unknown_note(P, &e, "pinning")),
        }),
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
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
  };
  use std::{collections::HashMap, sync::Mutex};

  #[derive(Default)]
  struct Log {
    registered: usize,
    uploads: usize,
    pins: Vec<Value>,
    refreshes: usize,
  }

  /// A fake Pinterest API, S3-style upload host and relay. `statuses` is what the media
  /// reports, in order; `pin_lost` makes POST /pins fail after the Pin exists.
  async fn fake(
    statuses: Vec<&'static str>,
    pin_lost: bool,
    board: &'static str,
  ) -> (String, Arc<Mutex<Log>>) {
    fake_answer(statuses, if pin_lost { Some(502) } else { None }, board).await
  }

  /// As `fake`, with POST /pins answering one row of the D-069 table (`None` creates the Pin).
  async fn fake_answer(
    statuses: Vec<&'static str>,
    pin_answer: Option<u16>,
    board: &'static str,
  ) -> (String, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let seq = Arc::new(Mutex::new(statuses.into_iter()));
    let base = Arc::new(Mutex::new(String::new()));
    let app = Router::new()
      .route("/media", post({ let log = log.clone(); let base = base.clone(); move |h: HeaderMap, Json(b): Json<Value>| {
        let log = log.clone(); let base = base.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          assert_eq!(b, json!({"media_type":"video"}));
          log.lock().unwrap().registered += 1;
          Json(json!({"media_id":"77","media_type":"video","upload_url":format!("{}/s3", base.lock().unwrap()),
            "upload_parameters":{"key":"uploads/77","policy":"p","x-amz-signature":"sig"}}))
        }
      }}))
      .route("/s3", post({ let log = log.clone(); move |h: HeaderMap, b: axum::body::Bytes| {
        let log = log.clone(); async move {
          assert!(h.get("authorization").is_none(), "no Pinterest token goes to the upload host");
          let body = String::from_utf8_lossy(&b);
          let key = body.find("name=\"key\"").unwrap();
          let file = body.find("name=\"file\"").unwrap();
          assert!(key < file, "signed fields come before the file");
          assert!(body.contains("uploads/77") && body.contains("sig") && body.contains("video-bytes"));
          log.lock().unwrap().uploads += 1;
          StatusCode::NO_CONTENT
        }
      }}))
      .route("/media/77", get(move || { let seq = seq.clone(); async move {
        Json(json!({"media_id":"77","media_type":"video","status":seq.lock().unwrap().next().unwrap_or("succeeded")}))
      } }))
      .route("/pins", post({ let log = log.clone(); move |h: HeaderMap, Json(b): Json<Value>| {
        let log = log.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          log.lock().unwrap().pins.push(b);
          match pin_answer { Some(code) => crate::uploaders::testkit::table_answer(code), None => (StatusCode::CREATED, Json(json!({"id":"9001"}))).into_response() }
        }
      }}))
      .route("/pins/9001", get({ let log = log.clone(); move || { let log = log.clone(); async move {
        let kind = log.lock().unwrap().pins.last().map(|p| if p.pointer("/media_source/source_type") == Some(&json!("video_id")) {"video"} else {"image"}).unwrap_or("image");
        Json(json!({"id":"9001","board_id":board,"media":{"media_type":kind}}))
      } } }))
      .route("/v1/oauth/pinterest/token", post({ let log = log.clone(); move |Json(b): Json<Value>| {
        let log = log.clone(); async move {
          assert_eq!(b, json!({"refresh_token":"r1"}));
          log.lock().unwrap().refreshes += 1;
          Json(json!({"access_token":"t","expires_in":2592000,"refresh_token":"r2"}))
        }
      }}));
    let url = serve(app).await;
    *base.lock().unwrap() = url.clone();
    (url, log)
  }

  fn setup(base: &str, dir: &std::path::Path, expires_at: i64) -> (Pinterest, Arc<Store>) {
    let store = Arc::new(Store::open(
      dir.join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    let secret = json!({"userId":"1","username":"artist","boardId":"55","boardName":"Art","accessToken":"t","refreshToken":"r1","expiresAt":expires_at});
    let c = store
      .save(
        Connection {
          id: "pinterest-1".into(),
          platform: "pinterest".into(),
          label: "artist · Art".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    let ep = Endpoints {
      pinterest: base.into(),
      worker: base.into(),
      ..Endpoints::default()
    };
    (
      Pinterest::new(
        reqwest::Client::new(),
        store.clone(),
        &c.id,
        &secret,
        &ep,
        dir.join("handles"),
      )
      .unwrap()
      .fast(),
      store,
    )
  }

  fn later() -> i64 {
    crate::pacing::now_ms() + 20 * 24 * 3600000
  }

  async fn run(
    up: &Pinterest,
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
    control: Option<PublishControl>,
  ) -> Result<Published, Failure> {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    let media = [p];
    let item = json!({"kind":"image","title":"Sunset"});
    let post = json!({"fields":{"body":"Mapped description"}});
    let options = json!({});
    let u = Upload {
      item: &item,
      post: Some(&post),
      media: &media,
      idempotency_key: "pin|1|src|1",
      options: &options,
    };
    match control {
      Some(c) => up.publish_controlled(u, c).await,
      None => up.publish(u).await,
    }
  }

  #[tokio::test]
  async fn pinterest_photo_goes_inline_as_base64_and_reads_back_on_its_board() {
    use base64::Engine;
    let (base, log) = fake(vec![], false, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), "a.jpg", b"jpeg-bytes", None)
      .await
      .unwrap();
    assert!(p.verified);
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://www.pinterest.com/pin/9001/")
    );
    let l = log.lock().unwrap();
    assert_eq!(
      l.registered, 0,
      "photos need no media registration or public URL"
    );
    let pin = &l.pins[0];
    assert_eq!(pin["board_id"], "55");
    assert_eq!(pin["description"], "Mapped description");
    assert_eq!(pin["media_source"]["source_type"], "image_base64");
    assert_eq!(pin["media_source"]["content_type"], "image/jpeg");
    assert_eq!(
      pin["media_source"]["data"],
      base64::engine::general_purpose::STANDARD.encode(b"jpeg-bytes")
    );
  }

  #[tokio::test]
  async fn pinterest_video_registers_uploads_and_waits_for_media() {
    let (base, log) = fake(vec!["registered", "processing", "succeeded"], false, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    assert!(
      run(&up, dir.path(), "a.mp4", b"video-bytes", None)
        .await
        .unwrap()
        .verified
    );
    let l = log.lock().unwrap();
    assert_eq!((l.registered, l.uploads, l.pins.len()), (1, 1, 1));
    assert_eq!(
      l.pins[0]["media_source"],
      json!({"source_type":"video_id","media_id":"77","cover_image_key_frame_time":0})
    );
  }

  #[tokio::test]
  async fn pinterest_failed_video_pins_nothing_and_a_later_hop_starts_fresh() {
    let (base, log) = fake(vec!["failed"], false, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let e = run(&up, dir.path(), "a.mp4", b"video-bytes", None)
      .await
      .unwrap_err();
    assert!(e.message.contains("Nothing was pinned"));
    assert!(log.lock().unwrap().pins.is_empty());
    assert!(
      run(&up, dir.path(), "a.mp4", b"video-bytes", None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().registered, 2);
  }

  #[tokio::test]
  async fn pinterest_pin_readback_checks_board_and_media() {
    let (base, _) = fake(vec![], false, "56").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), "a.png", b"png", None).await.unwrap();
    assert!(!p.verified, "a Pin on another board is not ours");
    assert!(p.dest_url.is_none());
  }

  #[tokio::test]
  async fn pinterest_timeout_never_creates_a_second_pin() {
    let (base, log) = fake(vec![], true, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), "a.jpg", b"jpeg", None).await.unwrap();
    assert!(!p.verified);
    assert!(p
      .note
      .unwrap()
      .contains("Check Pinterest before pinning again"));
    let (restarted, _) = setup(&base, dir.path(), later());
    assert!(
      !run(&restarted, dir.path(), "a.jpg", b"jpeg", None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().pins.len(), 1);
    assert!(!up.safe_to_retry());
  }

  #[tokio::test]
  async fn pinterest_stop_before_pin_never_pins() {
    let (base, log) = fake(vec!["succeeded"], false, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let e = run(
      &up,
      dir.path(),
      "a.mp4",
      b"video-bytes",
      Some(PublishControl::new(rx)),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "stopped");
    assert!(log.lock().unwrap().pins.is_empty());
  }

  #[tokio::test]
  async fn pinterest_refreshes_through_the_relay_and_keeps_the_rotated_token_in_keychain() {
    let (base, log) = fake(vec![], false, "55").await;
    let dir = tempfile::tempdir().unwrap();
    let (up, store) = setup(&base, dir.path(), crate::pacing::now_ms() + 3600000);
    assert!(
      run(&up, dir.path(), "a.jpg", b"jpeg", None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().refreshes, 1);
    let s = store.secret("pinterest-1").unwrap();
    assert_eq!(s["refreshToken"], "r2");
    assert!(s["expiresAt"].as_i64().unwrap() > crate::pacing::now_ms() + 20 * 24 * 3600000);
    assert!(!std::fs::read_to_string(dir.path().join("c.json"))
      .unwrap()
      .contains("r2"));
  }

  #[tokio::test]
  async fn pinterest_multi_photo_and_gif_wait_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup("http://127.0.0.1:9", dir.path(), later());
    let a = dir.path().join("a.jpg");
    let b = dir.path().join("b.gif");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let (item, options) = (json!({"kind":"carousel"}), json!({}));
    for media in [vec![a.clone(), a.clone()], vec![b]] {
      let e = up
        .publish(Upload {
          item: &item,
          post: None,
          media: &media,
          idempotency_key: "m",
          options: &options,
        })
        .await
        .unwrap_err();
      assert_eq!(e.code, "notSupported");
    }
  }

  async fn account(boards: Vec<Value>) -> String {
    let pages = Arc::new(Mutex::new(
      boards
        .chunks(2)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>()
        .into_iter(),
    ));
    serve(
      Router::new()
        .route("/user_account", get(|h: HeaderMap| async move {
          assert_eq!(h["authorization"], "Bearer t");
          Json(json!({"id":"1","username":"artist"}))
        }))
        .route("/boards", get(move |Query(q): Query<HashMap<String, String>>| { let pages = pages.clone(); async move {
          assert_eq!(q["page_size"], "100");
          let items = pages.lock().unwrap().next().unwrap_or_default();
          let more = items.len() == 2;
          Json(json!({"items":items,"bookmark":if more { json!(format!("b{}", q.get("bookmark").map(|s| s.len()).unwrap_or(0))) } else { Value::Null }}))
        } })),
    )
    .await
  }

  fn board(id: &str, name: &str, owner: &str, privacy: &str) -> Value {
    json!({"id":id,"name":name,"owner":{"username":owner},"privacy":privacy})
  }

  #[tokio::test]
  async fn pinterest_connect_lists_only_writable_boards() {
    let http = reqwest::Client::new();
    let tokens = json!({"access_token":"t","refresh_token":"r","expires_in":2592000});
    let base = account(vec![
      board("50", "Group", "someone", "PUBLIC"),
      board("51", "Secret", "artist", "SECRET"),
      board("55", "Art", "artist", "PUBLIC"),
    ])
    .await;
    let ep = Endpoints {
      pinterest: base,
      ..Endpoints::default()
    };
    let (label, s) = connect(&http, &ep, &tokens, None).await.unwrap();
    assert_eq!(label, "artist · Art");
    assert_eq!(
      (s["boardId"].as_str(), s["refreshToken"].as_str()),
      (Some("55"), Some("r"))
    );
    let base = account(vec![
      board("55", "Art", "artist", "PUBLIC"),
      board("56", "Food", "artist", "PUBLIC"),
    ])
    .await;
    let ep = Endpoints {
      pinterest: base,
      ..Endpoints::default()
    };
    let e = connect(&http, &ep, &tokens, None).await.unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    assert!(e.message.contains("Art") && e.message.contains("Food"));
    let base = account(vec![
      board("55", "Art", "artist", "PUBLIC"),
      board("56", "Food", "artist", "PUBLIC"),
    ])
    .await;
    let ep = Endpoints {
      pinterest: base,
      ..Endpoints::default()
    };
    assert_eq!(
      connect(&http, &ep, &tokens, Some("Food")).await.unwrap().1["boardId"],
      "56"
    );
    let none = json!({"access_token":"t","expires_in":2592000});
    assert_eq!(
      connect(&http, &ep, &none, None).await.unwrap_err().code,
      "signInRequired"
    );
  }

  #[tokio::test]
  async fn pinterest_refusals_free_the_item_and_other_answers_never_repeat() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let (base, log) = fake_answer(vec![], Some(code), "55").await;
      let dir = tempfile::tempdir().unwrap();
      let (up, _) = setup(&base, dir.path(), later());
      let first = run(&up, dir.path(), "a.jpg", b"jpeg", None).await;
      if freed {
        assert!(first.is_err(), "{code} is a refusal");
      } else {
        let p = first.unwrap_or_else(|e| panic!("{code} may have pinned: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check Pinterest before pinning again"),
          "{code}"
        );
      }
      let again = run(&up, dir.path(), "a.jpg", b"jpeg", None).await;
      let pins = log.lock().unwrap().pins.len();
      if freed {
        assert_eq!(pins, 2, "{code}: a refused Pin can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(pins, 1, "{code}: never a second Pin");
      }
    }
  }
}

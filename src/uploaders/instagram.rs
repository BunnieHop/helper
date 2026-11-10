//! Instagram Reels through Facebook Login (D-062, D-064). The file goes straight from this
//! computer to Instagram's resumable upload host; no public URL or staging copy exists.
//! Calls follow Meta's official sample `fbsamples/reels_publishing_apis` (insta sample v3.0.0).
use super::{body_text, is_video, json_or_fail, publish_answer, Endpoints, PublishAnswer};
use crate::hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader, With};
use crate::posted::UploadHandles;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const P: &str = "Instagram";
/// Meta's Reels specification: 1 GB per file.
const MAX_BYTES: u64 = 1_000_000_000;
const CAPTION_MAX: usize = 2200;
/// Polls of the container while Instagram processes the video (about five minutes).
const STATUS_TRIES: usize = 100;

fn ig_id_ok(s: &str) -> bool {
  !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Finds the professional Instagram accounts linked to the creator's Pages, picks one and
/// proves it may publish (`content_publishing_limit`) before reporting Connected (D12).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
  wanted: Option<&str>,
) -> Result<(String, Value), Failure> {
  let token = tokens["access_token"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Instagram didn't finish sign-in."))?;
  let mut accounts: Vec<Value> = Vec::new();
  let mut after: Option<String> = None;
  loop {
    let mut req = http
      .get(format!("{}/me/accounts", ep.facebook))
      .bearer_auth(token)
      .query(&[
        ("fields", "id,name,instagram_business_account{id,username}"),
        ("limit", "100"),
      ]);
    if let Some(cursor) = after.as_deref() {
      req = req.query(&[("after", cursor)]);
    }
    let v = json_or_fail(P, req.send().await).await?;
    for page in v["data"].as_array().into_iter().flatten() {
      let ig = &page["instagram_business_account"];
      if ig["id"].as_str().is_some_and(ig_id_ok)
        && ig["username"].as_str().is_some_and(|s| !s.is_empty())
        && !accounts.iter().any(|a| a["id"] == ig["id"])
      {
        accounts.push(ig.clone());
      }
    }
    if v.pointer("/paging/next").is_none() {
      break;
    }
    let next = v
      .pointer("/paging/cursors/after")
      .and_then(Value::as_str)
      .filter(|s| !s.is_empty())
      .ok_or_else(|| {
        Failure::new(
          "signInRequired",
          "Facebook returned an incomplete Page list.",
        )
      })?;
    if after.as_deref() == Some(next) || accounts.len() > 1000 {
      return Err(Failure::new(
        "signInRequired",
        "Facebook's Page list did not finish.",
      ));
    }
    after = Some(next.to_string());
  }
  let account = if let Some(id) = wanted {
    accounts.iter().find(|a| a["id"] == id)
  } else if accounts.len() == 1 {
    accounts.first()
  } else {
    None
  };
  let account = account.ok_or_else(|| {
    Failure::new(
      "requiredChoiceMissing",
      if accounts.is_empty() {
        "Instagram needs a professional (Business or Creator) account linked to a Facebook Page you manage. Switch the account to professional and link it to a Page in Instagram, then connect again.".to_string()
      } else {
        format!(
          "Several Instagram accounts were allowed. Allow only the one you want on Facebook's approve screen: {}.",
          accounts
            .iter()
            .filter_map(|a| a["username"].as_str())
            .map(|u| format!("@{u}"))
            .collect::<Vec<_>>()
            .join(", ")
        )
      },
    )
  })?;
  let id = account["id"].as_str().unwrap_or_default();
  let username = account["username"].as_str().unwrap_or_default();
  json_or_fail(
    P,
    http
      .get(format!("{}/{id}/content_publishing_limit", ep.facebook))
      .bearer_auth(token)
      .send()
      .await,
  )
  .await
  .map_err(|e| {
    Failure::new(
      "signInRequired",
      format!("@{username} can't publish through Instagram's API yet. Check that it is a professional account, then connect again."),
    )
    .with(e.verbatim.unwrap_or(e.message))
  })?;
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|s| *s > 0)
    .unwrap_or(60 * 24 * 3600);
  Ok((
    format!("@{username}"),
    json!({"userId":id,"username":username,"accessToken":token,"expiresAt":crate::pacing::now_ms()+expires*1000}),
  ))
}

pub struct Instagram {
  http: reqwest::Client,
  ep: Endpoints,
  user: String,
  token: String,
  expires: i64,
  handles: UploadHandles,
  poll: Duration,
}

impl Instagram {
  pub fn new(
    http: reqwest::Client,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    let user = secret["userId"].as_str().filter(|s| ig_id_ok(s))?;
    Some(Self {
      http,
      ep: ep.clone(),
      user: user.into(),
      token: secret["accessToken"].as_str()?.into(),
      expires: secret["expiresAt"].as_i64().unwrap_or(i64::MAX),
      handles: UploadHandles::new(handles),
      poll: Duration::from_secs(3),
    })
  }

  #[cfg(test)]
  fn fast(mut self) -> Self {
    self.poll = Duration::from_millis(1);
    self
  }

  fn save(&self, key: &str, v: &Value) -> Result<(), Failure> {
    self.handles.save(key, v).map_err(|e| {
      Failure::new(
        "vaultUnavailable",
        "Couldn't save Instagram's upload handle.",
      )
      .with(e)
    })
  }

  async fn container_status(&self, cid: &str) -> Result<Value, Failure> {
    json_or_fail(
      P,
      self
        .http
        .get(format!(
          "{}/{}",
          self.ep.facebook,
          super::ghost::urlencode(cid)
        ))
        .bearer_auth(&self.token)
        .query(&[("fields", "id,status_code,status")])
        .send()
        .await,
    )
    .await
  }

  /// Container, direct upload and processing. Returns the handle at stage "publishing",
  /// after Stop was last checked. Nothing here can make a Reel go live.
  async fn prepare(
    &self,
    u: &Upload<'_>,
    caption: &str,
    control: &PublishControl,
  ) -> Result<Value, Failure> {
    let path = &u.media[0];
    let len = tokio::fs::metadata(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
      .len();
    let container = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/{}/media", self.ep.facebook, self.user))
        .bearer_auth(&self.token)
        .form(&[
          ("media_type", "REELS"),
          ("upload_type", "resumable"),
          ("caption", caption),
        ])
        .send()
        .await,
    )
    .await?;
    let cid = container["id"]
      .as_str()
      .filter(|s| ig_id_ok(s))
      .ok_or_else(|| Failure::new("uploadRejected", "Instagram did not return a container ID."))?;
    // The token goes only to Instagram's own upload host.
    let target = container["uri"]
      .as_str()
      .and_then(|s| reqwest::Url::parse(s).ok())
      .filter(|u| {
        u.as_str()
          .starts_with(&format!("{}/", self.ep.instagram_upload))
          && u.query().is_none()
          && u.fragment().is_none()
      })
      .ok_or_else(|| {
        Failure::new(
          "uploadRejected",
          "Instagram returned an unexpected upload address. Nothing was sent.",
        )
      })?;
    let mut handle = json!({"kind":"reel","stage":"container","container":cid});
    self.save(u.idempotency_key, &handle)?;
    let file = tokio::fs::File::open(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?;
    json_or_fail(
      P,
      self
        .http
        .post(target)
        .header("authorization", format!("OAuth {}", self.token))
        .header("offset", "0")
        .header("file_size", len.to_string())
        .header("content-length", len.to_string())
        .body(reqwest::Body::from(file))
        .send()
        .await,
    )
    .await?;
    handle["stage"] = json!("processing");
    self.save(u.idempotency_key, &handle)?;
    let mut tries = 0;
    loop {
      let status = self.container_status(cid).await?;
      tries += 1;
      if status["id"] != cid {
        return Err(
          Failure::new("uploadRejected", "Instagram described a different upload.").with(status),
        );
      }
      match status["status_code"].as_str() {
        Some("FINISHED") => break,
        Some("IN_PROGRESS") if tries < STATUS_TRIES => tokio::time::sleep(self.poll).await,
        Some("IN_PROGRESS") => {
          return Err(Failure::new(
            "uploadRejected",
            "Instagram is still processing the video. Nothing was published; hop it again later.",
          ))
        }
        Some("EXPIRED") => {
          return Err(Failure::new(
            "uploadRejected",
            "Instagram's upload expired before publishing. Nothing was published.",
          ))
        }
        _ => {
          return Err(
            Failure::new(
              "uploadRejected",
              "Instagram refused the video. Nothing was published.",
            )
            .with(status),
          )
        }
      }
    }
    handle["stage"] = json!("publishing");
    self.save(u.idempotency_key, &handle)?;
    control.start_publish()?;
    Ok(handle)
  }

  async fn readback(&self, handle: &Value) -> Published {
    let id = handle["id"].as_str().unwrap_or("").to_string();
    let mut verified = false;
    let mut url = None;
    if !id.is_empty() {
      if let Ok(v) = json_or_fail(
        P,
        self
          .http
          .get(format!(
            "{}/{}",
            self.ep.facebook,
            super::ghost::urlencode(&id)
          ))
          .bearer_auth(&self.token)
          .query(&[("fields", "id,owner,media_type,media_product_type,permalink")])
          .send()
          .await,
      )
      .await
      {
        verified = v["id"] == id.as_str()
          && v.pointer("/owner/id").and_then(Value::as_str) == Some(self.user.as_str())
          && v["media_product_type"] == "REELS"
          && v["media_type"] == "VIDEO";
        if verified {
          url = v["permalink"]
            .as_str()
            .and_then(|s| reqwest::Url::parse(s).ok())
            .filter(|u| {
              u.scheme() == "https"
                && matches!(u.host_str(), Some("www.instagram.com" | "instagram.com"))
            })
            .map(|u| u.to_string());
        }
      }
    }
    Published {
      dest_item_id: id,
      dest_url: url,
      verified,
      note: (!verified).then(|| {
        "Instagram has not confirmed this Reel. Check Instagram before posting again.".into()
      }),
    }
  }
}

impl Uploader for Instagram {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    self.publish_controlled(u, PublishControl::new(tokio::sync::watch::channel(false).1))
  }

  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      if crate::pacing::now_ms() >= self.expires {
        return Err(Failure::new(
          "tokenExpired",
          "Connect Instagram again to renew this sign-in.",
        ));
      }
      if u.media.len() != 1
        || !is_video(&u.media[0])
        || matches!(u.item["kind"].as_str(), Some("image" | "carousel"))
      {
        return Err(Failure::new(
          "notSupported",
          "Instagram photos are not ready yet. Videos can hop as Reels now.",
        ));
      }
      let n = tokio::fs::metadata(&u.media[0])
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
        .len();
      if n == 0 || n > MAX_BYTES {
        return Err(Failure::new(
          "itemTooLarge",
          "This video is empty or over Instagram's 1 GB Reel limit.",
        ));
      }
      let caption = body_text(u.post, u.item);
      if caption.chars().count() > CAPTION_MAX {
        return Err(Failure::new(
          "uploadRejected",
          "Instagram captions are limited to 2,200 characters.",
        ));
      }
      let fresh = self.handles.begin(u.idempotency_key, "reel").map_err(|e| {
        Failure::new(
          "vaultUnavailable",
          "Couldn't reserve the Instagram upload. Nothing was sent.",
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
        return Ok(self.readback(&h).await);
      }
      // An unpublished container never goes live by itself and expires after a day, so a
      // failure before media_publish releases the reservation for a later deliberate hop.
      let mut handle = match self.prepare(&u, &caption, &control).await {
        Ok(h) => h,
        Err(e) => {
          self.handles.release(u.idempotency_key);
          return Err(e);
        }
      };
      let cid = handle["container"].as_str().unwrap_or("").to_string();
      let result = publish_answer(
        P,
        self
          .http
          .post(format!("{}/{}/media_publish", self.ep.facebook, self.user))
          .bearer_auth(&self.token)
          .form(&[("creation_id", cid.as_str())])
          .send()
          .await,
      )
      .await;
      let refused = matches!(result, PublishAnswer::Refused(_));
      match result {
        PublishAnswer::Posted(v) => {
          handle["id"] = v["id"].clone();
          handle["stage"] = json!("published");
          if self.save(u.idempotency_key, &handle).is_err() {
            return Ok(Published {
              dest_item_id: v["id"].as_str().unwrap_or("").into(),
              dest_url: None,
              verified: false,
              note: Some("Instagram may have published this Reel, but its ID could not be saved. Check Instagram before posting again.".into()),
            });
          }
          Ok(self.readback(&handle).await)
        }
        PublishAnswer::Refused(e) | PublishAnswer::Unknown(e) => {
          // Never publish again. The container says whether the request went through.
          let went = self
            .container_status(&cid)
            .await
            .is_ok_and(|s| s["status_code"] == "PUBLISHED");
          // A refusal (D-069) whose container never went live frees the item for a later hop.
          if refused && !went {
            self.handles.release(u.idempotency_key);
            return Err(e);
          }
          let mut note = if went {
            "Instagram says this Reel was published but did not return it. Check Instagram before posting again.".to_string()
          } else {
            format!("{} Check Instagram before posting again.", e.message)
          };
          if let Some(v) = e.verbatim {
            note.push('\n');
            note.push_str(&v);
          }
          Ok(Published {
            dest_item_id: String::new(),
            dest_url: None,
            verified: false,
            note: Some(note),
          })
        }
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::{
    extract::Form,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
  };
  use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
  };

  #[derive(Default)]
  struct Log {
    containers: usize,
    uploads: usize,
    publishes: usize,
    bytes: Vec<u8>,
  }

  /// A fake Graph + rupload host. `statuses` is what the container reports, in order;
  /// `publish_lost` makes media_publish fail after it went through.
  async fn fake(
    statuses: Vec<&'static str>,
    publish_lost: bool,
    upload_host: Option<String>,
  ) -> (String, Arc<Mutex<Log>>) {
    let answer = if publish_lost { Some(502) } else { None };
    fake_answer(statuses, answer, true, upload_host).await
  }

  /// As `fake`, with media_publish answering one row of the D-069 table (`None` publishes).
  /// `went` says whether the container reads PUBLISHED afterwards.
  async fn fake_answer(
    statuses: Vec<&'static str>,
    answer: Option<u16>,
    went: bool,
    upload_host: Option<String>,
  ) -> (String, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let seq = Arc::new(Mutex::new(statuses.into_iter()));
    let published = Arc::new(Mutex::new(false));
    let base = Arc::new(Mutex::new(String::new()));
    let app = Router::new()
      .route("/1784/media", post({ let log = log.clone(); let base = base.clone(); let upload_host = upload_host.clone(); move |h: HeaderMap, Form(f): Form<HashMap<String, String>>| {
        let log = log.clone(); let base = base.clone(); let upload_host = upload_host.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          assert_eq!(f["media_type"], "REELS");
          assert_eq!(f["upload_type"], "resumable");
          assert_eq!(f["caption"], "Mapped caption");
          assert!(!f.contains_key("video_url"), "no public URL is ever sent");
          log.lock().unwrap().containers += 1;
          let host = upload_host.unwrap_or_else(|| base.lock().unwrap().clone());
          Json(json!({"id":"555","uri":format!("{host}/ig-api-upload/v24.0/555")}))
        }
      }}))
      .route("/ig-api-upload/v24.0/555", post({ let log = log.clone(); move |h: HeaderMap, b: axum::body::Bytes| {
        let log = log.clone(); async move {
          assert_eq!(h["authorization"], "OAuth t");
          assert_eq!(h["offset"], "0");
          assert_eq!(h["file_size"], b.len().to_string().as_str());
          let mut l = log.lock().unwrap();
          l.uploads += 1;
          l.bytes = b.to_vec();
          Json(json!({"success":true,"message":"Upload successful."}))
        }
      }}))
      .route("/555", get({ let published = published.clone(); move || { let seq = seq.clone(); let published = published.clone(); async move {
        let s = if *published.lock().unwrap() { "PUBLISHED" } else { seq.lock().unwrap().next().unwrap_or("FINISHED") };
        Json(json!({"id":"555","status_code":s}))
      } } }))
      .route("/1784/media_publish", post({ let log = log.clone(); move |Form(f): Form<HashMap<String, String>>| {
        let log = log.clone(); let published = published.clone(); async move {
          assert_eq!(f["creation_id"], "555");
          log.lock().unwrap().publishes += 1;
          *published.lock().unwrap() = went;
          match answer { Some(code) => crate::uploaders::testkit::table_answer(code), None => (StatusCode::OK, Json(json!({"id":"9001"}))).into_response() }
        }
      }}))
      .route("/9001", get(|| async {
        Json(json!({"id":"9001","owner":{"id":"1784"},"media_type":"VIDEO","media_product_type":"REELS","permalink":"https://www.instagram.com/reel/abc/"}))
      }));
    let url = serve(app).await;
    *base.lock().unwrap() = url.clone();
    (url, log)
  }

  fn uploader(base: &str, dir: &std::path::Path) -> Instagram {
    Instagram::new(
      reqwest::Client::new(),
      &json!({"userId":"1784","username":"artist","accessToken":"t"}),
      &Endpoints {
        facebook: base.into(),
        instagram_upload: base.into(),
        ..Endpoints::default()
      },
      dir.join("handles"),
    )
    .unwrap()
    .fast()
  }

  async fn run(
    up: &Instagram,
    dir: &std::path::Path,
    control: Option<PublishControl>,
  ) -> Result<Published, Failure> {
    let video = dir.join("clip.mp4");
    std::fs::write(&video, b"reel-bytes").unwrap();
    let media = [video];
    let item = json!({"kind":"short"});
    let post = json!({"fields":{"body":"Mapped caption"}});
    let options = json!({});
    let u = Upload {
      item: &item,
      post: Some(&post),
      media: &media,
      idempotency_key: "ig|1784|src|1",
      options: &options,
    };
    match control {
      Some(c) => up.publish_controlled(u, c).await,
      None => up.publish(u).await,
    }
  }

  #[tokio::test]
  async fn instagram_reel_uploads_the_file_directly_and_waits_for_ingestion() {
    let (base, log) = fake(vec!["IN_PROGRESS", "IN_PROGRESS", "FINISHED"], false, None).await;
    let dir = tempfile::tempdir().unwrap();
    let up = uploader(&base, dir.path());
    let p = run(&up, dir.path(), None).await.unwrap();
    assert!(p.verified);
    assert_eq!(p.dest_item_id, "9001");
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://www.instagram.com/reel/abc/")
    );
    let l = log.lock().unwrap();
    assert_eq!((l.containers, l.uploads, l.publishes), (1, 1, 1));
    assert_eq!(l.bytes, b"reel-bytes");
    assert!(!up.safe_to_retry());
  }

  #[tokio::test]
  async fn instagram_publish_timeout_reads_back_without_republishing() {
    let (base, log) = fake(vec!["FINISHED"], true, None).await;
    let dir = tempfile::tempdir().unwrap();
    let p = run(&uploader(&base, dir.path()), dir.path(), None)
      .await
      .unwrap();
    assert!(!p.verified);
    assert!(p.note.unwrap().contains("says this Reel was published"));
    // A restarted Helper hops the same item: read-back only, never a second publish.
    let again = run(&uploader(&base, dir.path()), dir.path(), None)
      .await
      .unwrap();
    assert!(!again.verified);
    let l = log.lock().unwrap();
    assert_eq!((l.containers, l.uploads, l.publishes), (1, 1, 1));
  }

  #[tokio::test]
  async fn instagram_expired_container_is_not_published() {
    let (base, log) = fake(vec!["IN_PROGRESS", "EXPIRED"], false, None).await;
    let dir = tempfile::tempdir().unwrap();
    let e = run(&uploader(&base, dir.path()), dir.path(), None)
      .await
      .unwrap_err();
    assert_eq!(e.code, "uploadRejected");
    assert!(e.message.contains("expired"));
    assert_eq!(log.lock().unwrap().publishes, 0);
    // Nothing went live, so a later deliberate hop starts over.
    assert!(
      run(&uploader(&base, dir.path()), dir.path(), None)
        .await
        .unwrap()
        .verified
    );
    let l = log.lock().unwrap();
    assert_eq!((l.containers, l.publishes), (2, 1));
  }

  #[tokio::test]
  async fn instagram_stop_before_publish_never_publishes() {
    let (base, log) = fake(vec!["FINISHED"], false, None).await;
    let dir = tempfile::tempdir().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let e = run(
      &uploader(&base, dir.path()),
      dir.path(),
      Some(PublishControl::new(rx)),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "stopped");
    assert_eq!(log.lock().unwrap().publishes, 0);
  }

  #[tokio::test]
  async fn instagram_refuses_an_upload_address_off_its_upload_host() {
    let (base, log) = fake(
      vec!["FINISHED"],
      false,
      Some("https://elsewhere.example".into()),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let e = run(&uploader(&base, dir.path()), dir.path(), None)
      .await
      .unwrap_err();
    assert!(e.message.contains("unexpected upload address"));
    let l = log.lock().unwrap();
    assert_eq!((l.uploads, l.publishes), (0, 0));
  }

  #[tokio::test]
  async fn instagram_photos_wait_as_not_yet_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let up = uploader("http://127.0.0.1:9", dir.path());
    let photo = dir.path().join("a.jpg");
    std::fs::write(&photo, b"x").unwrap();
    let media = [photo];
    let item = json!({"kind":"image"});
    let options = json!({});
    let e = up
      .publish(Upload {
        item: &item,
        post: None,
        media: &media,
        idempotency_key: "p",
        options: &options,
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "notSupported");
    assert!(e.message.contains("not ready yet"));
  }

  async fn pages(body: Value, limit_ok: bool) -> String {
    serve(
      Router::new()
        .route(
          "/me/accounts",
          get(move |h: HeaderMap| {
            let body = body.clone();
            async move {
              assert_eq!(h["authorization"], "Bearer long");
              Json(body)
            }
          }),
        )
        .route(
          "/{id}/content_publishing_limit",
          get(move || async move {
            if limit_ok {
              (StatusCode::OK, Json(json!({"data":[{"quota_usage":0}]})))
            } else {
              (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":{"message":"(#10) Application does not have permission"}})),
              )
            }
          }),
        ),
    )
    .await
  }

  #[tokio::test]
  async fn instagram_connect_rejects_nonprofessional_accounts() {
    let http = reqwest::Client::new();
    let tokens = json!({"access_token":"long","expires_in":5184000});
    // A Page with no linked professional account offers nothing to connect.
    let base = pages(json!({"data":[{"id":"12","name":"Art"}]}), true).await;
    let e = connect(
      &http,
      &Endpoints {
        facebook: base,
        ..Endpoints::default()
      },
      &tokens,
      None,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    assert!(e.message.contains("professional"));
    // A linked account without publishing access is not reported Connected (D12).
    let base = pages(
      json!({"data":[{"id":"12","instagram_business_account":{"id":"1784","username":"artist"}}]}),
      false,
    )
    .await;
    let e = connect(
      &http,
      &Endpoints {
        facebook: base,
        ..Endpoints::default()
      },
      &tokens,
      None,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "signInRequired");
    assert!(e.verbatim.unwrap().contains("(#10)"));
    let base = pages(
      json!({"data":[{"id":"12","instagram_business_account":{"id":"1784","username":"artist"}}]}),
      true,
    )
    .await;
    let (label, secret) = connect(
      &http,
      &Endpoints {
        facebook: base,
        ..Endpoints::default()
      },
      &tokens,
      None,
    )
    .await
    .unwrap();
    assert_eq!(label, "@artist");
    assert_eq!(secret["userId"], "1784");
    assert_eq!(secret["accessToken"], "long");
  }

  #[tokio::test]
  async fn instagram_connect_never_silently_picks_between_accounts() {
    let http = reqwest::Client::new();
    let tokens = json!({"access_token":"long"});
    let base = pages(
      json!({"data":[
        {"id":"12","instagram_business_account":{"id":"1784","username":"art"}},
        {"id":"13","instagram_business_account":{"id":"1785","username":"music"}}
      ]}),
      true,
    )
    .await;
    let ep = Endpoints {
      facebook: base,
      ..Endpoints::default()
    };
    let e = connect(&http, &ep, &tokens, None).await.unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    assert!(e.message.contains("@art") && e.message.contains("@music"));
    let (_, s) = connect(&http, &ep, &tokens, Some("1785")).await.unwrap();
    assert_eq!(s["userId"], "1785");
  }

  #[tokio::test]
  async fn instagram_refusals_free_the_item_and_other_answers_never_repeat() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let (base, log) = fake_answer(vec!["FINISHED"], Some(code), false, None).await;
      let dir = tempfile::tempdir().unwrap();
      let up = uploader(&base, dir.path());
      let first = run(&up, dir.path(), None).await;
      if freed {
        assert!(first.is_err(), "{code} is a refusal");
      } else {
        let p = first.unwrap_or_else(|e| panic!("{code} may have published: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check Instagram before posting again"),
          "{code}"
        );
      }
      let again = run(&up, dir.path(), None).await;
      let publishes = log.lock().unwrap().publishes;
      if freed {
        assert_eq!(publishes, 2, "{code}: a refused Reel can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(publishes, 1, "{code}: never a second publish");
      }
    }
    // A refusal whose container nevertheless reads PUBLISHED is never freed.
    let (base, log) = fake_answer(vec!["FINISHED"], Some(400), true, None).await;
    let dir = tempfile::tempdir().unwrap();
    let up = uploader(&base, dir.path());
    assert!(!run(&up, dir.path(), None).await.unwrap().verified);
    assert!(!run(&up, dir.path(), None).await.unwrap().verified);
    assert_eq!(log.lock().unwrap().publishes, 1);
  }
}

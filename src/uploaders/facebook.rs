//! Facebook Page uploads. Files leave this computer directly; no public staging URL.
//! See Meta's Page SDK field definitions and video upload phases linked in the progress record.
use super::{
  body_text, is_image, is_video, json_or_fail, mime_of, net, publish_answer, title_text, Endpoints,
  PublishAnswer,
};
use crate::hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader, With};
use crate::posted::UploadHandles;
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const P: &str = "Facebook";

/// Why a Page post did not finish. A refusal of the publishing request (D-069) proves nothing
/// was posted; every other failure leaves the post possibly live.
enum Step {
  Failed(Failure),
  Refused(Failure),
}

impl From<Failure> for Step {
  fn from(f: Failure) -> Self {
    Step::Failed(f)
  }
}

fn failure_note(f: &Failure) -> String {
  let mut message = format!("{} Check Facebook before posting again.", f.message);
  if let Some(verbatim) = &f.verbatim {
    message.push('\n');
    message.push_str(verbatim);
  }
  message
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
    .ok_or_else(|| Failure::new("signInRequired", "Facebook didn't finish sign-in."))?;
  let mut pages = Vec::new();
  let mut after = None;
  loop {
    let mut req = http
      .get(format!("{}/me/accounts", ep.facebook))
      .bearer_auth(token)
      .query(&[("fields", "id,name,access_token,tasks"), ("limit", "100")]);
    if let Some(cursor) = after.as_deref() {
      req = req.query(&[("after", cursor)]);
    }
    let v = json_or_fail(P, req.send().await).await?;
    for page in v["data"].as_array().into_iter().flatten() {
      if page["tasks"].as_array().is_some_and(|t| {
        t.iter()
          .any(|v| matches!(v.as_str(), Some("CREATE_CONTENT" | "MANAGE")))
      }) && page["access_token"].as_str().is_some_and(|s| !s.is_empty())
        && page["id"]
          .as_str()
          .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty())
      {
        pages.push(page.clone());
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
          "Facebook returned incomplete Page choices.",
        )
      })?;
    if after.as_deref() == Some(next) || pages.len() > 1000 {
      return Err(Failure::new(
        "signInRequired",
        "Facebook's Page list did not finish.",
      ));
    }
    after = Some(next.to_string());
  }
  let page = if let Some(id) = wanted {
    pages.iter().find(|p| p["id"] == id)
  } else if pages.len() == 1 {
    pages.first()
  } else {
    None
  };
  let page = page.ok_or_else(|| Failure::new("requiredChoiceMissing", if pages.is_empty() {
    "Facebook granted no writable Page. Connect again and allow a Page you can post to.".to_string()
  } else { format!("Facebook granted several Pages. Allow only the Page you want on Facebook's approve screen: {}.", pages.iter().filter_map(|p|p["name"].as_str()).collect::<Vec<_>>().join(", ")) }))?;
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|s| *s > 0)
    .unwrap_or(60 * 24 * 3600);
  Ok((
    page["name"].as_str().unwrap_or("Facebook Page").to_string(),
    json!({"pageId":page["id"],"accessToken":page["access_token"],"expiresAt":crate::pacing::now_ms()+expires*1000}),
  ))
}

pub struct Facebook {
  http: reqwest::Client,
  ep: Endpoints,
  page: String,
  token: String,
  expires: i64,
  handles: UploadHandles,
  poll: Duration,
}

impl Facebook {
  pub fn new(
    http: reqwest::Client,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    let page = secret["pageId"].as_str()?;
    if page.is_empty() || !page.bytes().all(|b| b.is_ascii_digit()) {
      return None;
    }
    Some(Self {
      http,
      ep: ep.clone(),
      page: page.into(),
      token: secret["accessToken"].as_str()?.into(),
      expires: secret["expiresAt"].as_i64().unwrap_or(i64::MAX),
      handles: UploadHandles::new(handles),
      poll: Duration::from_secs(5),
    })
  }

  #[cfg(test)]
  fn fast(mut self) -> Self {
    self.poll = Duration::from_millis(1);
    self
  }

  async fn send(
    &self,
    edge: &str,
    form: Form,
    video: bool,
  ) -> Result<reqwest::Response, reqwest::Error> {
    let base = if video {
      &self.ep.facebook_video
    } else {
      &self.ep.facebook
    };
    self
      .http
      .post(format!("{base}/{}/{edge}", self.page))
      .bearer_auth(&self.token)
      .multipart(form)
      .send()
      .await
  }

  async fn form(&self, edge: &str, form: Form, video: bool) -> Result<Value, Failure> {
    json_or_fail(P, self.send(edge, form, video).await).await
  }

  /// The request that makes the post live, read under D-069.
  async fn publish_form(&self, edge: &str, form: Form, video: bool) -> Result<Value, Step> {
    match publish_answer(P, self.send(edge, form, video).await).await {
      PublishAnswer::Posted(v) => Ok(v),
      PublishAnswer::Refused(e) => Err(Step::Refused(e)),
      PublishAnswer::Unknown(e) => Err(Step::Failed(e)),
    }
  }

  fn save(&self, key: &str, handle: &Value) -> Result<(), Failure> {
    self.handles.save(key, handle).map_err(|e| {
      Failure::new(
        "vaultUnavailable",
        "Couldn't save Facebook's upload handle. Check Facebook before posting again.",
      )
      .with(e)
    })
  }

  async fn photos(&self, u: &Upload<'_>, control: &PublishControl) -> Result<Value, Step> {
    let multi = u.media.len() > 1;
    let mut ids = Vec::new();
    let mut single_post = Value::Null;
    for path in u.media {
      let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the photo.").with(e))?;
      let part = Part::stream(reqwest::Body::from(file))
        .file_name("photo")
        .mime_str(mime_of(path))
        .map_err(|e| net(P, e))?;
      let mut form = Form::new()
        .text("published", if multi { "false" } else { "true" })
        .part("source", part);
      if !multi {
        form = form.text("message", body_text(u.post, u.item));
      }
      let v = if multi {
        self.form("photos", form, false).await?
      } else {
        control.start_publish()?;
        self.publish_form("photos", form, false).await?
      };
      let id = v["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Failure::new("uploadRejected", "Facebook did not return the photo ID."))?;
      ids.push(id.to_string());
      single_post = v["post_id"].clone();
      self.save(
        u.idempotency_key,
        &json!({"kind":"image","stage":"uploading","photoIds":ids,"id":single_post}),
      )?;
    }
    let post_id = if multi {
      self.save(
        u.idempotency_key,
        &json!({"kind":"image","stage":"finishing","photoIds":ids}),
      )?;
      let attached: Vec<_> = ids.iter().map(|id| json!({"media_fbid":id})).collect();
      control.start_publish()?;
      let v = self
        .publish_form(
          "feed",
          Form::new()
            .text("message", body_text(u.post, u.item))
            .text("attached_media", json!(attached).to_string()),
          false,
        )
        .await?;
      v["id"].clone()
    } else {
      single_post
    };
    Ok(json!({"kind":"image","stage":"published","id":post_id,"photoIds":ids}))
  }

  async fn video(
    &self,
    u: &Upload<'_>,
    path: &Path,
    control: &PublishControl,
  ) -> Result<Value, Step> {
    let mut file = tokio::fs::File::open(path)
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?;
    let len = file
      .metadata()
      .await
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video.").with(e))?
      .len();
    let start = self
      .form(
        "videos",
        Form::new()
          .text("upload_phase", "start")
          .text("file_size", len.to_string()),
        true,
      )
      .await?;
    let id = start["video_id"]
      .as_str()
      .ok_or_else(|| Failure::new("uploadRejected", "Facebook did not return a video ID."))?;
    let session = start["upload_session_id"].as_str().ok_or_else(|| {
      Failure::new(
        "uploadRejected",
        "Facebook did not return an upload session.",
      )
    })?;
    let mut handle = json!({"kind":"video","stage":"uploading","id":id,"session":session});
    self.save(u.idempotency_key, &handle)?;
    let mut offsets = start.clone();
    let mut previous = 0;
    loop {
      let number = |k: &str| {
        offsets[k]
          .as_str()
          .and_then(|s| s.parse::<u64>().ok())
          .or(offsets[k].as_u64())
      };
      let (first, end) = number("start_offset")
        .zip(number("end_offset"))
        .ok_or_else(|| Failure::new("uploadRejected", "Facebook sent invalid video offsets."))?;
      if first != previous || end < first || end > len || end - first > 32 * 1024 * 1024 {
        return Err(Step::Failed(Failure::new(
          "uploadRejected",
          "Facebook sent an invalid video chunk range.",
        )));
      }
      if first == end {
        if end != len {
          return Err(Step::Failed(Failure::new(
            "uploadRejected",
            "Facebook stopped the upload before the last byte.",
          )));
        }
        break;
      }
      let mut bytes = vec![0; (end - first) as usize];
      file
        .seek(std::io::SeekFrom::Start(first))
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't seek in the video.").with(e))?;
      file
        .read_exact(&mut bytes)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the video chunk.").with(e))?;
      offsets = self
        .form(
          "videos",
          Form::new()
            .text("upload_phase", "transfer")
            .text("upload_session_id", session.to_string())
            .text("start_offset", first.to_string())
            .part(
              "video_file_chunk",
              Part::bytes(bytes).file_name("chunk.mp4"),
            ),
          true,
        )
        .await?;
      previous = end;
      handle["offset"] = json!(end);
      self.save(u.idempotency_key, &handle)?;
    }
    handle["stage"] = json!("finishing");
    self.save(u.idempotency_key, &handle)?;
    // Finish publishes. A refusal frees the item (D-069); any other failed or lost answer is
    // reconciled by ID, never by repeating finish.
    control.start_publish()?;
    if let Err(Step::Refused(e)) = self
      .publish_form(
        "videos",
        Form::new()
          .text("upload_phase", "finish")
          .text("upload_session_id", session.to_string())
          .text("published", "true")
          .text("title", title_text(u.post, u.item))
          .text("description", body_text(u.post, u.item)),
        true,
      )
      .await
    {
      return Err(Step::Refused(e));
    }
    Ok(handle)
  }

  async fn readback(&self, handle: &Value) -> Published {
    let id = handle["id"].as_str().unwrap_or("").to_string();
    let video = handle["kind"] == "video";
    let fields = if video {
      "id,from,published,status,permalink_url"
    } else {
      "id,from,is_published,permalink_url,attachments{target,subattachments}"
    };
    let mut verified = false;
    let mut url = None;
    for _ in 0..6 {
      if id.is_empty() {
        break;
      }
      let r = json_or_fail(
        P,
        self
          .http
          .get(format!(
            "{}/{}",
            self.ep.facebook,
            super::ghost::urlencode(&id)
          ))
          .bearer_auth(&self.token)
          .query(&[("fields", fields)])
          .send()
          .await,
      )
      .await;
      let Ok(v) = r else {
        break;
      };
      let media_ok = if video {
        v.pointer("/status/video_status").and_then(Value::as_str) == Some("ready")
          && v["published"] == true
      } else {
        v["is_published"] == true
          && (handle["kind"] == "text"
            || handle["photoIds"].as_array().is_some_and(|ids| {
              let attachments = v
                .pointer("/attachments/data/0/subattachments/data")
                .or_else(|| v.pointer("/attachments/data"))
                .and_then(Value::as_array);
              attachments.is_some_and(|a| {
                a.len() == ids.len()
                  && ids
                    .iter()
                    .all(|id| a.iter().any(|p| p.pointer("/target/id") == Some(id)))
              })
            }))
      };
      verified = v["id"] == id
        && v.pointer("/from/id").and_then(Value::as_str) == Some(&self.page)
        && media_ok;
      if verified {
        url = v["permalink_url"].as_str().and_then(|s| {
          if s.starts_with('/') && !s.starts_with("//") {
            Some(format!("https://www.facebook.com{s}"))
          } else {
            reqwest::Url::parse(s)
              .ok()
              .filter(|u| {
                u.scheme() == "https"
                  && matches!(u.host_str(), Some("www.facebook.com" | "facebook.com"))
              })
              .map(|u| u.to_string())
          }
        });
        break;
      }
      if !video {
        break;
      }
      tokio::time::sleep(self.poll).await;
    }
    Published {
      dest_item_id: id,
      dest_url: url,
      verified,
      note: (!verified).then(|| {
        "Facebook has not confirmed this Page post. Check Facebook before posting again.".into()
      }),
    }
  }
}

impl Uploader for Facebook {
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
          "Connect Facebook again to renew this sign-in.",
        ));
      }
      if u.media.len() > 10 || (u.media.len() > 1 && u.media.iter().any(|p| !is_image(p))) {
        return Err(Failure::new(
          "notSupported",
          "Facebook takes up to ten photos or one video per post.",
        ));
      }
      for p in u.media {
        let cap = if is_video(p) {
          10_000_000_000
        } else {
          10_000_000
        };
        let n = tokio::fs::metadata(p)
          .await
          .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the media.").with(e))?
          .len();
        if n == 0 || n > cap {
          return Err(Failure::new(
            "itemTooLarge",
            "This file is empty or exceeds Facebook's upload limit.",
          ));
        }
        if !is_image(p) && !is_video(p) {
          return Err(Failure::new(
            "notSupported",
            "Facebook needs a photo or video.",
          ));
        }
      }
      let kind = if u.media.first().is_some_and(|p| is_video(p)) {
        "video"
      } else if u.media.is_empty() {
        "text"
      } else {
        "image"
      };
      let fresh = self.handles.begin(u.idempotency_key, kind).map_err(|e| {
        Failure::new(
          "vaultUnavailable",
          "Couldn't reserve the Facebook upload. Nothing was sent.",
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
      let handle = if kind == "video" {
        match self.video(&u, &u.media[0], &control).await {
          Ok(h) => h,
          Err(Step::Refused(e)) => {
            self.handles.release(u.idempotency_key);
            return Err(e);
          }
          Err(Step::Failed(e)) if e.code == "stopped" => return Err(e),
          Err(Step::Failed(e)) => {
            let h = self
              .handles
              .load(u.idempotency_key)
              .ok()
              .flatten()
              .unwrap_or(Value::Null);
            let mut p = self.readback(&h).await;
            if !p.verified {
              p.note = Some(failure_note(&e));
            }
            return Ok(p);
          }
        }
      } else {
        let result = if kind == "image" {
          self.photos(&u, &control).await
        } else {
          control.start_publish()?;
          self
            .publish_form(
              "feed",
              Form::new().text("message", body_text(u.post, u.item)),
              false,
            )
            .await
            .map(|v| json!({"kind":"text","stage":"published","id":v["id"]}))
        };
        match result {
          Ok(v) => v,
          Err(Step::Refused(e)) => {
            self.handles.release(u.idempotency_key);
            return Err(e);
          }
          Err(Step::Failed(e)) if e.code == "stopped" => return Err(e),
          Err(Step::Failed(e)) => {
            return Ok(Published {
              dest_item_id: String::new(),
              dest_url: None,
              verified: false,
              note: Some(failure_note(&e)),
            })
          }
        }
      };
      // The handle marker already prevents another mutation even if this final save fails.
      if self.save(u.idempotency_key, &handle).is_err() {
        return Ok(Published {dest_item_id:handle["id"].as_str().unwrap_or("").into(),dest_url:None,verified:false,note:Some("Facebook may have published this post, but its ID could not be saved. Check Facebook before posting again.".into())});
      }
      Ok(self.readback(&handle).await)
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::hops::{Upload, Uploader};
  use crate::uploaders::{testkit::serve, Endpoints};
  use axum::{routing::get, Json, Router};
  use serde_json::json;

  async fn publish_case(kind: &str, ready: bool, finish_ok: bool) {
    use axum::{extract::State, http::HeaderMap, routing::post};
    use std::sync::{Arc, Mutex};
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let app = Router::new()
      .route("/12/videos", post({let calls = calls.clone(); move |h: HeaderMap, b: axum::body::Bytes| {
        let calls = calls.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          let b = String::from_utf8_lossy(&b);
          if b.contains("\r\nstart\r\n") {
            calls.lock().unwrap().push("start".into());
            Json(json!({"upload_session_id":"s1","video_id":"v1","start_offset":"0","end_offset":"3"}))
          } else if b.contains("\r\ntransfer\r\n") {
            assert!(b.contains("name=\"video_file_chunk\""));
            let mut log = calls.lock().unwrap();
            let n = log.iter().filter(|x| *x == "transfer").count();
            assert!(b.contains(if n == 0 { "abc" } else { "def" }));
            log.push("transfer".into());
            Json(if n == 0 {json!({"start_offset":"3","end_offset":"6"})} else {json!({"start_offset":"6","end_offset":"6"})})
          } else {
            assert!(b.contains("\r\nfinish\r\n"));
            assert!(b.contains("Mapped caption"));
            calls.lock().unwrap().push("finish".into());
            Json(json!({"success":finish_ok}))
          }
        }
      }}))
      .route("/12/photos", post({let calls = calls.clone(); move |h: HeaderMap, b: axum::body::Bytes| {
        let calls = calls.clone(); async move {
          assert_eq!(h["authorization"], "Bearer t");
          let b = String::from_utf8_lossy(&b);
          assert!(b.contains("name=\"source\""));
          assert!(b.contains("abcdef"));
          assert!(b.contains("Mapped caption"));
          calls.lock().unwrap().push("photo".into());
          Json(json!({"id":"p1","post_id":"12_99"}))
        }
      }}))
      .route("/12_99", get(move || async move {
        Json(json!({"id":"12_99","from":{"id":"12"},"is_published":ready,"attachments":{"data":[{"target":{"id":"p1"}}]},"permalink_url":"https://www.facebook.com/12/posts/99"}))
      }))
      .route("/v1", get(move |State(log): State<Arc<Mutex<Vec<String>>>>| async move {
        log.lock().unwrap().push("read".into());
        Json(json!({"id":"v1","from":{"id":"12"},"published":ready,"status":{"video_status":if ready {"ready"} else {"processing"}},"permalink_url":"/12/videos/v1/"}))
      }))
      .with_state(calls.clone());
    let base = serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let ep = Endpoints {
      facebook: base.clone(),
      facebook_video: base,
      ..Endpoints::default()
    };
    let p = dir
      .path()
      .join(if kind == "video" { "a.mp4" } else { "a.jpg" });
    std::fs::write(&p, b"abcdef").unwrap();
    let fb = Facebook::new(
      reqwest::Client::new(),
      &json!({"pageId":"12","accessToken":"t"}),
      &ep,
      dir.path().join("handles"),
    )
    .unwrap()
    .fast();
    let item = json!({"kind":kind});
    let post = json!({"fields":{"body":"Mapped caption"}});
    let media = [p];
    let options = json!({});
    let upload = || Upload {
      item: &item,
      post: Some(&post),
      media: &media,
      idempotency_key: "fb|12|source|one",
      options: &options,
    };
    let result = fb.publish(upload()).await.unwrap();
    assert_eq!(result.verified, ready);
    assert!(!fb.safe_to_retry());
    let mutations = calls
      .lock()
      .unwrap()
      .iter()
      .filter(|x| *x != "read")
      .count();
    // A new uploader after a restart reads the durable handle; it never posts again.
    let restarted = Facebook::new(
      reqwest::Client::new(),
      &json!({"pageId":"12","accessToken":"t"}),
      &ep,
      dir.path().join("handles"),
    )
    .unwrap()
    .fast();
    assert_eq!(restarted.publish(upload()).await.unwrap().verified, ready);
    assert_eq!(
      calls
        .lock()
        .unwrap()
        .iter()
        .filter(|x| *x != "read")
        .count(),
      mutations
    );
    assert_eq!(mutations, if kind == "video" { 4 } else { 1 });
  }

  #[tokio::test]
  async fn facebook_uploads_photo_and_resumes_video_directly() {
    publish_case("image", true, true).await;
    publish_case("video", true, true).await;
  }

  #[tokio::test]
  async fn facebook_processing_and_unpublished_are_not_verified() {
    publish_case("video", false, true).await;
    publish_case("image", false, true).await;
  }

  #[tokio::test]
  async fn facebook_publish_timeout_never_duplicates_page_media() {
    publish_case("video", true, false).await;
  }

  #[tokio::test]
  async fn facebook_connect_requires_a_writable_page() {
    let base = serve(Router::new().route("/me/accounts", get(|| async {
      Json(json!({"data":[{"id":"12","name":"Art","access_token":"page-token","tasks":["CREATE_CONTENT"]}]}))
    }))).await;
    let ep = Endpoints {
      facebook: base,
      ..Endpoints::default()
    };
    let (label, secret) = connect(
      &reqwest::Client::new(),
      &ep,
      &json!({"access_token":"long"}),
      None,
    )
    .await
    .unwrap();
    assert!(label.contains("Art"));
    assert_eq!(secret["pageId"], "12");
    assert_eq!(secret["accessToken"], "page-token");
  }

  #[tokio::test]
  async fn facebook_connect_never_silently_picks_between_pages() {
    let base = serve(Router::new().route(
      "/me/accounts",
      get(|| async {
        Json(json!({"data":[
          {"id":"12","name":"Art","access_token":"a","tasks":["CREATE_CONTENT"]},
          {"id":"13","name":"Music","access_token":"b","tasks":["MANAGE"]}
        ]}))
      }),
    ))
    .await;
    let ep = Endpoints {
      facebook: base,
      ..Endpoints::default()
    };
    assert_eq!(
      connect(
        &reqwest::Client::new(),
        &ep,
        &json!({"access_token":"long"}),
        None
      )
      .await
      .unwrap_err()
      .code,
      "requiredChoiceMissing"
    );
    let (_, s) = connect(
      &reqwest::Client::new(),
      &ep,
      &json!({"access_token":"long"}),
      Some("13"),
    )
    .await
    .unwrap();
    assert_eq!(s["pageId"], "13");
  }

  #[tokio::test]
  async fn facebook_expired_credentials_never_start_upload() {
    let dir = tempfile::tempdir().unwrap();
    let fb = Facebook::new(
      reqwest::Client::new(),
      &json!({"pageId":"12","accessToken":"t","expiresAt":1}),
      &Endpoints::default(),
      dir.path().to_owned(),
    )
    .unwrap();
    let e = fb
      .publish(Upload {
        item: &json!({}),
        post: None,
        media: &[],
        idempotency_key: "k",
        options: &json!({}),
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "tokenExpired");
  }

  #[tokio::test]
  async fn facebook_multi_photo_publishes_one_feed_post_after_all_direct_uploads() {
    use axum::{http::HeaderMap, routing::post};
    use std::sync::{Arc, Mutex};
    let photos = Arc::new(Mutex::new(0));
    let log = photos.clone();
    let app=Router::new().route("/12/photos",post(move |h:HeaderMap,b:axum::body::Bytes|{
      let log=log.clone();async move {
        assert_eq!(h["authorization"],"Bearer t");
        let body=String::from_utf8_lossy(&b);
        assert!(body.contains("\r\nfalse\r\n"));
        let mut n=log.lock().unwrap();*n+=1;
        Json(json!({"id":format!("p{n}")}))
      }
    })).route("/12/feed",post(move |b:axum::body::Bytes|async move{
      let body=String::from_utf8_lossy(&b);
      assert!(body.contains("p1") && body.contains("p2"));
      Json(json!({"id":"12_99"}))
    })).route("/12_99",get(||async{
      Json(json!({"id":"12_99","from":{"id":"12"},"is_published":true,"attachments":{"data":[{"subattachments":{"data":[{"target":{"id":"p1"}},{"target":{"id":"p2"}}]}}]}}))
    }));
    let base = serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.jpg");
    let b = dir.path().join("b.jpg");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let ep = Endpoints {
      facebook: base,
      ..Endpoints::default()
    };
    let fb = Facebook::new(
      reqwest::Client::new(),
      &json!({"pageId":"12","accessToken":"t"}),
      &ep,
      dir.path().join("handles"),
    )
    .unwrap()
    .fast();
    let result = fb
      .publish(Upload {
        item: &json!({"kind":"carousel"}),
        post: None,
        media: &[a, b],
        idempotency_key: "multi",
        options: &json!({}),
      })
      .await
      .unwrap();
    assert!(result.verified);
    assert_eq!(*photos.lock().unwrap(), 2);
  }

  #[tokio::test]
  async fn facebook_refused_publish_keeps_verbatim_error_and_frees_the_item() {
    use axum::{http::StatusCode, routing::post};
    let base = serve(Router::new().route(
      "/12/photos",
      // Read the upload before refusing, as Facebook does: on Windows an unread body resets the
      // connection, which the uploader rightly treats as "may have posted".
      post(|_body: axum::body::Bytes| async {
        (
          StatusCode::FORBIDDEN,
          Json(json!({"error":{"message":"(#200) Missing permission"}})),
        )
      }),
    ))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.jpg");
    std::fs::write(&p, b"photo").unwrap();
    let fb = Facebook::new(
      reqwest::Client::new(),
      &json!({"pageId":"12","accessToken":"t"}),
      &Endpoints {
        facebook: base,
        ..Endpoints::default()
      },
      dir.path().join("handles"),
    )
    .unwrap()
    .fast();
    let result = fb
      .publish(Upload {
        item: &json!({}),
        post: None,
        media: &[p],
        idempotency_key: "denied",
        options: &json!({}),
      })
      .await
      .unwrap_err();
    // A 403 proves nothing was posted (D-069): the error keeps Facebook's words, item freed.
    assert_eq!(result.code, "uploadRejected");
    assert!(result
      .verbatim
      .unwrap()
      .contains("(#200) Missing permission"));
    assert!(
      fb.handles.begin("denied", "image").unwrap(),
      "the item is free again"
    );
  }

  #[tokio::test]
  async fn facebook_refusals_free_the_item_and_other_answers_never_repeat() {
    use axum::routing::post;
    use std::sync::{Arc, Mutex};
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let posts = Arc::new(Mutex::new(0));
      let log = posts.clone();
      let base = serve(Router::new().route(
        "/12/feed",
        post(move || {
          let log = log.clone();
          async move {
            *log.lock().unwrap() += 1;
            crate::uploaders::testkit::table_answer(code)
          }
        }),
      ))
      .await;
      let dir = tempfile::tempdir().unwrap();
      let fb = Facebook::new(
        reqwest::Client::new(),
        &json!({"pageId":"12","accessToken":"t"}),
        &Endpoints {
          facebook: base,
          ..Endpoints::default()
        },
        dir.path().join("handles"),
      )
      .unwrap()
      .fast();
      let item = json!({"kind":"text","description":"Hello"});
      let options = json!({});
      let upload = || Upload {
        item: &item,
        post: None,
        media: &[],
        idempotency_key: "fb|12|src|1",
        options: &options,
      };
      let first = fb.publish(upload()).await;
      if freed {
        assert!(first.is_err(), "{code} is a refusal");
      } else {
        let p = first.unwrap_or_else(|e| panic!("{code} may have posted: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check Facebook before posting again"),
          "{code}"
        );
      }
      let again = fb.publish(upload()).await;
      let n = *posts.lock().unwrap();
      if freed {
        assert_eq!(n, 2, "{code}: a refused post can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(n, 1, "{code}: never a second post");
      }
    }
  }
}

//! Tumblr posts in the Neue Post Format (D-062, D-067). Text, up to ten photos or one video go
//! up from this computer in one multipart request; nothing is fetched from a URL. Contracts:
//! Tumblr's official API docs (`Tumblr/docs`, `api.md` and `npf-spec.md`).
use super::{
  body_text, is_image, is_video, json_or_fail, mime_of, net, publish_answer, tags, title_text,
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

const P: &str = "Tumblr";
/// The schema's unverified caps, kept until the live check (backlog).
const IMAGE_MAX: u64 = 20_000_000;
const VIDEO_MAX: u64 = 500_000_000;
const PHOTOS_MAX: usize = 10;
/// Tumblr access tokens last about 40 minutes; renew with under 5 minutes left.
const REFRESH_WITHIN_MS: i64 = 5 * 60000;

/// Picks the blog to post to: the one named (by name or UUID), otherwise the primary blog,
/// which is where Tumblr's own composer posts by default.
fn pick<'a>(blogs: &'a [Value], wanted: Option<&str>) -> Option<&'a Value> {
  match wanted {
    Some(w) => {
      let w = w.trim().trim_start_matches('@').to_ascii_lowercase();
      blogs.iter().find(|b| {
        b["uuid"].as_str() == Some(w.as_str())
          || b["name"].as_str().map(str::to_ascii_lowercase) == Some(w.clone())
      })
    }
    None => blogs.iter().find(|b| b["primary"] == true),
  }
}

pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
  wanted: Option<&str>,
) -> Result<(String, Value), Failure> {
  let s = |k: &str| tokens[k].as_str().filter(|s| !s.is_empty());
  let (Some(token), Some(refresh)) = (s("access_token"), s("refresh_token")) else {
    return Err(Failure::new(
      "signInRequired",
      "Tumblr didn't finish sign-in with a renewable token.",
    ));
  };
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|n| *n > 0)
    .ok_or_else(|| Failure::new("signInRequired", "Tumblr did not return a token lifetime."))?;
  let me = json_or_fail(
    P,
    http
      .get(format!("{}/user/info", ep.tumblr))
      .bearer_auth(token)
      .send()
      .await,
  )
  .await?;
  let blogs: Vec<Value> = me
    .pointer("/response/user/blogs")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter(|b| b["uuid"].as_str().is_some_and(|u| !u.is_empty()) && b["name"].is_string())
    .cloned()
    .collect();
  let blog = pick(&blogs, wanted).ok_or_else(|| {
    Failure::new(
      "requiredChoiceMissing",
      if blogs.is_empty() {
        "This Tumblr account has no blog BunnieHop can post to.".to_string()
      } else {
        format!(
          "Choose the Tumblr blog to post to: {}.",
          blogs
            .iter()
            .filter_map(|b| b["name"].as_str())
            .collect::<Vec<_>>()
            .join(", ")
        )
      },
    )
  })?;
  let name = blog["name"].as_str().unwrap_or("");
  Ok((
    name.to_string(),
    json!({"blogId":blog["uuid"],"blogName":name,"accessToken":token,"refreshToken":refresh,
      "expiresAt":crate::pacing::now_ms()+expires*1000}),
  ))
}

pub struct Tumblr {
  http: reqwest::Client,
  ep: Endpoints,
  blog: String,
  name: String,
  store: Arc<Store>,
  connection: String,
  secret: tokio::sync::Mutex<Value>,
  handles: UploadHandles,
  /// Read-back waits for video processing: `tries` checks, `poll` apart (about five minutes).
  poll: Duration,
  tries: usize,
}

/// What the post holds, decided before any call.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Shape {
  Text,
  Photos(usize),
  Video,
}

impl Shape {
  fn of(media: &[PathBuf]) -> Result<Self, Failure> {
    match media {
      [] => Ok(Shape::Text),
      [p] if is_video(p) => Ok(Shape::Video),
      ps if ps.iter().all(|p| is_image(p)) && ps.len() <= PHOTOS_MAX => Ok(Shape::Photos(ps.len())),
      ps if ps.iter().all(|p| is_image(p)) => Err(Failure::new(
        "notSupported",
        format!("Tumblr takes up to {PHOTOS_MAX} photos per post."),
      )),
      _ => Err(Failure::new(
        "notSupported",
        "Tumblr takes text, photos or one video per post here. Audio posts are not ready yet.",
      )),
    }
  }
  fn block(self) -> &'static str {
    match self {
      Shape::Video => "video",
      _ => "image",
    }
  }
}

impl Tumblr {
  pub fn new(
    http: reqwest::Client,
    store: Arc<Store>,
    connection: &str,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    let blog = secret["blogId"].as_str().filter(|s| !s.is_empty())?;
    secret["refreshToken"].as_str()?;
    Some(Self {
      http,
      ep: ep.clone(),
      blog: blog.into(),
      name: secret["blogName"].as_str().unwrap_or("").into(),
      store,
      connection: connection.into(),
      secret: tokio::sync::Mutex::new(secret.clone()),
      handles: UploadHandles::new(handles),
      poll: Duration::from_secs(5),
      tries: 60,
    })
  }

  #[cfg(test)]
  fn fast(mut self, tries: usize) -> Self {
    self.poll = Duration::from_millis(1);
    self.tries = tries;
    self
  }

  /// The current access token, renewed through the relay (which adds the app secret and keeps
  /// nothing). Tumblr returns a new refresh token each time; it replaces the old in the keychain.
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
        .post(format!("{}/v1/oauth/tumblr/token", self.ep.worker))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await,
    )
    .await
    .map_err(|e| {
      Failure::new(
        "tokenExpired",
        "Tumblr sign-in expired. Connect Tumblr again.",
      )
      .with(e.verbatim.unwrap_or(e.message))
    })?;
    let new = v["access_token"]
      .as_str()
      .filter(|t| !t.is_empty())
      .ok_or_else(|| Failure::new("tokenExpired", "Tumblr did not renew sign-in."))?;
    let lifetime = v["expires_in"]
      .as_i64()
      .filter(|n| *n > 0)
      .ok_or_else(|| Failure::new("tokenExpired", "Tumblr did not return a token lifetime."))?;
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
          "Couldn't save the renewed Tumblr sign-in.",
        )
        .with(e)
      })?;
    *s = next;
    Ok(new.to_string())
  }

  fn save(&self, key: &str, v: &Value) -> Result<(), Failure> {
    self
      .handles
      .save(key, v)
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't save Tumblr's post handle.").with(e))
  }

  /// The NPF body and the multipart form carrying it and the media, in block order.
  async fn form(&self, u: &Upload<'_>, shape: Shape) -> Result<Form, Failure> {
    let mut content = Vec::new();
    let mut parts = Vec::new();
    for (i, path) in u.media.iter().enumerate() {
      let id = format!("media{i}");
      let media = json!({"type": mime_of(path), "identifier": id});
      content.push(match shape {
        Shape::Video => json!({"type":"video","media":media}),
        _ => json!({"type":"image","media":[media]}),
      });
      let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the media.").with(e))?;
      let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("media")
        .to_string();
      parts.push((
        id,
        Part::bytes(bytes)
          .file_name(name)
          .mime_str(mime_of(path))
          .map_err(|e| net(P, e))?,
      ));
    }
    let title = title_text(u.post, u.item);
    // A mapped title becomes the post's heading; the body follows as paragraphs.
    if !title.is_empty() && u.post.and_then(|p| p.pointer("/fields/title")).is_some() {
      content.push(json!({"type":"text","subtype":"heading1","text":title}));
    }
    for para in body_text(u.post, u.item)
      .split("\n\n")
      .map(str::trim)
      .filter(|p| !p.is_empty())
    {
      content.push(json!({"type":"text","text":para}));
    }
    if content.is_empty() {
      return Err(Failure::new(
        "uploadRejected",
        "This post has nothing to send to Tumblr.",
      ));
    }
    let mut body = json!({"content": content, "state": "published"});
    let t = tags(u.post, u.item);
    if !t.is_empty() {
      body["tags"] = json!(t.join(","));
    }
    let mut form = Form::new().part(
      "json",
      Part::text(body.to_string())
        .mime_str("application/json")
        .map_err(|e| net(P, e))?,
    );
    for (id, part) in parts {
      form = form.part(id, part);
    }
    Ok(form)
  }

  /// Reads the post back: same ID, posted on this blog, and the media blocks that were sent.
  /// A video is ready once its block carries a playable `media.url` (NPF video blocks); until
  /// then the read-back waits, within a bounded time, as Instagram's does.
  async fn readback(&self, handle: &Value, token: &str) -> Published {
    let id = handle["id"].as_str().unwrap_or("").to_string();
    let blocks = handle["blocks"].as_str().unwrap_or("text");
    let count = handle["count"].as_u64().unwrap_or(0) as usize;
    let mut verified = false;
    let mut processing = false;
    let valid = !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit());
    for attempt in 0..self.tries {
      if !valid {
        break;
      }
      if attempt > 0 {
        tokio::time::sleep(self.poll).await;
      }
      let Ok(v) = json_or_fail(
        P,
        self
          .http
          .get(format!("{}/blog/{}/posts/{id}", self.ep.tumblr, self.blog))
          .bearer_auth(token)
          .query(&[("post_format", "npf")])
          .send()
          .await,
      )
      .await
      else {
        break;
      };
      let r = &v["response"];
      let sent: Vec<&Value> = r["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["type"] == blocks)
        .collect();
      let ours = r["id"] == id.as_str()
        && r["tumblelog_uuid"] == self.blog.as_str()
        && (blocks == "text" || sent.len() == count);
      processing = ours
        && blocks == "video"
        && !sent.iter().all(|b| {
          b.pointer("/media/url")
            .and_then(Value::as_str)
            .is_some_and(|u| !u.is_empty())
        });
      verified = ours && !processing;
      if !processing {
        break;
      }
    }
    let url = if self.name.is_empty() {
      None
    } else {
      Some(format!("https://www.tumblr.com/{}/{id}", self.name))
    };
    Published {
      dest_url: verified.then_some(url).flatten(),
      dest_item_id: id,
      verified,
      note: (!verified).then(|| {
        if processing {
          "Tumblr is still processing this video. Check Tumblr in a few minutes before posting it again."
        } else {
          "Tumblr has not confirmed this post with its media. Check Tumblr before posting again."
        }
        .into()
      }),
    }
  }
}

impl Uploader for Tumblr {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    self.publish_controlled(u, PublishControl::new(tokio::sync::watch::channel(false).1))
  }

  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let shape = Shape::of(u.media)?;
      for p in u.media {
        let n = tokio::fs::metadata(p)
          .await
          .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the media.").with(e))?
          .len();
        if n == 0 || n > if is_video(p) { VIDEO_MAX } else { IMAGE_MAX } {
          return Err(Failure::new(
            "itemTooLarge",
            "This file is empty or over Tumblr's upload limit.",
          ));
        }
      }
      let token = self.access().await?;
      let fresh = self
        .handles
        .begin(u.idempotency_key, shape.block())
        .map_err(|e| {
          Failure::new(
            "vaultUnavailable",
            "Couldn't reserve the Tumblr post. Nothing was sent.",
          )
          .with(e)
        })?;
      if !fresh {
        // Tumblr has no idempotency key: a saved handle is only ever read back.
        let h = self
          .handles
          .load(u.idempotency_key)
          .ok()
          .flatten()
          .unwrap_or(Value::Null);
        return Ok(self.readback(&h, &token).await);
      }
      let (blocks, count) = match shape {
        Shape::Text => ("text", 0),
        Shape::Photos(n) => ("image", n),
        Shape::Video => ("video", 1),
      };
      let prepared = async {
        let form = self.form(&u, shape).await?;
        self.save(
          u.idempotency_key,
          &json!({"kind":blocks,"stage":"publishing","blocks":blocks,"count":count}),
        )?;
        control.start_publish()?;
        Ok::<_, Failure>(form)
      }
      .await;
      let form = match prepared {
        Ok(f) => f,
        Err(e) => {
          self.handles.release(u.idempotency_key);
          return Err(e);
        }
      };
      let r = self
        .http
        .post(format!("{}/blog/{}/posts", self.ep.tumblr, self.blog))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await;
      match publish_answer(P, r).await {
        PublishAnswer::Posted(v) => {
          let id = v
            .pointer("/response/id")
            .and_then(Value::as_str)
            .unwrap_or("");
          let handle =
            json!({"kind":blocks,"stage":"published","blocks":blocks,"count":count,"id":id});
          if self.save(u.idempotency_key, &handle).is_err() {
            return Ok(Published {
              dest_item_id: id.into(),
              dest_url: None,
              verified: false,
              note: Some("Tumblr created this post, but its ID could not be saved. Check Tumblr before posting again.".into()),
            });
          }
          Ok(self.readback(&handle, &token).await)
        }
        // A refusal (D-069): nothing was posted, so a later hop may try again.
        PublishAnswer::Refused(e) => {
          self.handles.release(u.idempotency_key);
          // Tumblr's daily limits answer 403 with codes 8004, 8011 and 8023 (api.md).
          let limit = e
            .verbatim
            .as_deref()
            .is_some_and(|v| v.contains("8023") || v.contains("8011") || v.contains("8004"));
          Err(if limit {
            Failure::new(
              "dailyCapReached",
              "Tumblr's daily posting limit was reached for this blog.",
            )
            .with(e.verbatim.unwrap_or_default())
          } else {
            e
          })
        }
        // 408, 409, 429, a server error or no answer: the post may exist. Never sent again (D11).
        PublishAnswer::Unknown(e) => Ok(Published {
          dest_item_id: String::new(),
          dest_url: None,
          verified: false,
          note: Some(unknown_note(P, &e, "posting")),
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
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
  };
  use std::{collections::HashMap, sync::Mutex};

  #[derive(Default)]
  struct Log {
    posts: Vec<String>,
    refreshes: usize,
    reads: usize,
  }

  #[derive(Clone, Copy)]
  enum Answer {
    Created,
    Lost,
    Refused,
    Table(u16),
  }

  /// A fake Tumblr API and relay. `readback` is the content the post reads back with.
  async fn fake(answer: Answer, readback: Value) -> (String, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let app = Router::new()
      .route("/user/info", get(|h: HeaderMap| async move {
        assert_eq!(h["authorization"], "Bearer t");
        Json(json!({"meta":{"status":200},"response":{"user":{"name":"mara","blogs":[
          {"name":"sideblog","uuid":"t:side","primary":false,"type":"public"},
          {"name":"maravee","uuid":"t:main","primary":true,"type":"public"}]}}}))
      }))
      .route("/blog/{blog}/posts", post({ let log = log.clone(); move |Path(blog): Path<String>, h: HeaderMap, body: axum::body::Bytes| {
        let log = log.clone(); async move {
          assert_eq!(blog, "t:main");
          assert_eq!(h["authorization"], "Bearer t");
          assert!(h["content-type"].to_str().unwrap().starts_with("multipart/form-data"));
          log.lock().unwrap().posts.push(String::from_utf8_lossy(&body).into_owned());
          match answer {
            Answer::Created => (StatusCode::CREATED, Json(json!({"meta":{"status":201},"response":{"id":"7001"}}))),
            Answer::Lost => (StatusCode::BAD_GATEWAY, Json(json!({}))),
            Answer::Refused => (StatusCode::FORBIDDEN, Json(json!({"meta":{"status":403},"errors":[{"title":"Daily posting limit","code":8023}]}))),
            Answer::Table(code) => return crate::uploaders::testkit::table_answer(code),
          }.into_response()
        }
      }}))
      .route("/blog/{blog}/posts/{id}", get({ let log = log.clone(); let seq = Arc::new(Mutex::new(readback)); move |Path((blog, id)): Path<(String, String)>| { let log = log.clone(); let seq = seq.clone(); async move {
        assert_eq!((blog.as_str(), id.as_str()), ("t:main", "7001"));
        log.lock().unwrap().reads += 1;
        // An array of arrays is a sequence of read-backs; the last one repeats.
        let mut s = seq.lock().unwrap();
        let content = match s.as_array_mut() {
          Some(list) if list.first().is_some_and(Value::is_array) => if list.len() > 1 { list.remove(0) } else { list[0].clone() },
          _ => s.clone(),
        };
        Json(json!({"meta":{"status":200},"response":{"object_type":"post","id":"7001","tumblelog_uuid":"t:main","content":content}}))
      }}}))
      .route("/v1/oauth/tumblr/token", post({ let log = log.clone(); move |Json(b): Json<Value>| {
        let log = log.clone(); async move {
          assert_eq!(b, json!({"refresh_token":"r1"}));
          log.lock().unwrap().refreshes += 1;
          Json(json!({"access_token":"t","expires_in":2520,"refresh_token":"r2","scope":"basic write offline_access"}))
        }
      }}));
    (serve(app).await, log)
  }

  fn ep(base: &str) -> Endpoints {
    Endpoints {
      tumblr: base.into(),
      worker: base.into(),
      ..Endpoints::default()
    }
  }

  fn setup(base: &str, dir: &std::path::Path, expires_at: i64) -> (Tumblr, Arc<Store>) {
    let store = Arc::new(Store::open(
      dir.join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    let secret = json!({"blogId":"t:main","blogName":"maravee","accessToken":"t","refreshToken":"r1","expiresAt":expires_at});
    let c = store
      .save(
        Connection {
          id: "tumblr-1".into(),
          platform: "tumblr".into(),
          label: "maravee".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    let up = Tumblr::new(
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
    crate::pacing::now_ms() + 3600000
  }

  async fn run(
    up: &Tumblr,
    dir: &std::path::Path,
    files: &[(&str, &[u8])],
    control: Option<PublishControl>,
  ) -> Result<Published, Failure> {
    let media: Vec<PathBuf> = files
      .iter()
      .map(|(n, b)| {
        let p = dir.join(n);
        std::fs::write(&p, b).unwrap();
        p
      })
      .collect();
    let item = json!({"kind":"image","title":"Sunset"});
    let post = json!({"fields":{"title":"Sunset","body":"First line\n\nSecond line","tags":["golden hour","sky"]}});
    let options = json!({});
    let u = Upload {
      item: &item,
      post: Some(&post),
      media: &media,
      idempotency_key: "tu|1|src|1",
      options: &options,
    };
    match control {
      Some(c) => up.publish_controlled(u, c).await,
      None => up.publish(u).await,
    }
  }

  fn json_part(body: &str) -> Value {
    let start = body.find("name=\"json\"").unwrap();
    let open = body[start..].find('{').unwrap() + start;
    let end = body[open..].find("\r\n--").unwrap() + open;
    serde_json::from_str(&body[open..end]).unwrap()
  }

  #[tokio::test]
  async fn tumblr_oauth_checks_blog_before_connected() {
    let (base, _) = fake(Answer::Created, json!([])).await;
    let http = reqwest::Client::new();
    let tokens = json!({"access_token":"t","refresh_token":"r","expires_in":2520});
    let (label, secret) = connect(&http, &ep(&base), &tokens, None).await.unwrap();
    assert_eq!(
      label, "maravee",
      "the primary blog, as Tumblr's composer picks"
    );
    assert_eq!(secret["blogId"], "t:main");
    let (label, _) = connect(&http, &ep(&base), &tokens, Some("@SideBlog"))
      .await
      .unwrap();
    assert_eq!(label, "sideblog");
    let e = connect(&http, &ep(&base), &tokens, Some("someone-else"))
      .await
      .unwrap_err();
    assert_eq!(e.code, "requiredChoiceMissing");
    assert!(e.message.contains("sideblog, maravee"));
    let no_refresh = json!({"access_token":"t","expires_in":2520});
    assert_eq!(
      connect(&http, &ep(&base), &no_refresh, None)
        .await
        .unwrap_err()
        .code,
      "signInRequired"
    );
  }

  #[tokio::test]
  async fn tumblr_npf_uploads_photo_and_video_parts() {
    let (base, log) = fake(
      Answer::Created,
      json!([{"type":"image","media":[{"url":"x"}]},{"type":"image","media":[{"url":"y"}]},{"type":"text","text":"First line"}]),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(
      &up,
      dir.path(),
      &[("a.jpg", b"jpeg-a"), ("b.png", b"png-b")],
      None,
    )
    .await
    .unwrap();
    assert!(p.verified);
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://www.tumblr.com/maravee/7001")
    );
    let body = log.lock().unwrap().posts[0].clone();
    assert_eq!(
      json_part(&body),
      json!({"content":[
        {"type":"image","media":[{"type":"image/jpeg","identifier":"media0"}]},
        {"type":"image","media":[{"type":"image/png","identifier":"media1"}]},
        {"type":"text","subtype":"heading1","text":"Sunset"},
        {"type":"text","text":"First line"},{"type":"text","text":"Second line"}],
        "state":"published","tags":"golden hour,sky"})
    );
    assert!(body.find("name=\"json\"").unwrap() < body.find("name=\"media0\"").unwrap());
    assert!(body.contains("jpeg-a") && body.contains("png-b"));

    let (base, log) = fake(
      Answer::Created,
      json!([{"type":"video","media":{"url":"v"}}]),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    assert!(
      run(&up, dir.path(), &[("v.mp4", b"video-bytes")], None)
        .await
        .unwrap()
        .verified
    );
    let body = log.lock().unwrap().posts[0].clone();
    assert_eq!(
      json_part(&body)["content"][0],
      json!({"type":"video","media":{"type":"video/mp4","identifier":"media0"}})
    );
    assert!(body.contains("video-bytes"));
  }

  #[tokio::test]
  async fn tumblr_readback_checks_media_before_published() {
    // The post exists but came back without its photo: not called published.
    let (base, _) = fake(
      Answer::Created,
      json!([{"type":"text","text":"First line"}]),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None)
      .await
      .unwrap();
    assert!(!p.verified && p.dest_url.is_none());
    assert_eq!(p.dest_item_id, "7001");
    assert!(p.note.unwrap().contains("Check Tumblr"));
  }

  #[tokio::test]
  async fn tumblr_video_readback_waits_for_processing_then_verifies_or_stays_unverified() {
    let processing = json!([{"type":"video","provider":"tumblr"}]);
    let ready = json!([{"type":"video","provider":"tumblr","media":{"type":"video/mp4","url":"https://va.media.tumblr.com/v.mp4"}}]);
    let (base, log) = fake(Answer::Created, json!([processing, processing, ready])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), &[("v.mp4", b"video-bytes")], None)
      .await
      .unwrap();
    assert!(p.verified, "ready on the third read");
    assert_eq!(log.lock().unwrap().reads, 3);

    // Still processing when the time runs out: unverified in the creator's words, never failed.
    let (base, log) = fake(Answer::Created, json!([processing])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let p = run(&up, dir.path(), &[("v.mp4", b"video-bytes")], None)
      .await
      .unwrap();
    assert!(!p.verified && p.dest_url.is_none());
    assert_eq!(p.dest_item_id, "7001");
    assert_eq!(
      p.note.as_deref(),
      Some("Tumblr is still processing this video. Check Tumblr in a few minutes before posting it again.")
    );
    assert_eq!(
      log.lock().unwrap().reads,
      4,
      "bounded: the set number of checks"
    );
    assert_eq!(log.lock().unwrap().posts.len(), 1);
  }

  #[tokio::test]
  async fn tumblr_timeout_and_restart_never_create_a_second_post() {
    let (base, log) = fake(Answer::Lost, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let first = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None)
      .await
      .unwrap();
    assert!(!first.verified);
    assert!(first
      .note
      .unwrap()
      .contains("Check Tumblr before posting again"));
    // A restarted Helper builds a new uploader over the same handles.
    let (again, _) = setup(&base, dir.path(), later());
    let second = run(&again, dir.path(), &[("a.jpg", b"jpeg")], None)
      .await
      .unwrap();
    assert!(!second.verified);
    assert_eq!(log.lock().unwrap().posts.len(), 1, "never a second post");
  }

  #[tokio::test]
  async fn tumblr_refusal_frees_the_item_and_names_the_daily_limit() {
    let (base, log) = fake(Answer::Refused, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let e = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None)
      .await
      .unwrap_err();
    assert_eq!(e.code, "dailyCapReached");
    let e = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None)
      .await
      .unwrap_err();
    assert_eq!(e.code, "dailyCapReached");
    assert_eq!(
      log.lock().unwrap().posts.len(),
      2,
      "a refused post can be tried again"
    );
  }

  #[tokio::test]
  async fn tumblr_refusals_free_the_item_and_other_answers_never_repeat() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let (base, log) = fake(Answer::Table(code), json!([])).await;
      let dir = tempfile::tempdir().unwrap();
      let (up, _) = setup(&base, dir.path(), later());
      let r = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None).await;
      if freed {
        assert!(r.is_err(), "{code} is a refusal");
      } else {
        let p = r.unwrap_or_else(|e| panic!("{code} may have posted: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check Tumblr before posting again"),
          "{code}"
        );
      }
      let again = run(&up, dir.path(), &[("a.jpg", b"jpeg")], None).await;
      let posts = log.lock().unwrap().posts.len();
      if freed {
        assert_eq!(posts, 2, "{code}: a refused post can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(posts, 1, "{code}: never a second post");
      }
    }
  }

  #[tokio::test]
  async fn tumblr_stop_before_post_never_posts() {
    let (base, log) = fake(Answer::Created, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let e = run(
      &up,
      dir.path(),
      &[("a.jpg", b"jpeg")],
      Some(PublishControl::new(rx)),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "stopped");
    assert!(log.lock().unwrap().posts.is_empty());
  }

  #[tokio::test]
  async fn tumblr_audio_and_mixed_media_wait_before_any_call() {
    let (base, log) = fake(Answer::Created, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, _) = setup(&base, dir.path(), later());
    for files in [
      vec![("a.mp3", b"mp3".as_slice())],
      vec![("a.jpg", b"jpg".as_slice()), ("v.mp4", b"mp4".as_slice())],
    ] {
      let e = run(&up, dir.path(), &files, None).await.unwrap_err();
      assert_eq!(e.code, "notSupported");
    }
    assert!(log.lock().unwrap().posts.is_empty());
  }

  #[tokio::test]
  async fn tumblr_refreshes_through_the_relay_and_keeps_the_rotated_token_in_keychain() {
    let (base, log) = fake(Answer::Created, json!([{"type":"image"}])).await;
    let dir = tempfile::tempdir().unwrap();
    let (up, store) = setup(&base, dir.path(), crate::pacing::now_ms() + 60000);
    assert!(
      run(&up, dir.path(), &[("a.jpg", b"jpeg")], None)
        .await
        .unwrap()
        .verified
    );
    assert_eq!(log.lock().unwrap().refreshes, 1);
    assert_eq!(store.secret("tumblr-1").unwrap()["refreshToken"], "r2");
  }
}

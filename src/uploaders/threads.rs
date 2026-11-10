//! Threads round 1: text containers only. No media staging or implicit auto-publish.
use super::{body_text, json_or_fail, publish_answer, unknown_note, Endpoints, PublishAnswer};
use crate::{
  connections::Store,
  hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader, With},
  posted::UploadHandles,
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
const P: &str = "Threads";

pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let token = tokens["access_token"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Threads did not finish sign-in."))?;
  let me = json_or_fail(
    P,
    http
      .get(format!("{}/me", ep.threads))
      .bearer_auth(token)
      .query(&[("fields", "id,username")])
      .send()
      .await,
  )
  .await?;
  let id = me["id"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Threads did not identify this account."))?;
  let name = me["username"]
    .as_str()
    .filter(|s| !s.is_empty())
    .ok_or_else(|| Failure::new("signInRequired", "Threads did not name this account."))?;
  let expires = tokens["expires_in"]
    .as_i64()
    .filter(|n| *n > 0 && *n <= 60 * 24 * 3600)
    .ok_or_else(|| {
      Failure::new(
        "signInRequired",
        "Threads did not return a valid token lifetime.",
      )
    })?;
  let now = crate::pacing::now_ms();
  Ok((
    format!("@{name}"),
    json!({"userId":id,"username":name,"accessToken":token,"issuedAt":now,"expiresAt":now+expires*1000}),
  ))
}

pub struct Threads {
  http: reqwest::Client,
  api: String,
  user: String,
  store: Arc<Store>,
  connection: String,
  secret: tokio::sync::Mutex<Value>,
  handles: UploadHandles,
  poll: std::time::Duration,
}

/// Renew once the token is a day old (Threads refuses younger ones) and has under
/// 30 of its 60 days left, so a creator who hops monthly never meets an expiry.
const RENEW_AFTER_MS: i64 = 24 * 3600000;
const RENEW_WITHIN_MS: i64 = 30 * 24 * 3600000;

impl Threads {
  pub fn new(
    http: reqwest::Client,
    store: Arc<Store>,
    connection: &str,
    secret: &Value,
    ep: &Endpoints,
    handles: PathBuf,
  ) -> Option<Self> {
    Some(Self {
      http,
      api: ep.threads.clone(),
      user: secret["userId"].as_str()?.into(),
      store,
      connection: connection.into(),
      secret: tokio::sync::Mutex::new(secret.clone()),
      handles: UploadHandles::new(handles),
      poll: std::time::Duration::from_secs(2),
    })
  }

  #[cfg(test)]
  fn fast(mut self) -> Self {
    self.poll = std::time::Duration::from_millis(1);
    self
  }

  async fn access(&self) -> Result<String, Failure> {
    let mut s = self.secret.lock().await;
    let now = crate::pacing::now_ms();
    let expires = s["expiresAt"].as_i64().unwrap_or(0);
    if expires <= now {
      return Err(Failure::new(
        "tokenExpired",
        "Threads sign-in expired. Connect Threads again.",
      ));
    }
    let token = s["accessToken"]
      .as_str()
      .filter(|t| !t.is_empty())
      .ok_or_else(|| Failure::new("tokenExpired", "Connect Threads again."))?
      .to_string();
    if expires - now > RENEW_WITHIN_MS
      || now - s["issuedAt"].as_i64().unwrap_or(now) < RENEW_AFTER_MS
    {
      return Ok(token);
    }
    let v = json_or_fail(
      P,
      self
        .http
        .get(format!("{}/refresh_access_token", self.api))
        .bearer_auth(&token)
        .query(&[("grant_type", "th_refresh_token")])
        .send()
        .await,
    )
    .await?;
    let new = v["access_token"]
      .as_str()
      .filter(|s| !s.is_empty())
      .ok_or_else(|| Failure::new("tokenExpired", "Threads did not renew sign-in."))?;
    let lifetime = v["expires_in"]
      .as_i64()
      .filter(|n| *n > 0 && *n <= 60 * 24 * 3600)
      .ok_or_else(|| Failure::new("tokenExpired", "Threads did not return a token lifetime."))?;
    let mut next = s.clone();
    next["accessToken"] = json!(new);
    next["issuedAt"] = json!(now);
    next["expiresAt"] = json!(now + lifetime * 1000);
    self
      .store
      .set_secret(&self.connection, &next)
      .map_err(|e| {
        Failure::new(
          "vaultUnavailable",
          "Couldn't save the renewed Threads sign-in.",
        )
        .with(e)
      })?;
    *s = next;
    Ok(new.to_string())
  }

  /// Creates the text container and waits until Threads reports it FINISHED.
  /// Returns the saved handle at stage "publishing", after Stop was last checked.
  async fn prepare(
    &self,
    u: &Upload<'_>,
    token: &str,
    text: &str,
    control: &PublishControl,
  ) -> Result<Value, Failure> {
    let container = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/{}/threads", self.api, self.user))
        .bearer_auth(token)
        .form(&[("media_type", "TEXT"), ("text", text)])
        .send()
        .await,
    )
    .await?;
    let cid = container["id"]
      .as_str()
      .filter(|s| !s.is_empty())
      .ok_or_else(|| Failure::new("uploadRejected", "Threads did not return a container ID."))?;
    let mut handle = json!({"kind":"text","stage":"container","container":cid});
    self.save(u.idempotency_key, &handle)?;
    let mut tries = 0;
    loop {
      let status = json_or_fail(
        P,
        self
          .http
          .get(format!("{}/{}", self.api, super::ghost::urlencode(cid)))
          .bearer_auth(token)
          .query(&[("fields", "id,status,error_message")])
          .send()
          .await,
      )
      .await?;
      tries += 1;
      if status["id"] != cid {
        return Err(
          Failure::new("uploadRejected", "Threads described a different post.").with(status),
        );
      }
      match status["status"].as_str() {
        Some("FINISHED") => break,
        Some("IN_PROGRESS") if tries < 5 => tokio::time::sleep(self.poll).await,
        Some("IN_PROGRESS") => {
          return Err(Failure::new(
            "uploadRejected",
            "Threads did not finish preparing the text post. Nothing was published.",
          ))
        }
        _ => {
          return Err(
            Failure::new(
              "uploadRejected",
              "Threads refused the text post. Nothing was published.",
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

  fn save(&self, key: &str, v: &Value) -> Result<(), Failure> {
    self.handles.save(key, v).map_err(|e| {
      Failure::new("vaultUnavailable", "Couldn't save Threads' upload handle.").with(e)
    })
  }

  async fn readback(&self, handle: &Value, token: &str, text: &str) -> Published {
    let id = handle["id"].as_str().unwrap_or("");
    let mut verified = false;
    let mut url = None;
    if !id.is_empty() {
      if let Ok(v) = json_or_fail(
        P,
        self
          .http
          .get(format!("{}/{}", self.api, super::ghost::urlencode(id)))
          .bearer_auth(token)
          .query(&[("fields", "id,owner,username,media_type,text,permalink")])
          .send()
          .await,
      )
      .await
      {
        verified = v["id"] == id
          && v.pointer("/owner/id").and_then(Value::as_str) == Some(self.user.as_str())
          && v["media_type"] == "TEXT_POST"
          && v["text"] == text;
        if verified {
          url = v["permalink"]
            .as_str()
            .and_then(|s| reqwest::Url::parse(s).ok())
            .filter(|u| {
              u.scheme() == "https"
                && matches!(
                  u.host_str(),
                  Some("www.threads.com" | "www.threads.net" | "threads.com" | "threads.net")
                )
            })
            .map(|u| u.to_string());
        }
      }
    }
    Published {
      dest_item_id: id.into(),
      dest_url: url,
      verified,
      note: (!verified)
        .then(|| "Threads has not confirmed this post. Check Threads before posting again.".into()),
    }
  }
}

impl Uploader for Threads {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    self.publish_controlled(u, PublishControl::new(tokio::sync::watch::channel(false).1))
  }
  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      if !u.media.is_empty() || !matches!(u.item["kind"].as_str(), Some("text" | "article")) {
        return Err(Failure::new(
          "notSupported",
          "Threads photos and videos are not ready yet.",
        ));
      }
      let text = body_text(u.post, u.item);
      if text.is_empty() || text.chars().count() > 500 {
        return Err(Failure::new(
          "uploadRejected",
          "Threads needs between 1 and 500 characters.",
        ));
      }
      if !super::thread(u.post).is_empty() {
        return Err(Failure::new(
          "notSupported",
          "Threads reply chains are not ready yet.",
        ));
      }
      let token = self.access().await?;
      if !self.handles.begin(u.idempotency_key, "text").map_err(|e| {
        Failure::new("vaultUnavailable", "Couldn't reserve the Threads post.").with(e)
      })? {
        return Ok(
          self
            .readback(
              &self
                .handles
                .load(u.idempotency_key)
                .ok()
                .flatten()
                .unwrap_or(Value::Null),
              &token,
              &text,
            )
            .await,
        );
      }
      // Without auto_publish_text a container never goes live on its own, so any failure
      // before threads_publish releases the reservation: a later deliberate hop starts fresh.
      let mut handle = match self.prepare(&u, &token, &text, &control).await {
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
          .post(format!("{}/{}/threads_publish", self.api, self.user))
          .bearer_auth(&token)
          .form(&[("creation_id", cid.as_str())])
          .send()
          .await,
      )
      .await;
      match result {
        PublishAnswer::Posted(v) => {
          handle["id"] = v["id"].clone();
          handle["stage"] = json!("published");
          if self.save(u.idempotency_key, &handle).is_err() {
            return Ok(Published{dest_item_id:v["id"].as_str().unwrap_or("").into(),dest_url:None,verified:false,note:Some("Threads may have published this post, but its ID could not be saved. Check Threads before posting again.".into())});
          }
          Ok(self.readback(&handle, &token, &text).await)
        }
        // A refusal (D-069): nothing was posted, so a later hop may try again.
        PublishAnswer::Refused(e) => {
          self.handles.release(u.idempotency_key);
          Err(e)
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
  use crate::{
    connections::{new_id, Connection, MemorySecrets, Store},
    hops::{Upload, Uploader},
    uploaders::{testkit::serve, Endpoints},
  };
  use axum::{
    extract::Form,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
  };
  use serde_json::json;
  use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
  };

  #[tokio::test]
  async fn threads_refusals_free_the_item_and_other_answers_never_repeat() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let publishes = Arc::new(Mutex::new(0));
      let log = publishes.clone();
      let app = Router::new()
        .route(
          "/me",
          get(|| async { Json(json!({"id":"42","username":"artist"})) }),
        )
        .route(
          "/42/threads",
          post(|| async { Json(json!({"id":"container"})) }),
        )
        .route(
          "/container",
          get(|| async { Json(json!({"id":"container","status":"FINISHED"})) }),
        )
        .route(
          "/42/threads_publish",
          post(move || {
            let log = log.clone();
            async move {
              *log.lock().unwrap() += 1;
              crate::uploaders::testkit::table_answer(code)
            }
          }),
        );
      let ep = Endpoints {
        threads: serve(app).await,
        ..Endpoints::default()
      };
      let dir = tempfile::tempdir().unwrap();
      let st = Arc::new(Store::open(
        dir.path().join("c.json"),
        Box::new(MemorySecrets::default()),
      ));
      let (label, secret) = connect(
        &reqwest::Client::new(),
        &ep,
        &json!({"access_token":"t","expires_in":5184000}),
      )
      .await
      .unwrap();
      let c = st
        .save(
          Connection {
            id: new_id("threads"),
            platform: "threads".into(),
            label,
            path: "api".into(),
            checked_at: "t".into(),
            choices: HashMap::new(),
            account: String::new(),
          },
          &secret,
        )
        .unwrap();
      let up = Threads::new(
        reqwest::Client::new(),
        st,
        &c.id,
        &secret,
        &ep,
        dir.path().join("handles"),
      )
      .unwrap();
      let item = json!({"kind":"text","description":"Hello"});
      let options = json!({});
      let upload = || Upload {
        item: &item,
        post: None,
        media: &[],
        idempotency_key: "threads|42|source|1",
        options: &options,
      };
      let first = up.publish(upload()).await;
      if freed {
        assert!(first.is_err(), "{code} is a refusal");
      } else {
        let p = first.unwrap_or_else(|e| panic!("{code} may have posted: {}", e.message));
        assert!(!p.verified, "{code}");
        assert!(
          p.note
            .unwrap()
            .contains("Check Threads before posting again"),
          "{code}"
        );
      }
      let again = up.publish(upload()).await;
      let n = *publishes.lock().unwrap();
      if freed {
        assert_eq!(n, 2, "{code}: a refused post can be tried again");
      } else {
        assert!(again.is_ok_and(|p| !p.verified), "{code}");
        assert_eq!(n, 1, "{code}: never a second post");
      }
    }
  }

  async fn scenario(publish_error: bool, read_matches: bool) {
    let mutations = Arc::new(Mutex::new(0));
    let log = mutations.clone();
    let app=Router::new()
      .route("/me",get(||async{Json(json!({"id":"42","username":"artist"}))}))
      .route("/42/threads",post(move|h:HeaderMap,Form(f):Form<HashMap<String,String>>|{let log=log.clone();async move {
        assert_eq!(h["authorization"],"Bearer t");assert_eq!(f["media_type"],"TEXT");assert_eq!(f["text"],"Hello 🐇");
        assert!(!f.contains_key("auto_publish_text"));
        *log.lock().unwrap()+=1;Json(json!({"id":"container"}))
      }}))
      .route("/container",get(||async{Json(json!({"id":"container","status":"FINISHED"}))}))
      .route("/42/threads_publish",post({let log=mutations.clone();move|Form(f):Form<HashMap<String,String>>|{let log=log.clone();async move {
        assert_eq!(f["creation_id"],"container");*log.lock().unwrap()+=1;
        if publish_error {(axum::http::StatusCode::BAD_GATEWAY,Json(json!({"error":{"message":"connection lost"}})))} else {(axum::http::StatusCode::OK,Json(json!({"id":"post-1"})))}
      }}}))
      .route("/post-1",get(move||async move{Json(json!({"id":"post-1","owner":{"id":if read_matches{"42"}else{"other"}},"username":if read_matches{"artist"}else{"other"},"media_type":"TEXT_POST","text":"Hello 🐇","permalink":"https://www.threads.com/@artist/post/example"}))}));
    let base = serve(app).await;
    let ep = Endpoints {
      threads: base,
      ..Endpoints::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let st = Arc::new(Store::open(
      dir.path().join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    let (label, secret) = connect(
      &reqwest::Client::new(),
      &ep,
      &json!({"access_token":"t","expires_in":5184000}),
    )
    .await
    .unwrap();
    let c = st
      .save(
        Connection {
          id: new_id("threads"),
          platform: "threads".into(),
          label,
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    let up = Threads::new(
      reqwest::Client::new(),
      st.clone(),
      &c.id,
      &secret,
      &ep,
      dir.path().join("handles"),
    )
    .unwrap();
    let item = json!({"kind":"text","description":"Hello 🐇"});
    let options = json!({});
    let upload = || Upload {
      item: &item,
      post: None,
      media: &[],
      idempotency_key: "threads|42|source|1",
      options: &options,
    };
    let result = up.publish(upload()).await.unwrap();
    assert_eq!(result.verified, !publish_error && read_matches);
    let restarted = Threads::new(
      reqwest::Client::new(),
      st,
      &c.id,
      &secret,
      &ep,
      dir.path().join("handles"),
    )
    .unwrap();
    assert_eq!(
      restarted.publish(upload()).await.unwrap().verified,
      result.verified
    );
    assert_eq!(
      *mutations.lock().unwrap(),
      2,
      "no second container or publish after restart"
    );
    assert!(!up.safe_to_retry());
  }

  #[tokio::test]
  async fn threads_text_creates_container_publishes_and_reads_back() {
    scenario(false, true).await;
  }
  #[tokio::test]
  async fn threads_unknown_publish_never_posts_twice() {
    scenario(true, true).await;
  }
  #[tokio::test]
  async fn threads_wrong_account_readback_is_unverified() {
    scenario(false, false).await;
  }

  #[tokio::test]
  async fn threads_refreshes_long_lived_token_directly_and_saves_it_in_keychain() {
    use axum::extract::Query;
    let base = serve(Router::new().route(
      "/refresh_access_token",
      get(
        |h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
          assert_eq!(h["authorization"], "Bearer old");
          assert_eq!(q["grant_type"], "th_refresh_token");
          assert!(!q.contains_key("client_secret"));
          Json(json!({"access_token":"new","expires_in":5184000}))
        },
      ),
    ))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let st = Arc::new(Store::open(
      dir.path().join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    let secret = json!({"userId":"42","username":"artist","accessToken":"old","issuedAt":0,"expiresAt":crate::pacing::now_ms()+3600000});
    let c = st
      .save(
        Connection {
          id: "threads-1".into(),
          platform: "threads".into(),
          label: "artist".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    let up = Threads::new(
      reqwest::Client::new(),
      st.clone(),
      &c.id,
      &secret,
      &Endpoints {
        threads: base,
        ..Endpoints::default()
      },
      dir.path().join("handles"),
    )
    .unwrap();
    assert_eq!(up.access().await.unwrap(), "new");
    assert_eq!(st.secret(&c.id).unwrap()["accessToken"], "new");
    assert!(std::fs::read_to_string(dir.path().join("c.json"))
      .unwrap()
      .find("new\"")
      .is_none());
  }

  fn uploader(base: String, dir: &std::path::Path, secret: Value) -> Threads {
    let st = Arc::new(Store::open(
      dir.join("c.json"),
      Box::new(MemorySecrets::default()),
    ));
    Threads::new(
      reqwest::Client::new(),
      st,
      "threads-1",
      &secret,
      &Endpoints {
        threads: base,
        ..Endpoints::default()
      },
      dir.join("handles"),
    )
    .unwrap()
    .fast()
  }

  fn fresh_secret() -> Value {
    let now = crate::pacing::now_ms();
    json!({"userId":"42","username":"artist","accessToken":"t","issuedAt":now,"expiresAt":now+60*24*3600000_i64})
  }

  /// Fake Threads whose container reports the given statuses in order, counting publishes.
  async fn statuses(seq: Vec<&'static str>) -> (String, Arc<Mutex<usize>>, Arc<Mutex<usize>>) {
    let containers = Arc::new(Mutex::new(0));
    let publishes = Arc::new(Mutex::new(0));
    let seq = Arc::new(Mutex::new(seq.into_iter()));
    let (c, p) = (containers.clone(), publishes.clone());
    let app = Router::new()
      .route("/42/threads", post(move || { let c = c.clone(); async move { *c.lock().unwrap() += 1; Json(json!({"id":"container"})) } }))
      .route("/container", get(move || { let seq = seq.clone(); async move {
        let s = seq.lock().unwrap().next().unwrap_or("FINISHED");
        Json(json!({"id":"container","status":s,"error_message":"Unknown"}))
      } }))
      .route("/42/threads_publish", post(move || { let p = p.clone(); async move { *p.lock().unwrap() += 1; Json(json!({"id":"post-1"})) } }))
      .route("/post-1", get(|| async { Json(json!({"id":"post-1","owner":{"id":"42"},"media_type":"TEXT_POST","text":"Hi","permalink":"https://www.threads.com/@artist/post/x"})) }));
    (serve(app).await, containers, publishes)
  }

  fn text_upload<'a>(item: &'a Value, options: &'a Value) -> Upload<'a> {
    Upload {
      item,
      post: None,
      media: &[],
      idempotency_key: "threads|42|source|2",
      options,
    }
  }

  #[tokio::test]
  async fn threads_waits_for_an_in_progress_container_before_publishing() {
    let (base, containers, publishes) =
      statuses(vec!["IN_PROGRESS", "IN_PROGRESS", "FINISHED"]).await;
    let dir = tempfile::tempdir().unwrap();
    let up = uploader(base, dir.path(), fresh_secret());
    let (item, options) = (json!({"kind":"text","description":"Hi"}), json!({}));
    assert!(
      up.publish(text_upload(&item, &options))
        .await
        .unwrap()
        .verified
    );
    assert_eq!(
      (*containers.lock().unwrap(), *publishes.lock().unwrap()),
      (1, 1)
    );
  }

  #[tokio::test]
  async fn threads_refused_container_publishes_nothing_and_a_later_hop_starts_fresh() {
    let (base, containers, publishes) = statuses(vec!["ERROR"]).await;
    let dir = tempfile::tempdir().unwrap();
    let up = uploader(base, dir.path(), fresh_secret());
    let (item, options) = (json!({"kind":"text","description":"Hi"}), json!({}));
    let e = up.publish(text_upload(&item, &options)).await.unwrap_err();
    assert_eq!(e.code, "uploadRejected");
    assert!(e.message.contains("Nothing was published"));
    assert_eq!(*publishes.lock().unwrap(), 0);
    // The unpublished container cannot go live by itself, so a deliberate retry may proceed.
    assert!(
      up.publish(text_upload(&item, &options))
        .await
        .unwrap()
        .verified
    );
    assert_eq!(
      (*containers.lock().unwrap(), *publishes.lock().unwrap()),
      (2, 1)
    );
  }

  #[tokio::test]
  async fn threads_stop_before_publish_never_publishes() {
    let (base, containers, publishes) = statuses(vec!["FINISHED"]).await;
    let dir = tempfile::tempdir().unwrap();
    let up = uploader(base, dir.path(), fresh_secret());
    let (item, options) = (json!({"kind":"text","description":"Hi"}), json!({}));
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let e = up
      .publish_controlled(text_upload(&item, &options), PublishControl::new(rx))
      .await
      .unwrap_err();
    assert_eq!(e.code, "stopped");
    assert_eq!(
      (*containers.lock().unwrap(), *publishes.lock().unwrap()),
      (1, 0)
    );
  }

  #[tokio::test]
  async fn threads_rejects_media_long_text_and_reply_chains_before_any_call() {
    // No server: any network call would fail with a different code.
    let dir = tempfile::tempdir().unwrap();
    let up = uploader("http://127.0.0.1:9".into(), dir.path(), fresh_secret());
    let options = json!({});
    let photo = dir.path().join("a.jpg");
    std::fs::write(&photo, b"x").unwrap();
    let media = [photo];
    let item = json!({"kind":"image","description":"Hi"});
    let e = up
      .publish(Upload {
        item: &item,
        post: None,
        media: &media,
        idempotency_key: "a",
        options: &options,
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "notSupported");
    let long = json!({"kind":"text","description":"x".repeat(501)});
    assert_eq!(
      up.publish(text_upload(&long, &options))
        .await
        .unwrap_err()
        .code,
      "uploadRejected"
    );
    let chain = json!({"fields":{"body":"one"},"thread":["two"]});
    let text = json!({"kind":"text","description":"one"});
    let e = up
      .publish(Upload {
        item: &text,
        post: Some(&chain),
        media: &[],
        idempotency_key: "b",
        options: &options,
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "notSupported");
  }

  #[tokio::test]
  async fn threads_keeps_young_tokens_and_renews_within_thirty_days() {
    let refreshes = Arc::new(Mutex::new(0));
    let r = refreshes.clone();
    let base = serve(Router::new().route(
      "/refresh_access_token",
      get(move || {
        let r = r.clone();
        async move {
          *r.lock().unwrap() += 1;
          Json(json!({"access_token":"new","expires_in":5184000}))
        }
      }),
    ))
    .await;
    let dir = tempfile::tempdir().unwrap();
    let now = crate::pacing::now_ms();
    let day = 24 * 3600000_i64;
    // Issued an hour ago with 59 days left: kept.
    let young = uploader(
      base.clone(),
      dir.path(),
      json!({"userId":"42","accessToken":"t","issuedAt":now-3600000,"expiresAt":now+59*day}),
    );
    assert_eq!(young.access().await.unwrap(), "t");
    // Issued 10 days ago with 50 days left: kept.
    let mid = uploader(
      base.clone(),
      dir.path(),
      json!({"userId":"42","accessToken":"t","issuedAt":now-10*day,"expiresAt":now+50*day}),
    );
    assert_eq!(mid.access().await.unwrap(), "t");
    assert_eq!(*refreshes.lock().unwrap(), 0);
    // Issued 31 days ago with 29 days left: renewed.
    let old = uploader(
      base,
      dir.path(),
      json!({"userId":"42","accessToken":"t","issuedAt":now-31*day,"expiresAt":now+29*day}),
    );
    assert_eq!(old.access().await.unwrap(), "new");
    assert_eq!(*refreshes.lock().unwrap(), 1);
  }

  #[tokio::test]
  async fn threads_connect_checks_current_account() {
    let base = serve(Router::new().route(
      "/me",
      get(|h: HeaderMap| async move {
        assert_eq!(h["authorization"], "Bearer t");
        Json(json!({"id":"42","username":"artist"}))
      }),
    ))
    .await;
    let ep = Endpoints {
      threads: base,
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    let (label, secret) = connect(
      &http,
      &ep,
      &json!({"access_token":"t","expires_in":5184000}),
    )
    .await
    .unwrap();
    assert_eq!(label, "@artist");
    assert_eq!(secret["userId"], "42");
    // A missing lifetime is never guessed into a Connected account.
    assert_eq!(
      connect(&http, &ep, &json!({"access_token":"t"}))
        .await
        .unwrap_err()
        .code,
      "signInRequired"
    );
    let nameless =
      serve(Router::new().route("/me", get(|| async { Json(json!({"id":"42"})) }))).await;
    let ep = Endpoints {
      threads: nameless,
      ..Endpoints::default()
    };
    assert_eq!(
      connect(
        &http,
        &ep,
        &json!({"access_token":"t","expires_in":5184000})
      )
      .await
      .unwrap_err()
      .code,
      "signInRequired"
    );
  }
}

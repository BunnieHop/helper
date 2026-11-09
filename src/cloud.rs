//! Cloud vaults (PLAN §8): the vault lives in the creator's own cloud storage instead of a folder
//! on this computer. The hop files each item into a staging copy of the vault inside the Helper's
//! temp folder exactly as it would locally, then uploads the item folder and the merged
//! `bunniehop.json` / `index.csv`, and the staging copy is deleted ("nothing left in temp").
//! Nothing passes through BunnieHop's servers (D8); the Worker only refreshes OAuth tokens.

use crate::hops::{BoxFut, Failure, With};
use crate::uploaders::{json_or_fail, net, status_failure, Endpoints};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

/// One cloud vault account. Paths are relative to the vault root ("youtube/mara/2026/…/media.mp4").
pub trait Remote: Send + Sync {
  /// File names directly inside `rel` (empty when the folder doesn't exist).
  fn list<'a>(&'a self, rel: &'a str) -> BoxFut<'a, Result<Vec<String>, Failure>>;
  /// Downloads `rel` to `dest`; `Ok(false)` when it doesn't exist.
  fn get<'a>(&'a self, rel: &'a str, dest: &'a Path) -> BoxFut<'a, Result<bool, Failure>>;
  /// Uploads `src` to `rel`, replacing what's there.
  fn put<'a>(&'a self, src: &'a Path, rel: &'a str) -> BoxFut<'a, Result<(), Failure>>;
  /// Shown in events and the hop record ("Dropbox:/BunnieHop/youtube/mara").
  fn describe(&self, rel: &str) -> String;
}

/// Looks up the remote for `(kind, connectionId, target)`; `None` when it isn't wired.
pub type Remotes = Arc<dyn Fn(&str, &str, &str) -> Option<Arc<dyn Remote>> + Send + Sync>;

/// `target` as typed ("/BunnieHop", "Backups/Mara") → "/BunnieHop". No `..`, no control chars.
pub fn root_path(target: &str) -> Option<String> {
  let t = target.trim().trim_matches('/');
  if t.is_empty() {
    return Some("/BunnieHop".into());
  }
  let ok = t
    .split('/')
    .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.chars().any(char::is_control));
  ok.then(|| format!("/{t}"))
}

/// Dropbox wants `Dropbox-API-Arg` in ASCII; anything else is written as a JSON \u escape.
pub fn api_arg(v: &Value) -> String {
  let mut out = String::new();
  for c in v.to_string().chars() {
    if c.is_ascii() {
      out.push(c);
    } else {
      let mut b = [0u16; 2];
      for u in c.encode_utf16(&mut b) {
        out.push_str(&format!("\\u{u:04x}"));
      }
    }
  }
  out
}

/// Builds the remote for a plan's `vault` from the stored connection.
pub fn remotes(
  store: Arc<crate::connections::Store>,
  http: reqwest::Client,
  ep: Endpoints,
) -> Remotes {
  Arc::new(move |kind: &str, conn_id: &str, target: &str| {
    let r: Arc<dyn Remote> = match kind {
      "dropbox" => {
        let c = store.find("dropbox", conn_id)?;
        Arc::new(Dropbox::new(
          http.clone(),
          &store.secret(&c.id)?,
          &ep,
          target,
        )?)
      }
      "google-drive" => {
        let c = store.find("google-drive", conn_id)?;
        Arc::new(crate::gdrive::Drive::new(
          http.clone(),
          &store.secret(&c.id)?,
          &ep,
          target,
        )?)
      }
      _ => return None,
    };
    Some(r)
  })
}

const P: &str = "Dropbox";
/// Files up to this go in one call; larger ones in an upload session (Dropbox caps calls at 150 MB).
const SINGLE_MAX: u64 = 128 * 1024 * 1024;
const CHUNK: usize = 32 * 1024 * 1024;

pub struct Dropbox {
  http: reqwest::Client,
  api: String,
  content: String,
  worker: String,
  root: String,
  refresh: String,
  access: Mutex<Option<String>>,
}

/// After the relay sign-in: checks the account and returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let (Some(access), Some(refresh)) = (
    tokens["access_token"].as_str().filter(|t| !t.is_empty()),
    tokens["refresh_token"].as_str().filter(|t| !t.is_empty()),
  ) else {
    return Err(Failure {
      code: "signInRequired",
      message: "Dropbox didn't finish the sign-in. Try again.".into(),
      verbatim: tokens["error_description"]
        .as_str()
        .or(tokens["error"].as_str())
        .map(str::to_string),
    });
  };
  let me = json_or_fail(
    P,
    http
      .post(format!("{}/2/users/get_current_account", ep.dropbox_api))
      .bearer_auth(access)
      .header("content-type", "application/json")
      .body("null")
      .send()
      .await,
  )
  .await?;
  let name = me
    .pointer("/name/display_name")
    .and_then(Value::as_str)
    .unwrap_or("Dropbox account");
  Ok((
    format!("{name} (Dropbox)"),
    json!({ "refreshToken": refresh }),
  ))
}

impl Dropbox {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints, target: &str) -> Option<Self> {
    Some(Self {
      http,
      api: ep.dropbox_api.clone(),
      content: ep.dropbox_content.clone(),
      worker: ep.worker.clone(),
      root: root_path(target)?,
      refresh: secret["refreshToken"].as_str()?.to_string(),
      access: Mutex::new(None),
    })
  }

  fn path(&self, rel: &str) -> String {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
      self.root.clone()
    } else {
      format!("{}/{rel}", self.root)
    }
  }

  /// Short-lived access token, refreshed through the Worker (it adds the app secret only).
  async fn token(&self, fresh: bool) -> Result<String, Failure> {
    if !fresh {
      if let Some(t) = self
        .access
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
      {
        return Ok(t);
      }
    }
    let r = json_or_fail(
      P,
      self
        .http
        .post(format!("{}/v1/oauth/dropbox/token", self.worker))
        .json(&json!({ "refresh_token": self.refresh }))
        .send()
        .await,
    )
    .await
    .map_err(|f| Failure {
      code: if f.code == "networkLost" {
        f.code
      } else {
        "tokenExpired"
      },
      message: if f.code == "networkLost" {
        f.message
      } else {
        "Dropbox signed BunnieHop out. Connect Dropbox again.".into()
      },
      verbatim: f.verbatim,
    })?;
    let t = r["access_token"]
      .as_str()
      .filter(|t| !t.is_empty())
      .ok_or_else(|| {
        Failure::new(
          "tokenExpired",
          "Dropbox signed BunnieHop out. Connect Dropbox again.",
        )
      })?
      .to_string();
    *self.access.lock().unwrap_or_else(|e| e.into_inner()) = Some(t.clone());
    Ok(t)
  }

  /// Sends a request built by `make`, refreshing the token once on 401.
  async fn send(
    &self,
    make: impl Fn(&str) -> reqwest::RequestBuilder,
  ) -> Result<reqwest::Response, Failure> {
    let t = self.token(false).await?;
    let r = make(&t).send().await.map_err(|e| net(P, e))?;
    if r.status() != reqwest::StatusCode::UNAUTHORIZED {
      return Ok(r);
    }
    let t = self.token(true).await?;
    make(&t).send().await.map_err(|e| net(P, e))
  }

  fn not_found(body: &str) -> bool {
    body.contains("not_found")
  }

  /// Large files: start → append … → finish. Only used above `SINGLE_MAX`, so there are always
  /// several chunks and the last one goes with `finish`.
  async fn upload_session(&self, src: &Path, path: &str, size: u64) -> Result<(), Failure> {
    let read_err =
      |e: std::io::Error| Failure::new("unknown", "Couldn't read a vault file.").with(e);
    let mut f = tokio::fs::File::open(src).await.map_err(read_err)?;
    let mut offset: u64 = 0;
    let mut session = String::new();
    while offset < size {
      let want = CHUNK.min((size - offset) as usize);
      let mut chunk = vec![0u8; want];
      f.read_exact(&mut chunk).await.map_err(read_err)?;
      let last = offset + want as u64 >= size;
      let cursor = json!({ "session_id": session, "offset": offset });
      let (op, arg) = if session.is_empty() {
        ("start", json!({ "close": false }))
      } else if last {
        (
          "finish",
          json!({ "cursor": cursor,
                  "commit": { "path": path, "mode": "overwrite", "autorename": false, "mute": true } }),
        )
      } else {
        ("append_v2", json!({ "cursor": cursor, "close": false }))
      };
      let url = format!("{}/2/files/upload_session/{op}", self.content);
      let r = self
        .send(|t| {
          self
            .http
            .post(&url)
            .bearer_auth(t)
            .header("Dropbox-API-Arg", api_arg(&arg))
            .header("content-type", "application/octet-stream")
            .body(chunk.clone())
        })
        .await?;
      let status = r.status();
      let text = r.text().await.unwrap_or_default();
      if !status.is_success() {
        return Err(status_failure(P, status, &text));
      }
      if session.is_empty() {
        session = serde_json::from_str::<Value>(&text)
          .ok()
          .and_then(|v| v["session_id"].as_str().map(str::to_string))
          .ok_or_else(|| Failure::new("uploadRejected", "Dropbox didn't open an upload."))?;
      }
      offset += want as u64;
    }
    Ok(())
  }
}

impl Remote for Dropbox {
  fn list<'a>(&'a self, rel: &'a str) -> BoxFut<'a, Result<Vec<String>, Failure>> {
    Box::pin(async move {
      let mut names = Vec::new();
      let mut cursor: Option<String> = None;
      loop {
        let (url, body) = match &cursor {
          None => (
            format!("{}/2/files/list_folder", self.api),
            json!({ "path": self.path(rel), "recursive": false }),
          ),
          Some(c) => (
            format!("{}/2/files/list_folder/continue", self.api),
            json!({ "cursor": c }),
          ),
        };
        let r = self
          .send(|t| self.http.post(&url).bearer_auth(t).json(&body))
          .await?;
        let status = r.status();
        let text = r.text().await.unwrap_or_default();
        if status.as_u16() == 409 && Self::not_found(&text) {
          return Ok(vec![]);
        }
        if !status.is_success() {
          return Err(status_failure(P, status, &text));
        }
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        for e in v["entries"].as_array().into_iter().flatten() {
          if e[".tag"] == "file" {
            if let Some(n) = e["name"].as_str() {
              names.push(n.to_string());
            }
          }
        }
        if v["has_more"] == true {
          cursor = v["cursor"].as_str().map(str::to_string);
          if cursor.is_some() {
            continue;
          }
        }
        return Ok(names);
      }
    })
  }

  fn get<'a>(&'a self, rel: &'a str, dest: &'a Path) -> BoxFut<'a, Result<bool, Failure>> {
    Box::pin(async move {
      let arg = api_arg(&json!({ "path": self.path(rel) }));
      let url = format!("{}/2/files/download", self.content);
      let mut r = self
        .send(|t| {
          self
            .http
            .post(&url)
            .bearer_auth(t)
            .header("Dropbox-API-Arg", &arg)
        })
        .await?;
      let status = r.status();
      if status.as_u16() == 409 {
        let text = r.text().await.unwrap_or_default();
        if Self::not_found(&text) {
          return Ok(false);
        }
        return Err(status_failure(P, status, &text));
      }
      if !status.is_success() {
        return Err(status_failure(
          P,
          status,
          &r.text().await.unwrap_or_default(),
        ));
      }
      if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d)
          .map_err(|e| Failure::new("diskFull", "Couldn't make a temp folder.").with(e))?;
      }
      // written to `.part` and renamed when complete: a dropped download never leaves a
      // truncated file that looks whole (a cut-off sidecar would wipe the cloud index)
      let part = std::path::PathBuf::from(format!("{}.part", dest.display()));
      let mut f = tokio::fs::File::create(&part)
        .await
        .map_err(|e| Failure::new("diskFull", "Couldn't write a temp file.").with(e))?;
      use tokio::io::AsyncWriteExt;
      while let Some(c) = r.chunk().await.map_err(|e| net(P, e))? {
        f.write_all(&c)
          .await
          .map_err(|e| Failure::new("diskFull", "The disk is full.").with(e))?;
      }
      f.flush()
        .await
        .map_err(|e| Failure::new("diskFull", "The disk is full.").with(e))?;
      drop(f);
      std::fs::rename(&part, dest)
        .map_err(|e| Failure::new("diskFull", "Couldn't write a temp file.").with(e))?;
      Ok(true)
    })
  }

  fn put<'a>(&'a self, src: &'a Path, rel: &'a str) -> BoxFut<'a, Result<(), Failure>> {
    Box::pin(async move {
      let size = tokio::fs::metadata(src)
        .await
        .map_err(|e| Failure::new("unknown", "Couldn't read a vault file.").with(e))?
        .len();
      let path = self.path(rel);
      if size > SINGLE_MAX {
        return self.upload_session(src, &path, size).await;
      }
      let bytes = tokio::fs::read(src)
        .await
        .map_err(|e| Failure::new("unknown", "Couldn't read a vault file.").with(e))?;
      let arg =
        api_arg(&json!({ "path": path, "mode": "overwrite", "autorename": false, "mute": true }));
      let url = format!("{}/2/files/upload", self.content);
      let r = self
        .send(|t| {
          self
            .http
            .post(&url)
            .bearer_auth(t)
            .header("Dropbox-API-Arg", &arg)
            .header("content-type", "application/octet-stream")
            .body(bytes.clone())
        })
        .await?;
      if !r.status().is_success() {
        let s = r.status();
        let text = r.text().await.unwrap_or_default();
        if text.contains("insufficient_space") {
          return Err(Failure::new("diskFull", "Your Dropbox is full.").with(text));
        }
        return Err(status_failure(P, s, &text));
      }
      Ok(())
    })
  }

  fn describe(&self, rel: &str) -> String {
    format!("Dropbox:{}", self.path(rel))
  }
}

/// A cloud vault kept in memory for tests: rel path → bytes.
#[cfg(test)]
#[derive(Default)]
pub struct MemRemote {
  pub files: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
  /// Every upload fails as a full account would.
  pub full: Mutex<bool>,
  /// Listing fails (a network blip).
  pub list_fails: Mutex<bool>,
  /// Downloads of `bunniehop.json` come back cut off.
  pub truncate_sidecar: Mutex<bool>,
}

#[cfg(test)]
impl Remote for MemRemote {
  fn list<'a>(&'a self, rel: &'a str) -> BoxFut<'a, Result<Vec<String>, Failure>> {
    Box::pin(async move {
      if *self.list_fails.lock().unwrap() {
        return Err(Failure::new("networkLost", "Couldn't reach Dropbox."));
      }
      let pre = format!("{}/", rel.trim_matches('/'));
      Ok(
        self
          .files
          .lock()
          .unwrap()
          .keys()
          .filter_map(|k| k.strip_prefix(&pre))
          .filter(|r| !r.contains('/'))
          .map(str::to_string)
          .collect(),
      )
    })
  }
  fn get<'a>(&'a self, rel: &'a str, dest: &'a Path) -> BoxFut<'a, Result<bool, Failure>> {
    Box::pin(async move {
      let Some(mut b) = self.files.lock().unwrap().get(rel).cloned() else {
        return Ok(false);
      };
      if rel.ends_with("bunniehop.json") && *self.truncate_sidecar.lock().unwrap() {
        b.truncate(b.len() / 2);
      }
      std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
      std::fs::write(dest, b).unwrap();
      Ok(true)
    })
  }
  fn put<'a>(&'a self, src: &'a Path, rel: &'a str) -> BoxFut<'a, Result<(), Failure>> {
    Box::pin(async move {
      if *self.full.lock().unwrap() {
        return Err(Failure::new("diskFull", "Your Dropbox is full."));
      }
      let b = std::fs::read(src).unwrap();
      self.files.lock().unwrap().insert(rel.to_string(), b);
      Ok(())
    })
  }
  fn describe(&self, rel: &str) -> String {
    format!("Mem:/{rel}")
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::http::{HeaderMap, StatusCode};
  use axum::response::IntoResponse;
  use axum::routing::post;
  use axum::{Json, Router};

  #[test]
  fn dropbox_paths_stay_inside_the_vault_root() {
    assert_eq!(root_path("").unwrap(), "/BunnieHop");
    assert_eq!(root_path("/Backups/Mara/").unwrap(), "/Backups/Mara");
    assert!(root_path("/a/../b").is_none());
    assert!(root_path("a//b").is_none());
    assert_eq!(
      api_arg(&json!({ "path": "/Café" })),
      format!("{{\"path\":\"/Caf{}u00e9\"}}", '\\')
    );
  }

  type Files = Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>;

  fn arg(h: &HeaderMap) -> Value {
    serde_json::from_str(h["dropbox-api-arg"].to_str().unwrap()).unwrap()
  }

  fn fake(files: Files, refreshes: Arc<Mutex<u32>>) -> Router {
    let authed = |h: &HeaderMap| h["authorization"] == "Bearer acc-2";
    Router::new()
      .route(
        "/v1/oauth/dropbox/token",
        post(move |Json(b): Json<Value>| async move {
          assert_eq!(b["refresh_token"], "ref-1");
          *refreshes.lock().unwrap() += 1;
          Json(json!({ "access_token": "acc-2", "expires_in": 14400 }))
        }),
      )
      .route(
        "/2/users/get_current_account",
        post(|| async { Json(json!({ "name": { "display_name": "Mara Lin" } })) }),
      )
      .route(
        "/2/files/upload",
        post({
          let files = files.clone();
          move |h: HeaderMap, b: axum::body::Bytes| async move {
            if !authed(&h) {
              return (StatusCode::UNAUTHORIZED, "expired").into_response();
            }
            let a = arg(&h);
            assert_eq!(a["mode"], "overwrite");
            files
              .lock()
              .unwrap()
              .insert(a["path"].as_str().unwrap().into(), b.to_vec());
            Json(json!({})).into_response()
          }
        }),
      )
      .route(
        "/2/files/download",
        post({
          let files = files.clone();
          move |h: HeaderMap| async move {
            let p = arg(&h)["path"].as_str().unwrap().to_string();
            match files.lock().unwrap().get(&p) {
              Some(b) => b.clone().into_response(),
              None => (
                StatusCode::CONFLICT,
                r#"{"error_summary":"path/not_found/"}"#,
              )
                .into_response(),
            }
          }
        }),
      )
      .route(
        "/2/files/list_folder",
        post({
          let files = files.clone();
          move |Json(b): Json<Value>| async move {
            let pre = format!("{}/", b["path"].as_str().unwrap());
            let entries: Vec<Value> = files
              .lock()
              .unwrap()
              .keys()
              .filter_map(|k| k.strip_prefix(&pre).map(str::to_string))
              .filter(|r| !r.contains('/'))
              .map(|n| json!({ ".tag": "file", "name": n }))
              .collect();
            if entries.is_empty() {
              return (
                StatusCode::CONFLICT,
                r#"{"error_summary":"path/not_found/"}"#,
              )
                .into_response();
            }
            Json(json!({ "entries": entries, "has_more": false })).into_response()
          }
        }),
      )
  }

  #[tokio::test]
  async fn dropbox_vault_refreshes_its_token_and_round_trips_files() {
    let files: Files = Arc::default();
    let refreshes = Arc::new(Mutex::new(0));
    let base = serve(fake(files.clone(), refreshes.clone())).await;
    let ep = Endpoints {
      worker: base.clone(),
      dropbox_api: base.clone(),
      dropbox_content: base.clone(),
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    let (label, secret) = connect(
      &http,
      &ep,
      &json!({ "access_token": "acc-1", "refresh_token": "ref-1" }),
    )
    .await
    .unwrap();
    assert_eq!(label, "Mara Lin (Dropbox)");
    assert_eq!(secret, json!({ "refreshToken": "ref-1" }));
    let d = Dropbox::new(http, &secret, &ep, "/BunnieHop").unwrap();
    // a stale cached token gets one refresh on 401
    *d.access.lock().unwrap() = Some("acc-old".into());
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("media.mp4");
    std::fs::write(&src, b"video").unwrap();
    d.put(&src, "youtube/mara/2026/a/media.mp4").await.unwrap();
    assert_eq!(*refreshes.lock().unwrap(), 1);
    assert_eq!(
      files.lock().unwrap()["/BunnieHop/youtube/mara/2026/a/media.mp4"],
      b"video"
    );
    assert_eq!(
      d.list("youtube/mara/2026/a").await.unwrap(),
      vec!["media.mp4".to_string()]
    );
    assert!(d.list("youtube/mara/2026/none").await.unwrap().is_empty());
    let back = dir.path().join("back/m.mp4");
    assert!(d.get("youtube/mara/2026/a/media.mp4", &back).await.unwrap());
    assert_eq!(std::fs::read(&back).unwrap(), b"video");
    assert!(!d.get("youtube/mara/bunniehop.json", &back).await.unwrap());
    assert_eq!(
      d.describe("youtube/mara"),
      "Dropbox:/BunnieHop/youtube/mara"
    );
  }
}

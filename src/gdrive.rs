//! Google Drive vault (PLAN §8, D-046): the same staged vault as Dropbox (D-041), in a
//! `BunnieHop` folder in the creator's own Drive. The sign-in asks only for `drive.file`, so
//! BunnieHop can see and change nothing but the files it made. Drive is id-based, so vault paths
//! are resolved folder by folder (and remembered for the hop).

use crate::cloud::{root_path, Remote};
use crate::hops::{BoxFut, Failure, With};
use crate::uploaders::{json_or_fail, net, resumable_put, status_failure, Endpoints, RelayToken};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

const P: &str = "Google Drive";
const FOLDER: &str = "application/vnd.google-apps.folder";

pub struct Drive {
  http: reqwest::Client,
  api: String,
  /// Vault root segments under My Drive ("BunnieHop", or what the creator chose).
  root: Vec<String>,
  token: RelayToken,
  /// Folder path ("BunnieHop/youtube/mara") → id.
  folders: Mutex<HashMap<String, String>>,
}

/// After Google's sign-in page: checks the account and returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let (Some(access), Some(refresh)) = (
    tokens["access_token"].as_str().filter(|t| !t.is_empty()),
    tokens["refresh_token"].as_str().filter(|t| !t.is_empty()),
  ) else {
    return Err(Failure::new(
      "signInRequired",
      "Google didn't finish the sign-in. Try again and allow BunnieHop to add files.",
    ));
  };
  let about = json_or_fail(
    P,
    http
      .get(format!("{}/drive/v3/about", ep.google_api))
      .query(&[("fields", "user(displayName,emailAddress)")])
      .bearer_auth(access)
      .send()
      .await,
  )
  .await?;
  let who = about
    .pointer("/user/emailAddress")
    .or(about.pointer("/user/displayName"))
    .and_then(Value::as_str)
    .unwrap_or("Google account");
  Ok((
    format!("{who} (Google Drive)"),
    json!({ "refreshToken": refresh }),
  ))
}

/// A name inside a Drive query string literal.
fn q_name(s: &str) -> String {
  s.replace('\\', "\\\\").replace('\'', "\\'")
}

impl Drive {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints, target: &str) -> Option<Self> {
    let root = root_path(target)?
      .trim_matches('/')
      .split('/')
      .map(String::from)
      .collect();
    Some(Self {
      token: RelayToken::new(
        http.clone(),
        ep,
        "gdrive",
        secret["refreshToken"].as_str()?,
        P,
      ),
      http,
      api: ep.google_api.clone(),
      root,
      folders: Mutex::new(HashMap::new()),
    })
  }

  fn segments(&self, rel: &str) -> Vec<String> {
    let mut v = self.root.clone();
    v.extend(
      rel
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .map(String::from),
    );
    v
  }

  /// The id of `name` directly inside `parent` (newest first, so a duplicate never wins over
  /// what was just written).
  async fn find(&self, parent: &str, name: &str, folder: bool) -> Result<Option<String>, Failure> {
    let kind = if folder {
      format!("mimeType = '{FOLDER}'")
    } else {
      format!("mimeType != '{FOLDER}'")
    };
    let q = format!(
      "'{}' in parents and name = '{}' and {kind} and trashed = false",
      q_name(parent),
      q_name(name)
    );
    let r = self
      .token
      .send(|| {
        self
          .http
          .get(format!("{}/drive/v3/files", self.api))
          .query(&[
            ("q", q.as_str()),
            ("fields", "files(id)"),
            ("orderBy", "modifiedTime desc"),
            ("pageSize", "1"),
            ("spaces", "drive"),
          ])
      })
      .await?;
    let v = json_or_fail(P, Ok(r)).await?;
    Ok(
      v.pointer("/files/0/id")
        .and_then(Value::as_str)
        .map(String::from),
    )
  }

  async fn make_folder(&self, parent: &str, name: &str) -> Result<String, Failure> {
    let r = self
      .token
      .send(|| {
        self
          .http
          .post(format!("{}/drive/v3/files", self.api))
          .query(&[("fields", "id")])
          .json(&json!({ "name": name, "mimeType": FOLDER, "parents": [parent] }))
      })
      .await?;
    let v = json_or_fail(P, Ok(r)).await?;
    v["id"]
      .as_str()
      .map(String::from)
      .ok_or_else(|| Failure::new("uploadRejected", "Google Drive didn't make the folder."))
  }

  /// Folder id for `segs`, made on the way when `create`; `None` when it doesn't exist.
  async fn folder(&self, segs: &[String], create: bool) -> Result<Option<String>, Failure> {
    let mut parent = "root".to_string();
    for i in 0..segs.len() {
      let key = segs[..=i].join("/");
      let cached = self
        .folders
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned();
      let id = match cached {
        Some(id) => id,
        None => {
          let id = match self.find(&parent, &segs[i], true).await? {
            Some(id) => id,
            None if create => self.make_folder(&parent, &segs[i]).await?,
            None => return Ok(None),
          };
          self
            .folders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, id.clone());
          id
        }
      };
      parent = id;
    }
    Ok(Some(parent))
  }

  /// (parent folder id, file name) for a file path, or `None` when the folder is missing.
  async fn locate(&self, rel: &str, create: bool) -> Result<Option<(String, String)>, Failure> {
    let mut segs = self.segments(rel);
    let Some(name) = segs.pop().filter(|_| segs.len() >= self.root.len()) else {
      return Ok(None);
    };
    Ok(self.folder(&segs, create).await?.map(|p| (p, name)))
  }
}

impl Remote for Drive {
  fn list<'a>(&'a self, rel: &'a str) -> BoxFut<'a, Result<Vec<String>, Failure>> {
    Box::pin(async move {
      let Some(id) = self.folder(&self.segments(rel), false).await? else {
        return Ok(Vec::new());
      };
      let q = format!("'{}' in parents and trashed = false", q_name(&id));
      let mut names = Vec::new();
      let mut page: Option<String> = None;
      loop {
        let r = self
          .token
          .send(|| {
            let mut b = self
              .http
              .get(format!("{}/drive/v3/files", self.api))
              .query(&[
                ("q", q.as_str()),
                ("fields", "nextPageToken,files(name)"),
                ("pageSize", "1000"),
                ("spaces", "drive"),
              ]);
            if let Some(p) = &page {
              b = b.query(&[("pageToken", p.as_str())]);
            }
            b
          })
          .await?;
        let v = json_or_fail(P, Ok(r)).await?;
        names.extend(
          v["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["name"].as_str().map(String::from)),
        );
        match v["nextPageToken"].as_str() {
          Some(t) => page = Some(t.to_string()),
          None => break,
        }
      }
      names.sort();
      names.dedup();
      Ok(names)
    })
  }

  fn get<'a>(&'a self, rel: &'a str, dest: &'a Path) -> BoxFut<'a, Result<bool, Failure>> {
    Box::pin(async move {
      let Some((parent, name)) = self.locate(rel, false).await? else {
        return Ok(false);
      };
      let Some(id) = self.find(&parent, &name, false).await? else {
        return Ok(false);
      };
      let mut r = self
        .token
        .send(|| {
          self
            .http
            .get(format!("{}/drive/v3/files/{id}", self.api))
            .query(&[("alt", "media")])
        })
        .await?;
      if !r.status().is_success() {
        let s = r.status();
        return Err(status_failure(P, s, &r.text().await.unwrap_or_default()));
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
      let len = tokio::fs::metadata(src)
        .await
        .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read a vault file.").with(e))?
        .len();
      let Some((parent, name)) = self.locate(rel, true).await? else {
        return Err(Failure::new(
          "vaultUnavailable",
          "That isn't a file path in the vault.",
        ));
      };
      let mime = crate::uploaders::mime_of(src);
      // replace in place when it exists, so the vault never holds two copies of a file
      let existing = self.find(&parent, &name, false).await?;
      let r = self
        .token
        .send(|| {
          let b = match &existing {
            Some(id) => self
              .http
              .patch(format!("{}/upload/drive/v3/files/{id}", self.api))
              .json(&json!({})),
            None => self
              .http
              .post(format!("{}/upload/drive/v3/files", self.api))
              .json(&json!({ "name": name, "parents": [parent] })),
          };
          b.query(&[("uploadType", "resumable"), ("fields", "id")])
            .header("X-Upload-Content-Length", len.to_string())
            .header("X-Upload-Content-Type", mime)
        })
        .await?;
      if !r.status().is_success() {
        let s = r.status();
        let text = r.text().await.unwrap_or_default();
        if text.contains("storageQuotaExceeded") {
          return Err(Failure::new("diskFull", "Your Google Drive is full.").with(text));
        }
        return Err(status_failure(P, s, &text));
      }
      let url = r
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .filter(|u| u.starts_with("https://") || u.starts_with("http://127.0.0.1:"))
        .ok_or_else(|| Failure::new("uploadRejected", "Google Drive didn't start the upload."))?
        .to_string();
      let r = resumable_put(&self.http, &url, src, P).await?;
      if !r.status().is_success() {
        let s = r.status();
        let text = r.text().await.unwrap_or_default();
        if text.contains("storageQuotaExceeded") {
          return Err(Failure::new("diskFull", "Your Google Drive is full.").with(text));
        }
        return Err(status_failure(P, s, &text));
      }
      Ok(())
    })
  }

  fn describe(&self, rel: &str) -> String {
    let segs = self.segments(rel);
    format!("Google Drive:/{}", segs.join("/"))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Path as AxPath, Query, State};
  use axum::http::{HeaderMap, StatusCode};
  use axum::routing::{get, post, put};
  use axum::{Json, Router};
  use std::sync::Arc;

  /// id, name, parent, folder?, bytes
  type File = (String, String, String, bool, Vec<u8>);
  /// existing id (update) or name + parent (create), bytes so far
  type Session = (Option<String>, String, String, Vec<u8>);

  /// A tiny Drive.
  #[derive(Default)]
  struct Fake {
    base: Mutex<String>,
    files: Mutex<Vec<File>>,
    sessions: Mutex<HashMap<String, Session>>,
    refreshes: Mutex<u32>,
  }
  type S = Arc<Fake>;

  fn authed(h: &HeaderMap) -> bool {
    h.get("authorization").is_some_and(|v| v == "Bearer acc-1")
  }

  /// Parses the two query shapes the vault sends.
  fn matches(q: &str, f: &File) -> bool {
    let parent = q.split('\'').nth(1).unwrap_or("");
    if f.2 != parent {
      return false;
    }
    if let Some(rest) = q.split("name = '").nth(1) {
      let name = rest.split("' and").next().unwrap().replace("\\'", "'");
      if f.1 != name {
        return false;
      }
      return q.contains("mimeType != ") != f.3;
    }
    true
  }

  fn app(s: S) -> Router {
    Router::new()
      .route(
        "/v1/oauth/gdrive/token",
        post(|State(s): State<S>, Json(b): Json<Value>| async move {
          assert_eq!(b["refresh_token"], "ref-1");
          *s.refreshes.lock().unwrap() += 1;
          Json(json!({ "access_token": "acc-1" }))
        }),
      )
      .route(
        "/drive/v3/about",
        get(|| async {
          Json(json!({ "user": { "displayName": "Mara", "emailAddress": "mara@example.com" } }))
        }),
      )
      .route(
        "/drive/v3/files",
        get(
          |State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
            assert!(authed(&h));
            let files = s.files.lock().unwrap();
            let hits: Vec<Value> = files
              .iter()
              .rev()
              .filter(|f| matches(&q["q"], f))
              .map(|f| json!({ "id": f.0, "name": f.1 }))
              .collect();
            Json(json!({ "files": hits }))
          },
        )
        .post(
          |State(s): State<S>, h: HeaderMap, Json(b): Json<Value>| async move {
            assert!(authed(&h));
            assert_eq!(b["mimeType"], FOLDER);
            let mut files = s.files.lock().unwrap();
            let id = format!("f{}", files.len() + 1);
            files.push((
              id.clone(),
              b["name"].as_str().unwrap().into(),
              b["parents"][0].as_str().unwrap().into(),
              true,
              vec![],
            ));
            Json(json!({ "id": id }))
          },
        ),
      )
      .route(
        "/drive/v3/files/{id}",
        get(
          |State(s): State<S>, AxPath(id): AxPath<String>| async move {
            let files = s.files.lock().unwrap();
            files
              .iter()
              .find(|f| f.0 == id)
              .map(|f| f.4.clone())
              .unwrap_or_default()
          },
        ),
      )
      .route(
        "/upload/drive/v3/files",
        post(
          |State(s): State<S>, h: HeaderMap, Json(b): Json<Value>| async move {
            assert!(authed(&h));
            let mut ss = s.sessions.lock().unwrap();
            let sid = format!("s{}", ss.len() + 1);
            ss.insert(
              sid.clone(),
              (
                None,
                b["name"].as_str().unwrap().into(),
                b["parents"][0].as_str().unwrap().into(),
                vec![],
              ),
            );
            let mut hm = HeaderMap::new();
            hm.insert(
              "location",
              format!("{}/session/{sid}", s.base.lock().unwrap())
                .parse()
                .unwrap(),
            );
            (StatusCode::OK, hm)
          },
        ),
      )
      .route(
        "/upload/drive/v3/files/{id}",
        axum::routing::patch(
          |State(s): State<S>, AxPath(id): AxPath<String>| async move {
            let mut ss = s.sessions.lock().unwrap();
            let sid = format!("s{}", ss.len() + 1);
            ss.insert(
              sid.clone(),
              (Some(id), String::new(), String::new(), vec![]),
            );
            let mut hm = HeaderMap::new();
            hm.insert(
              "location",
              format!("{}/session/{sid}", s.base.lock().unwrap())
                .parse()
                .unwrap(),
            );
            (StatusCode::OK, hm)
          },
        ),
      )
      .route(
        "/session/{sid}",
        put(
          |State(s): State<S>,
           AxPath(sid): AxPath<String>,
           h: HeaderMap,
           body: axum::body::Bytes| async move {
            let range = h["content-range"].to_str().unwrap().to_string();
            let total: usize = range.rsplit('/').next().unwrap().parse().unwrap();
            let mut ss = s.sessions.lock().unwrap();
            let sess = ss.get_mut(&sid).unwrap();
            sess.3.extend_from_slice(&body);
            if sess.3.len() < total {
              return (StatusCode::PERMANENT_REDIRECT, Json(Value::Null));
            }
            let mut files = s.files.lock().unwrap();
            let id = match &sess.0 {
              Some(id) => {
                let f = files.iter_mut().find(|f| &f.0 == id).unwrap();
                f.4 = sess.3.clone();
                id.clone()
              }
              None => {
                let id = format!("f{}", files.len() + 1);
                files.push((
                  id.clone(),
                  sess.1.clone(),
                  sess.2.clone(),
                  false,
                  sess.3.clone(),
                ));
                id
              }
            };
            (StatusCode::OK, Json(json!({ "id": id })))
          },
        ),
      )
      .layer(axum::extract::DefaultBodyLimit::disable())
      .with_state(s)
  }

  #[tokio::test]
  async fn drive_vault_makes_folders_once_replaces_files_and_round_trips() {
    let s: S = Arc::default();
    let base = serve(app(s.clone())).await;
    *s.base.lock().unwrap() = base.clone();
    let ep = Endpoints {
      worker: base.clone(),
      google_api: base.clone(),
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    let (label, secret) = connect(
      &http,
      &ep,
      &json!({ "access_token": "first", "refresh_token": "ref-1" }),
    )
    .await
    .unwrap();
    assert_eq!(label, "mara@example.com (Google Drive)");
    assert_eq!(secret, json!({ "refreshToken": "ref-1" }));
    let d = Drive::new(http.clone(), &secret, &ep, "/BunnieHop").unwrap();
    assert!(
      d.list("youtube/mara").await.unwrap().is_empty(),
      "nothing yet, nothing made"
    );
    assert!(s.files.lock().unwrap().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("media.mp4");
    let data: Vec<u8> = (0..(8 * 1024 * 1024 + 77))
      .map(|i| (i % 249) as u8)
      .collect();
    std::fs::write(&big, &data).unwrap();
    d.put(&big, "youtube/mara/2019/it's here/media.mp4")
      .await
      .unwrap();
    let side = dir.path().join("bunniehop.json");
    std::fs::write(&side, b"{\"v\":1}").unwrap();
    d.put(&side, "youtube/mara/bunniehop.json").await.unwrap();
    std::fs::write(&side, b"{\"v\":2}").unwrap();
    d.put(&side, "youtube/mara/bunniehop.json").await.unwrap();
    {
      let files = s.files.lock().unwrap();
      let folders: Vec<&str> = files.iter().filter(|f| f.3).map(|f| f.1.as_str()).collect();
      assert_eq!(
        folders,
        ["BunnieHop", "youtube", "mara", "2019", "it's here"],
        "each folder made once"
      );
      assert_eq!(
        files.iter().filter(|f| f.1 == "bunniehop.json").count(),
        1,
        "replaced, not duplicated"
      );
    }
    // a fresh Drive (next hop) finds everything by name
    let d2 = Drive::new(http, &secret, &ep, "/BunnieHop").unwrap();
    assert_eq!(
      d2.list("youtube/mara").await.unwrap(),
      ["2019", "bunniehop.json"]
    );
    let out = dir.path().join("out/side.json");
    assert!(d2.get("youtube/mara/bunniehop.json", &out).await.unwrap());
    assert_eq!(std::fs::read(&out).unwrap(), b"{\"v\":2}");
    let out2 = dir.path().join("out/media.mp4");
    assert!(d2
      .get("youtube/mara/2019/it's here/media.mp4", &out2)
      .await
      .unwrap());
    assert_eq!(std::fs::read(&out2).unwrap(), data);
    assert!(!d2.get("youtube/nobody/x.mp4", &out2).await.unwrap());
    assert_eq!(
      d2.describe("youtube/mara"),
      "Google Drive:/BunnieHop/youtube/mara"
    );
    assert_eq!(*s.refreshes.lock().unwrap(), 2, "one token per Drive");
  }
}

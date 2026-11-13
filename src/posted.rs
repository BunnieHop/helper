//! What this Helper has already posted (D11, PLAN §9.1). One entry per
//! `<destination>|<account>|<source platform>|<source item>`, kept on the creator's computer
//! only (D8): the destination's post id and public link, and when. A second hop of the same item
//! to the same account finds the entry and posts nothing. The account part is a hash of the
//! platform's own account id, so reconnecting the same account keeps its history.
//!
//! Order per post: `reserve` before the upload starts, `finish` with the result before the hop
//! saves the cell. A reservation left by a crash (not held by this run) means "maybe posted":
//! the creator checks.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

pub enum Seen {
  /// Nothing recorded: go ahead (the slot is now reserved for this run).
  Clear,
  /// Another hop in this run is posting it right now.
  Busy,
  /// Posted before (`state` is `published` or `publishedUnverified`).
  Posted(Value),
  /// A run that stopped was posting it; nobody knows whether it went out.
  Interrupted,
}

pub struct Posted {
  file: PathBuf,
  map: Mutex<(HashMap<String, Value>, HashSet<String>)>,
}

/// Provider upload handles, separate from the duplicate ledger but in the same local directory.
/// A create-new marker is durable before the first mutation. Any existing marker means read-back
/// only, including malformed state. No token, media or credential is stored here.
pub struct UploadHandles {
  dir: PathBuf,
}

impl UploadHandles {
  pub fn new(dir: PathBuf) -> Self {
    Self { dir }
  }

  fn path(&self, key: &str) -> PathBuf {
    self
      .dir
      .join(format!("{}.json", crate::sigv4::sha256_hex(key.as_bytes())))
  }

  pub fn load(&self, key: &str) -> std::io::Result<Option<Value>> {
    match std::fs::read(self.path(key)) {
      Ok(bytes) => serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(std::io::Error::other),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
      Err(e) => Err(e),
    }
  }

  pub fn begin(&self, key: &str, kind: &str) -> std::io::Result<bool> {
    use std::io::Write;
    std::fs::create_dir_all(&self.dir)?;
    crate::config::restrict(&self.dir)?;
    let path = self.path(key);
    let mut file = match std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&path)
    {
      Ok(f) => f,
      Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
      Err(e) => return Err(e),
    };
    crate::config::restrict(&path)?;
    file.write_all(
      json!({"kind":kind,"stage":"starting"})
        .to_string()
        .as_bytes(),
    )?;
    file.sync_all()?;
    Ok(true)
  }

  /// Only for an uploader that knows nothing it created can publish by itself
  /// (an unpublished Threads container), so a later deliberate hop may start fresh.
  pub fn release(&self, key: &str) {
    let _ = std::fs::remove_file(self.path(key));
  }

  pub fn save(&self, key: &str, handle: &Value) -> std::io::Result<()> {
    crate::vault::write_atomic(&self.path(key), handle.to_string().as_bytes())?;
    crate::config::restrict(&self.path(key))
  }
}

impl Posted {
  pub fn open(file: PathBuf) -> Self {
    let map = std::fs::read_to_string(&file)
      .ok()
      .and_then(|s| serde_json::from_str(&s).ok())
      .unwrap_or_default();
    Self {
      file,
      map: Mutex::new((map, HashSet::new())),
    }
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, (HashMap<String, Value>, HashSet<String>)> {
    self.map.lock().unwrap_or_else(|e| e.into_inner())
  }

  fn write(&self, m: &HashMap<String, Value>) {
    if let Ok(s) = serde_json::to_string(m) {
      if crate::vault::write_atomic(&self.file, s.as_bytes()).is_ok() {
        let _ = crate::config::restrict(&self.file);
      }
    }
  }

  /// A finished post (`published` or `publishedUnverified`), without reserving anything.
  pub fn posted(&self, key: &str) -> Option<Value> {
    self
      .lock()
      .0
      .get(key)
      .filter(|e| e["state"] != "reserved")
      .cloned()
  }

  /// Looks the post up and, when it is clear, reserves it for this run (saved to disk first).
  pub fn reserve(&self, key: &str, at: &str) -> Seen {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    match map.get(key) {
      Some(e) if e["state"] == "reserved" => {
        if live.contains(key) {
          Seen::Busy
        } else {
          Seen::Interrupted
        }
      }
      Some(e) => Seen::Posted(e.clone()),
      None => {
        map.insert(key.into(), json!({ "state": "reserved", "at": at }));
        live.insert(key.into());
        self.write(map);
        Seen::Clear
      }
    }
  }

  /// Records the outcome of a reserved post. `None` (the post failed) frees the slot.
  pub fn finish(&self, key: &str, entry: Option<Value>) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    live.remove(key);
    match entry {
      Some(e) => map.insert(key.into(), e),
      None => map.remove(key),
    };
    self.write(map);
  }

  /// Used only after the queue knows no publishing request started.
  pub fn discard_upload(&self, key: &str) {
    if let Some(dir) = self.file.parent() {
      let handles = UploadHandles::new(dir.join("upload-handles"));
      let _ = std::fs::remove_file(handles.path(key));
    }
  }

  /// Every entry, reservations included (`GET /v1/ledger`, D-082).
  pub fn entries(&self) -> HashMap<String, Value> {
    self.lock().0.clone()
  }

  /// Takes in another engine's entries (the browser's, D-082). Only ledger fields are kept. A
  /// reservation without a result comes in as `publishedUnverified` (it may have gone out). An
  /// entry never moves down (`published` > `publishedUnverified` > reserved), and a post this run
  /// is making is left to finish. Returns how many entries changed.
  pub fn merge(&self, incoming: &HashMap<String, Value>) -> usize {
    let rank = |e: &Value| match e["state"].as_str() {
      Some("published") => 3,
      Some("publishedUnverified") => 2,
      Some("reserved") => 1,
      _ => 0,
    };
    let mut g = self.lock();
    let (map, live) = &mut *g;
    let mut changed = 0;
    for (key, e) in incoming {
      if key.len() > 1024 || key.matches('|').count() < 3 || live.contains(key) {
        continue;
      }
      let state = match e["state"].as_str() {
        Some(s @ ("published" | "publishedUnverified")) => s,
        Some("reserved") => "publishedUnverified",
        _ => continue,
      };
      let mut clean = json!({ "state": state });
      for f in ["at", "destUrl", "destItemId", "verifiedAt"] {
        if let Some(v) = e[f].as_str().filter(|v| v.len() <= 2048) {
          clean[f] = json!(v);
        }
      }
      if map.get(key).is_some_and(|old| rank(old) >= rank(&clean)) {
        continue;
      }
      map.insert(key.clone(), clean);
      changed += 1;
    }
    if changed > 0 {
      self.write(map);
    }
    changed
  }

  /// The creator asked to post again on purpose.
  pub fn forget(&self, key: &str) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    if !live.contains(key) && map.remove(key).is_some() {
      self.write(map);
      if let Some(dir) = self.file.parent() {
        let handles = UploadHandles::new(dir.join("upload-handles"));
        let _ = std::fs::remove_file(handles.path(key));
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ledger_merge_keeps_unverified_reservations_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("posted.json");
    let p = Posted::open(f.clone());
    assert!(matches!(p.reserve("yt|acc|export|live", "t"), Seen::Clear));
    p.finish(
      "yt|acc|export|done",
      Some(json!({ "state": "published", "destUrl": "https://x/1", "at": "t" })),
    );
    let incoming: HashMap<String, Value> = serde_json::from_value(json!({
      // the browser was posting it when its tab closed: maybe posted
      "yt|acc|export|cut": { "state": "reserved", "at": "t2" },
      // posted from the browser
      "yt|acc|export|new": { "state": "published", "destUrl": "https://x/2", "destItemId": "2", "at": "t2", "token": "never kept" },
      // never downgrades what the Helper knows
      "yt|acc|export|done": { "state": "publishedUnverified", "at": "t2" },
      // this run is posting it right now: left to finish
      "yt|acc|export|live": { "state": "published", "destUrl": "https://x/3", "at": "t2" },
      // not a ledger entry
      "nonsense": { "state": "published" },
      "yt|acc|export|odd": { "state": "deleted" },
    }))
    .unwrap();
    assert_eq!(p.merge(&incoming), 2);
    let cut = p.posted("yt|acc|export|cut").unwrap();
    assert_eq!(cut["state"], "publishedUnverified");
    let new = p.posted("yt|acc|export|new").unwrap();
    assert_eq!(new["destUrl"], "https://x/2");
    assert!(new.get("token").is_none(), "only ledger fields are kept");
    assert_eq!(
      p.posted("yt|acc|export|done").unwrap()["state"],
      "published"
    );
    assert!(matches!(p.reserve("yt|acc|export|live", "t"), Seen::Busy));
    assert!(p.posted("nonsense").is_none());
    assert!(p.posted("yt|acc|export|odd").is_none());
    // a crash reservation here is replaced by the browser's result
    let q = Posted::open(f.clone());
    assert!(matches!(
      q.reserve("yt|acc|export|live", "t"),
      Seen::Interrupted
    ));
    let back: HashMap<String, Value> = serde_json::from_value(
      json!({ "yt|acc|export|live": { "state": "published", "destUrl": "https://x/3", "at": "t3" } }),
    )
    .unwrap();
    let q = Posted::open(f.clone());
    assert_eq!(q.merge(&back), 1);
    assert_eq!(
      Posted::open(f).posted("yt|acc|export|live").unwrap()["destUrl"],
      "https://x/3",
      "saved to disk"
    );
  }

  #[test]
  fn posted_ledger_survives_restart_and_tells_a_crash_from_a_live_post() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("posted.json");
    let p = Posted::open(f.clone());
    assert!(matches!(p.reserve("k1", "t"), Seen::Clear));
    assert!(matches!(p.reserve("k1", "t"), Seen::Busy));
    p.finish(
      "k1",
      Some(json!({ "state": "published", "destUrl": "https://x/1" })),
    );
    assert!(matches!(p.reserve("k2", "t"), Seen::Clear));
    p.finish("k2", None);
    assert!(matches!(p.reserve("k3", "t"), Seen::Clear));
    // restart: k1 posted, k2 free, k3 was in flight
    let p = Posted::open(f);
    assert!(matches!(p.reserve("k1", "t"), Seen::Posted(e) if e["destUrl"] == "https://x/1"));
    assert!(matches!(p.reserve("k3", "t"), Seen::Interrupted));
    assert!(matches!(p.reserve("k2", "t"), Seen::Clear));
    p.forget("k1");
    assert!(matches!(p.reserve("k1", "t"), Seen::Clear));
  }

  #[test]
  fn upload_handles_survive_restart_and_a_second_begin_cannot_publish_again() {
    let dir = tempfile::tempdir().unwrap();
    let h = UploadHandles::new(dir.path().join("uploads"));
    assert!(h.begin("k", "video").unwrap());
    h.save(
      "k",
      &json!({"kind":"video","stage":"finishing","id":"1","session":"s"}),
    )
    .unwrap();
    let restarted = UploadHandles::new(dir.path().join("uploads"));
    assert!(!restarted.begin("k", "video").unwrap());
    assert_eq!(restarted.load("k").unwrap().unwrap()["id"], "1");
    std::fs::write(restarted.path("k"), b"broken").unwrap();
    assert!(restarted.load("k").is_err());
    assert!(!restarted.begin("k", "video").unwrap());
  }

  #[test]
  fn stopping_before_publish_discards_the_upload_marker() {
    let dir = tempfile::tempdir().unwrap();
    let p = Posted::open(dir.path().join("posted.json"));
    let handles = UploadHandles::new(dir.path().join("upload-handles"));
    handles.begin("k", "video").unwrap();
    p.discard_upload("k");
    assert!(handles.load("k").unwrap().is_none());
  }
}

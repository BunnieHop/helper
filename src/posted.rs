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

  /// The creator asked to post again on purpose.
  pub fn forget(&self, key: &str) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    if !live.contains(key) && map.remove(key).is_some() {
      self.write(map);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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
}

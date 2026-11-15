//! What this Helper has already posted (D11, PLAN §9.1). One entry per
//! `<destination>|<account>|<source platform>|<source item>`, kept on the creator's computer
//! only (D8): the destination's post id and public link, and when. A second hop of the same item
//! to the same account finds the entry and posts nothing. The account part is a hash of the
//! platform's own account id, so reconnecting the same account keeps its history.
//!
//! Order per post: `reserve` before the upload starts, `finish` with the result before the hop
//! saves the cell. A reservation left by a crash (not held by this run) means "maybe posted":
//! the creator checks.
//!
//! Same-file grouping (O-023 as narrowed by O-024, D-122/D-123): an item in a work also answers to
//! `<destination>|<account>|work|<work id>`. `reserve_any` checks every alias of the cell under
//! one lock and reserves under the work key plus the posting member's own key (its "twin", which
//! carries `under`). Entries are never moved or deleted by grouping; an entry under a work key
//! counts only while its `fromItem` is still a member, so a member that split away leaves it inert.

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

/// What `reserve_any` looks for and where it reserves (`works::ledger_aliases` builds it; the
/// rules match `pickAlias` in packages/sidecar, pinned by `works-aliases.json`).
#[derive(Debug, Clone, Default)]
pub struct Want {
  /// Every alias, in order of preference on a tie: the cell's saved key, the work key, absorbed
  /// work keys, the item's own key, the other members' keys.
  pub aliases: Vec<String>,
  /// The current members of the item's work (`<platform>|<id>`). An entry under a work key
  /// (`<dest>|<account>|work|<id>`) counts only while its `fromItem` is one of them.
  pub members: HashSet<String>,
  /// The posting member, `<source platform>|<item>`. Its own key is `<dest>|<account>|<fromItem>`.
  pub from_item: String,
  /// The posting member's own (legacy, 0.2.0) key.
  pub own: String,
  /// `<dest>|<account>|work|<id>` when the item is in a work.
  pub work: Option<String>,
  /// The creator tapped "Post again" on this cell: finished hits are ignored this once.
  pub post_again: bool,
}

/// Where a post is reserved. `key` goes to the uploader (Bluesky's record key and Mastodon's
/// `Idempotency-Key` come from it); `keys` are the ledger entries holding the reservation, which
/// `finish_slot` writes or frees together.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Slot {
  pub key: String,
  pub keys: Vec<String>,
  /// The member that reserved it (`<source platform>|<item>`).
  pub from_item: String,
  /// `post_again` was used for this reservation; the hop clears the cell's flag.
  pub post_again_used: bool,
  /// An earlier attempt under these keys may have reached the platform: the slot resumes a
  /// cut-off reservation. Its keys are never freed after that, only released (D-144).
  pub sent: bool,
}

/// `<dest>|<account>|<rest>` → `(dest|account|, rest)`.
fn split_key(key: &str) -> Option<(&str, &str)> {
  let mut i = key.match_indices('|').map(|(i, _)| i);
  let _ = i.next()?;
  let second = i.next()?;
  Some((&key[..=second], &key[second + 1..]))
}

fn is_work_key(key: &str) -> bool {
  key.split('|').nth(2) == Some("work")
}

/// `published` before `publishedUnverified`; the first alias wins a tie.
/// Among finished posts of one state, the item's own key (`own`) wins, so a post it made on purpose
/// after Post again shows its own link rather than the group's (QA 2026-11-14, N2).
fn best_finished(hits: &[(String, Value)], own: &str) -> Option<(String, Value)> {
  ["published", "publishedUnverified"].iter().find_map(|s| {
    let state = |(_, e): &&(String, Value)| e["state"] == *s;
    hits
      .iter()
      .filter(state)
      .find(|(k, _)| k == own)
      .or_else(|| hits.iter().find(state))
      .cloned()
  })
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

  /// The entries that count for `aliases` (the membership filter applied), in alias order.
  fn hits(map: &HashMap<String, Value>, want: &Want) -> Vec<(String, Value)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for k in &want.aliases {
      if !seen.insert(k.as_str()) {
        continue;
      }
      let Some(e) = map.get(k) else { continue };
      // an entry under a work key with no `fromItem` came from elsewhere: it counts (D11)
      let inert = is_work_key(k)
        && e["fromItem"]
          .as_str()
          .is_some_and(|f| !want.members.contains(f));
      if !inert {
        out.push((k.clone(), e.clone()));
      }
    }
    out
  }

  /// The best finished post across every alias (`published` before `publishedUnverified`),
  /// without reserving anything. A fast path only; `reserve_any` decides.
  pub fn posted_any(&self, want: &Want) -> Option<(String, Value)> {
    let g = self.lock();
    let hits = Self::hits(&g.0, want);
    best_finished(&hits, &want.own)
  }

  /// Whether `from` (`<platform>|<item>`) has a reservation this run is posting right now: a
  /// split of that member is refused (`workBusy`).
  pub fn live_from(&self, from: &str) -> bool {
    let g = self.lock();
    g.1.iter().any(|k| {
      g.0.get(k).is_some_and(|e| {
        e["fromItem"].as_str() == Some(from)
          || (e.get("fromItem").is_none() && split_key(k).is_some_and(|(_, rest)| rest == from))
      })
    })
  }

  /// Checks every alias and reserves under one lock (D11). Precedence across the hits that
  /// count: `published`, then `publishedUnverified`, then a live reservation (`Busy`), then a
  /// cut-off one (`Interrupted`, with the slot to resume); ties go to alias order. With no hit,
  /// reserves under the work key and the posting member's own key (`under` the work key), or the
  /// own key alone outside a work. `post_again` passes over every hit but a live one, once.
  pub fn reserve_any(&self, want: &Want, at: &str) -> (Seen, Slot) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    let hits = Self::hits(map, want);
    let reserved: Vec<&(String, Value)> = hits
      .iter()
      .filter(|(_, e)| e["state"] == "reserved")
      .collect();
    let busy = reserved.iter().any(|(k, _)| live.contains(k));
    if !want.post_again {
      if let Some((k, e)) = best_finished(&hits, &want.own) {
        let slot = Slot {
          key: k,
          ..Slot::default()
        };
        return (Seen::Posted(e), slot);
      }
    }
    if busy {
      return (Seen::Busy, Slot::default());
    }
    if !want.post_again {
      if let Some((k, e)) = reserved.first() {
        let slot = Self::resume_slot(map, live, want, k, e);
        self.write(map);
        return (Seen::Interrupted, slot);
      }
    }
    let mut slot = Slot {
      from_item: want.from_item.clone(),
      post_again_used: want.post_again,
      ..Slot::default()
    };
    match &want.work {
      // a key another item already sent is never sent again: Bluesky's record key and Mastodon's
      // Idempotency-Key come from it, so the platform would answer with that item's post (D-143)
      Some(w)
        if map
          .get(w)
          .is_some_and(|e| e["fromItem"].as_str() != Some(want.from_item.as_str())) =>
      {
        slot.key = want.own.clone();
        slot.keys = vec![want.own.clone()];
      }
      Some(w) => {
        slot.key = w.clone();
        slot.keys = vec![w.clone(), want.own.clone()];
      }
      None => {
        slot.key = want.own.clone();
        slot.keys = vec![want.own.clone()];
      }
    }
    if want.post_again {
      // nothing on these keys is live (checked above): an old upload marker would turn the new
      // post into a read-back of the old one
      for k in &slot.keys {
        self.remove_marker(k);
      }
    }
    Self::put_reserved(map, live, &slot, at);
    self.write(map);
    (Seen::Clear, slot)
  }

  /// The slot a cut-off reservation at `k` resumes under. A twin (`under`) gives the uploader the
  /// work key it was reserved under; if the member has since split away, the resume still holds
  /// and finishes the work key, which stays an inert record of this item (R1, D-143).
  fn resume_slot(
    map: &mut HashMap<String, Value>,
    live: &HashSet<String>,
    want: &Want,
    k: &str,
    e: &Value,
  ) -> Slot {
    let from = e["fromItem"]
      .as_str()
      .map(str::to_string)
      .or_else(|| split_key(k).map(|(_, rest)| rest.to_string()))
      .unwrap_or_default();
    let mut slot = Slot {
      key: k.to_string(),
      keys: vec![k.to_string()],
      from_item: from.clone(),
      post_again_used: false,
      sent: true,
    };
    if let Some(under) = e["under"].as_str() {
      slot.key = under.to_string();
      let ours = |x: &Value| x["state"] == "reserved" && x["fromItem"].as_str() == Some(&from);
      let still_counts = want.aliases.iter().any(|a| a == under) && want.members.contains(&from);
      // the group key went to the platform with the first attempt: it moves with the twin and stays
      // this item's record even after a split, so no other item sends it again (D-143)
      if map.get(under).is_some_and(ours) && (still_counts || !live.contains(under)) {
        slot.keys.insert(0, under.to_string());
      }
    } else if let (Some((prefix, rest)), false) = (split_key(k), from.is_empty()) {
      if rest.starts_with("work|") {
        let twin = format!("{prefix}{from}");
        if map.get(&twin).is_some_and(|x| x["under"] == k) {
          slot.keys.push(twin);
        }
      }
    }
    slot
  }

  fn put_reserved(
    map: &mut HashMap<String, Value>,
    live: &mut HashSet<String>,
    slot: &Slot,
    at: &str,
  ) {
    for k in &slot.keys {
      let mut e = json!({ "state": "reserved", "at": at, "fromItem": slot.from_item });
      if *k != slot.key {
        e["under"] = json!(slot.key);
      }
      map.insert(k.clone(), e);
      live.insert(k.clone());
    }
  }

  /// A cut-off reservation the platform dedupes on: freed and reserved again for this run, every
  /// key of the slot together.
  pub fn retry_slot(&self, slot: &Slot, at: &str) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    for k in &slot.keys {
      map.remove(k);
    }
    Self::put_reserved(map, live, slot, at);
    self.write(map);
  }

  /// Records the outcome under every key of the slot, with `fromItem` (and `under` on the twin),
  /// in one write. `None` (the post failed, or a definite refusal) frees them all.
  pub fn finish_slot(&self, slot: &Slot, entry: Option<Value>) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    for k in &slot.keys {
      live.remove(k);
      match &entry {
        Some(e) => {
          let mut e = e.clone();
          if !slot.from_item.is_empty() {
            e["fromItem"] = json!(slot.from_item);
          }
          if *k != slot.key {
            e["under"] = json!(slot.key);
          }
          map.insert(k.clone(), e);
        }
        None => {
          map.remove(k);
        }
      }
    }
    self.write(map);
  }

  fn remove_marker(&self, key: &str) {
    if let Some(dir) = self.file.parent() {
      let handles = UploadHandles::new(dir.join("upload-handles"));
      let _ = std::fs::remove_file(handles.path(key));
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

  /// A failed attempt on a slot that may already be on the platform (`sent`): its keys stay as a
  /// cut-off reservation with their `fromItem`, so the same item resumes under the same key and
  /// no other item ever sends it (D-144).
  pub fn release_slot(&self, slot: &Slot) {
    let mut g = self.lock();
    let (map, live) = &mut *g;
    for k in &slot.keys {
      live.remove(k);
    }
    self.write(map);
  }

  /// Used only after the queue knows no publishing request started.
  pub fn discard_upload(&self, key: &str) {
    if let Some(dir) = self.file.parent() {
      let handles = UploadHandles::new(dir.join("upload-handles"));
      let _ = std::fs::remove_file(handles.path(key));
    }
  }

  /// Finished posts under `prefix` (`<destination>|<account>|`) made in `[from, to)` (unix ms), the
  /// browser's merged ones included, counted as the browser's `paceRow` counts them: a twin counts
  /// with its group entry, a post found already there doesn't count, an unreadable date doesn't.
  pub fn finished_between(&self, prefix: &str, from: i64, to: i64) -> u32 {
    let g = self.lock();
    let map = &g.0;
    let ms = |e: &Value| {
      let at = e["at"].as_str()?;
      let t =
        time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()?;
      Some((t.unix_timestamp_nanos() / 1_000_000) as i64)
    };
    map
      .iter()
      .filter(|(k, e)| {
        k.starts_with(prefix)
          && matches!(
            e["state"].as_str(),
            Some("published" | "publishedUnverified")
          )
          && e["foundThere"] != true
          && ms(e).is_some_and(|t| t >= from && t < to)
          && !e["under"]
            .as_str()
            .and_then(|u| map.get(u))
            .is_some_and(|g| g["at"] == e["at"])
      })
      .count() as u32
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
      for f in [
        "at",
        "destUrl",
        "destItemId",
        "verifiedAt",
        "fromItem",
        "under",
      ] {
        if let Some(v) = e[f].as_str().filter(|v| v.len() <= 2048) {
          clean[f] = json!(v);
        }
      }
      if e["foundThere"] == true {
        clean["foundThere"] = json!(true);
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
  }

  /// Item `from` (`<src>|<item>`) in work `G` with the other members `others`, to Bluesky.
  fn want(from: &str, others: &[&str], all: &[&str]) -> Want {
    let own = format!("bluesky|acc|{from}");
    let mut aliases = vec!["bluesky|acc|work|G".to_string(), own.clone()];
    aliases.extend(others.iter().map(|o| format!("bluesky|acc|{o}")));
    Want {
      aliases,
      members: all.iter().map(|s| s.to_string()).collect(),
      from_item: from.into(),
      own,
      work: Some("bluesky|acc|work|G".into()),
      post_again: false,
    }
  }

  #[test]
  fn ledger_lookup_prefers_published_across_every_alias() {
    let dir = tempfile::tempdir().unwrap();
    let p = Posted::open(dir.path().join("posted.json"));
    let all = ["youtube|a", "tiktok|b"];
    let incoming: HashMap<String, Value> = serde_json::from_value(json!({
      // a's own key: maybe posted
      "bluesky|acc|youtube|a": { "state": "publishedUnverified", "at": "t1" },
      // b's own key: posted, read back
      "bluesky|acc|tiktok|b": { "state": "published", "destUrl": "https://x/b", "at": "t2" },
      // left under the work by a member that split away: inert
      "bluesky|acc|work|G": { "state": "published", "destUrl": "https://x/gone", "fromItem": "x|left", "at": "t0" },
    }))
    .unwrap();
    p.merge(&incoming);
    let w = want("youtube|a", &["tiktok|b"], &all);
    assert_eq!(p.posted_any(&w).unwrap().1["destUrl"], "https://x/b");
    assert!(
      matches!(p.reserve_any(&w, "t"), (Seen::Posted(e), _) if e["destUrl"] == "https://x/b")
    );
    // the leaving member's post alone never counts for the members that stay
    let q = Posted::open(dir.path().join("q.json"));
    q.merge(&serde_json::from_value(json!({
      "bluesky|acc|work|G": { "state": "published", "destUrl": "https://x/gone", "fromItem": "x|left", "at": "t0" },
    })).unwrap());
    assert!(q.posted_any(&w).is_none());
    let (seen, slot) = q.reserve_any(&w, "t");
    assert!(matches!(seen, Seen::Clear));
    // the group key was sent by the item that left: a posts under its own key alone (D-143)
    assert_eq!(slot.keys, ["bluesky|acc|youtube|a"]);
    let e = q.entries();
    assert_eq!(e["bluesky|acc|work|G"]["fromItem"], "x|left");
    assert!(e["bluesky|acc|youtube|a"]["under"].is_null());
    // a live reservation on any alias outranks a cut-off one; finished outranks both
    let b = want("tiktok|b", &["youtube|a"], &all);
    assert!(matches!(q.reserve_any(&b, "t"), (Seen::Busy, _)));
    // on a group key no one has sent, a reserves under it with its twin
    let z = Posted::open(dir.path().join("z.json"));
    let (_, slot) = z.reserve_any(&w, "t");
    assert_eq!(slot.keys, ["bluesky|acc|work|G", "bluesky|acc|youtube|a"]);
    assert!(matches!(z.reserve_any(&b, "t"), (Seen::Busy, _)));
    let e = z.entries();
    assert_eq!(e["bluesky|acc|youtube|a"]["under"], "bluesky|acc|work|G");
    assert_eq!(e["bluesky|acc|work|G"]["fromItem"], "youtube|a");
    // after a restart the reservation is cut off: it resumes under the work key, both keys held
    let r = Posted::open(dir.path().join("z.json"));
    let (seen, slot) = r.reserve_any(&b, "t");
    assert!(matches!(seen, Seen::Interrupted));
    assert_eq!(slot.key, "bluesky|acc|work|G");
    assert_eq!(slot.from_item, "youtube|a");
    assert_eq!(slot.keys, ["bluesky|acc|work|G", "bluesky|acc|youtube|a"]);
    r.finish_slot(
      &slot,
      Some(json!({ "state": "published", "destUrl": "https://x/a" })),
    );
    assert!(
      matches!(r.reserve_any(&b, "t"), (Seen::Posted(e), _) if e["destUrl"] == "https://x/a")
    );

    // the browser's rules, case by case (packages/sidecar/fixtures/cross/works-aliases.json)
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mono = root.join("../../packages/sidecar/fixtures/cross");
    let fx = if mono.is_dir() {
      mono
    } else {
      root.join("fixtures/sidecar-cross")
    };
    let v: Value =
      serde_json::from_str(&std::fs::read_to_string(fx.join("works-aliases.json")).unwrap())
        .unwrap();
    let doc = crate::works::WorksDoc::parse(&v["doc"].to_string()).unwrap();
    let (dest, account) = (
      v["destination"].as_str().unwrap(),
      v["account"].as_str().unwrap(),
    );
    for (i, c) in v["cases"].as_array().unwrap().iter().enumerate() {
      let name = c["name"].as_str().unwrap();
      let item = crate::works::Ref::new(
        c["item"]["platform"].as_str().unwrap(),
        c["item"]["id"].as_str().unwrap(),
      );
      let mut w = crate::works::ledger_aliases(&doc, &item, dest, account, c["savedKey"].as_str());
      assert_eq!(json!(w.aliases), c["aliases"], "{name}: aliases");
      let reserve_under = w.work.clone().unwrap_or_else(|| w.own.clone());
      assert_eq!(reserve_under, c["reserveUnder"], "{name}: reserveUnder");
      w.post_again = c["postAgain"] == true;
      let p = Posted::open(dir.path().join(format!("case-{i}.json")));
      {
        let mut g = p.lock();
        for (k, e) in c["entries"].as_object().unwrap() {
          let mut e = e.clone();
          if e["live"] == true {
            g.1.insert(k.clone());
          }
          e.as_object_mut().unwrap().remove("live");
          g.0.insert(k.clone(), e);
        }
      }
      let (seen, slot) = p.reserve_any(&w, "t");
      let pick = &c["pick"];
      match (pick["kind"].as_str(), seen) {
        (None, Seen::Clear) => assert_eq!(slot.key, c["reserveKey"], "{name}: reserveKey"),
        (Some("posted"), Seen::Posted(e)) => {
          assert_eq!(e, c["entries"][pick["key"].as_str().unwrap()], "{name}")
        }
        (Some("busy"), Seen::Busy) => {}
        (Some("interrupted"), Seen::Interrupted) => {
          assert!(slot.keys.iter().any(|k| pick["key"] == *k), "{name}")
        }
        (want, _) => panic!("{name}: expected {want:?}"),
      }
    }
  }

  /// The cap counts the browser's posts as the browser counts the Helper's (runner.ts `paceRow`).
  #[test]
  fn finished_posts_today_count_merged_browser_posts_once() {
    let dir = tempfile::tempdir().unwrap();
    let p = Posted::open(dir.path().join("posted.json"));
    let at = "2026-11-12T10:00:00.000Z";
    let from = 1_794_441_600_000; // 2026-11-12T00:00:00Z
    let to = from + 86_400_000;
    let mut b = HashMap::new();
    // a grouped post and its twin: one post
    b.insert(
      "bluesky|acc|work|w1".to_string(),
      json!({ "state": "published", "at": at, "fromItem": "youtube|v1" }),
    );
    b.insert("bluesky|acc|youtube|v1".to_string(), json!({ "state": "published", "at": at, "fromItem": "youtube|v1", "under": "bluesky|acc|work|w1" }));
    // a post the browser couldn't confirm still counts
    b.insert(
      "bluesky|acc|youtube|v2".to_string(),
      json!({ "state": "publishedUnverified", "at": "2026-11-12T11:00:00Z" }),
    );
    // already there, yesterday, another account, another platform: not today's posts here
    b.insert(
      "bluesky|acc|youtube|v3".to_string(),
      json!({ "state": "published", "at": at, "foundThere": true }),
    );
    b.insert(
      "bluesky|acc|youtube|v4".to_string(),
      json!({ "state": "published", "at": "2026-11-11T23:59:59Z" }),
    );
    b.insert(
      "bluesky|other|youtube|v5".to_string(),
      json!({ "state": "published", "at": at }),
    );
    b.insert(
      "mastodon|acc|youtube|v6".to_string(),
      json!({ "state": "published", "at": at }),
    );
    b.insert(
      "bluesky|acc|youtube|v7".to_string(),
      json!({ "state": "published", "at": "not a date" }),
    );
    p.merge(&b);
    assert_eq!(p.finished_between("bluesky|acc|", from, to), 2);
  }

  #[test]
  fn ledger_merge_keeps_work_keys_and_from_item() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("posted.json");
    let p = Posted::open(f.clone());
    let incoming: HashMap<String, Value> = serde_json::from_value(json!({
      "bluesky|acc|work|G": { "state": "published", "fromItem": "tiktok|b", "destUrl": "https://x/1", "at": "t", "token": "never kept" },
      "bluesky|acc|tiktok|b": { "state": "reserved", "fromItem": "tiktok|b", "under": "bluesky|acc|work|G", "at": "t" },
      "soapbox|acc|work|H": { "state": "published", "fromItem": "youtube|c", "foundThere": true, "destUrl": "https://x/2", "at": "t" },
    }))
    .unwrap();
    assert_eq!(p.merge(&incoming), 3);
    let e = Posted::open(f).entries();
    assert_eq!(e["bluesky|acc|work|G"]["fromItem"], "tiktok|b");
    assert!(e["bluesky|acc|work|G"].get("token").is_none());
    assert_eq!(e["bluesky|acc|tiktok|b"]["state"], "publishedUnverified");
    assert_eq!(e["bluesky|acc|tiktok|b"]["under"], "bluesky|acc|work|G");
    assert_eq!(e["bluesky|acc|tiktok|b"]["fromItem"], "tiktok|b");
    assert_eq!(e["soapbox|acc|work|H"]["foundThere"], true);
    // the membership filter still applies to merged entries
    let w = want("youtube|a", &[], &["youtube|a"]);
    assert!(Posted::open(dir.path().join("posted.json"))
      .posted_any(&w)
      .is_none());
  }

  #[test]
  fn post_again_keeps_every_alias_and_posts_once() {
    let dir = tempfile::tempdir().unwrap();
    let p = Posted::open(dir.path().join("posted.json"));
    let handles = UploadHandles::new(dir.path().join("upload-handles"));
    let all = ["youtube|a", "tiktok|b"];
    let b = want("tiktok|b", &["youtube|a"], &all);
    let (_, slot) = p.reserve_any(&b, "t1");
    handles.begin(&slot.key, "video").unwrap();
    handles.begin("bluesky|acc|tiktok|b", "video").unwrap();
    p.finish_slot(
      &slot,
      Some(json!({ "state": "published", "destUrl": "https://x/b" })),
    );
    // a is held back by b's post until the creator taps Post again
    let mut a = want("youtube|a", &["tiktok|b"], &all);
    assert!(matches!(p.reserve_any(&a, "t2"), (Seen::Posted(_), _)));
    a.post_again = true;
    let (seen, slot) = p.reserve_any(&a, "t2");
    assert!(matches!(seen, Seen::Clear));
    assert!(slot.post_again_used);
    // b sent the group key, so a's new post goes under a's own key alone (D-143)
    assert_eq!(slot.keys, ["bluesky|acc|youtube|a"]);
    // b's markers and record stay
    assert!(handles.load("bluesky|acc|work|G").unwrap().is_some());
    assert!(handles.load("bluesky|acc|tiktok|b").unwrap().is_some());
    // a live reservation is never passed, Post again or not
    assert!(matches!(p.reserve_any(&a, "t2"), (Seen::Busy, _)));
    p.finish_slot(
      &slot,
      Some(json!({ "state": "published", "destUrl": "https://x/a" })),
    );
    let e = p.entries();
    assert_eq!(e["bluesky|acc|tiktok|b"]["destUrl"], "https://x/b");
    assert_eq!(e["bluesky|acc|work|G"]["destUrl"], "https://x/b");
    assert_eq!(e["bluesky|acc|work|G"]["fromItem"], "tiktok|b");
    assert_eq!(e["bluesky|acc|youtube|a"]["destUrl"], "https://x/a");
    assert!(e["bluesky|acc|youtube|a"]["under"].is_null());
    // the flag was used once: the next hop of a posts nothing
    a.post_again = false;
    // the group key holds b's post too; a's own post wins the tie, with a's link
    let (seen, slot) = p.reserve_any(&a, "t3");
    assert!(matches!(seen, Seen::Posted(e) if e["destUrl"] == "https://x/a"));
    assert_eq!(slot.key, "bluesky|acc|youtube|a");
  }

  #[test]
  fn post_again_survives_a_ledger_merge() {
    let dir = tempfile::tempdir().unwrap();
    let p = Posted::open(dir.path().join("posted.json"));
    let all = ["youtube|a", "tiktok|b"];
    let before: HashMap<String, Value> = serde_json::from_value(json!({
      "bluesky|acc|work|G": { "state": "published", "fromItem": "tiktok|b", "destUrl": "https://x/old", "at": "t0" },
      "bluesky|acc|youtube|a": { "state": "publishedUnverified", "fromItem": "youtube|a", "at": "t0" },
    }))
    .unwrap();
    p.merge(&before);
    let mut a = want("youtube|a", &["tiktok|b"], &all);
    a.post_again = true;
    let (seen, slot) = p.reserve_any(&a, "t1");
    assert!(matches!(seen, Seen::Clear));
    // the other engine's older copy arrives while the post is in flight: left to finish
    assert_eq!(p.merge(&before), 0);
    p.finish_slot(
      &slot,
      Some(json!({ "state": "published", "destUrl": "https://x/new" })),
    );
    // and after: nothing moves down, the new post stays a's record and b's stays b's
    assert_eq!(p.merge(&before), 0);
    let e = p.entries();
    assert_eq!(slot.key, "bluesky|acc|youtube|a");
    assert_eq!(e["bluesky|acc|work|G"]["destUrl"], "https://x/old");
    assert_eq!(e["bluesky|acc|youtube|a"]["destUrl"], "https://x/new");
    assert_eq!(e["bluesky|acc|youtube|a"]["state"], "published");
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

//! Hop executor (PLAN §4.3, §5). The web app sends a HopPlan with the mapping already done
//! (D-033); the Helper downloads each item once, files it in the vault with its sidecar, hands
//! it to each destination's uploader, and empties temp as it goes. Every change is an event
//! with a sequence number, so a browser that reconnects replays what it missed.
//!
//! D11: a destination that reached `published`/`publishedUnverified`/`skipped` is never posted
//! again, and nothing retries by itself; retries come only from the creator.

use crate::binaries::Tool;
use crate::cloud::{Remote, Remotes};
use crate::exports::Exports;
use crate::pacing::{now_ms, Ledger, Pace};
use crate::posted::Seen;
use crate::server::{iso, Tooling};
use crate::{vault, ytdlp};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use tokio::sync::{broadcast, watch, Semaphore};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What an uploader gets: the source item, the post the web app mapped for this destination
/// (D-033), the media files, and the key that makes a retry publish-only.
pub struct Upload<'a> {
  pub item: &'a Value,
  pub post: Option<&'a Value>,
  pub media: &'a [PathBuf],
  pub idempotency_key: &'a str,
  pub options: &'a Value,
}

#[derive(Debug, Clone)]
pub struct Published {
  pub dest_item_id: String,
  pub dest_url: Option<String>,
  /// The post was read back from the destination after publishing (D12).
  pub verified: bool,
  /// Why an unverified post isn't verified, in the creator's words ("YouTube has this video set
  /// to private."). Shown on the cell.
  pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
  pub code: &'static str,
  pub message: String,
  pub verbatim: Option<String>,
}

impl Failure {
  pub fn new(code: &'static str, message: impl Into<String>) -> Self {
    Self {
      code,
      message: message.into(),
      verbatim: None,
    }
  }
  fn issue(&self) -> Value {
    let mut v = json!({ "code": self.code, "message": self.message });
    if let Some(t) = &self.verbatim {
      v["verbatim"] = json!(t);
    }
    v
  }
}

pub trait Uploader: Send + Sync {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>>;
  /// True when publishing the same upload again can't make a second post (a deterministic
  /// record key, an idempotency key, or a search for the post first). After a crash mid-post
  /// such cells are simply retried; the others come back `publishedUnverified` (D11).
  fn safe_to_retry(&self) -> bool {
    false
  }
}

/// Looks up the uploader for `(platform, connectionId)`; `None` when the platform isn't wired.
pub type Uploaders = Arc<dyn Fn(&str, &str) -> Option<Arc<dyn Uploader>> + Send + Sync>;

/// `(platform, connectionId)` → the account's stable key (`Connection::account`), so what was
/// posted is remembered per account, not per connection record.
pub type Accounts = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
  pub seq: u64,
  pub event: Value,
}

const LOG_CAP: usize = 20_000;
/// A post whose slot is further away than this waits in the hop's "later" list (cap reached,
/// outside posting hours) so the other destinations keep going; shorter gaps are slept inline.
const DEFER_AFTER_MS: i64 = 5 * 60_000;

#[derive(Debug, Clone)]
enum Job {
  Item(usize),
  Retry(String, String),
}

struct Hop {
  id: String,
  plan: Value,
  paused: watch::Sender<bool>,
  cancel: watch::Sender<bool>,
  /// `itemId\u{1f}platform` → DestinationState JSON.
  cells: Mutex<HashMap<String, Value>>,
  queue: Mutex<VecDeque<Job>>,
  /// (unix ms, item, platform): posts waiting for their slot.
  later: Mutex<Vec<(i64, String, String)>>,
  /// Rings when the creator queues a retry while the hop sleeps until a slot.
  wake: tokio::sync::Notify,
  running: Mutex<bool>,
  /// Set for cloud vaults: items are staged in temp, then uploaded here.
  remote: Option<Arc<dyn Remote>>,
}

fn key(item: &str, dest: &str) -> String {
  format!("{item}\u{1f}{dest}")
}

struct Inner {
  seq: u64,
  log: VecDeque<Envelope>,
  hops: HashMap<String, Arc<Hop>>,
}

pub struct Hub {
  inner: Mutex<Inner>,
  tx: broadcast::Sender<Envelope>,
  hops_dir: PathBuf,
  temp_dir: PathBuf,
  vault_dir: PathBuf,
  tools: Arc<Tooling>,
  uploaders: Uploaders,
  /// One download at a time: the creator's connection, paced like a person (PLAN ground rules).
  downloads: Semaphore,
  /// Posts per destination account per day, and the last post time (F8).
  ledger: Ledger,
  /// Export zips handed over for "leave a platform" hops (in temp; deleted when the hop ends).
  exports: Exports,
  /// Cloud vault accounts (Dropbox …), set once at start-up.
  remotes: OnceLock<Remotes>,
  /// What this Helper already posted, across hops (D11).
  posted: crate::posted::Posted,
  /// Account keys for the posted ledger, set once at start-up (else the connection id).
  accounts: OnceLock<Accounts>,
  /// Items in each cloud `bunniehop.json` when it came down (keyed by the local copy's path).
  /// A merged index with fewer items is never pushed back.
  remote_counts: Mutex<HashMap<PathBuf, usize>>,
  /// Accounts whose platform said its daily allowance is used up, and when it resets (ms).
  quota_until: Mutex<HashMap<String, i64>>,
}

/// When a used-up daily allowance comes back. YouTube resets at midnight Pacific: 08:00 UTC is
/// midnight in winter and 01:00 in summer, so it is never early. Other platforms: an hour.
fn quota_reset_ms(platform: &str, now: i64) -> i64 {
  const DAY: i64 = 86_400_000;
  if platform == "youtube" {
    let at = now.div_euclid(DAY) * DAY + 8 * 3_600_000;
    if at > now {
      at
    } else {
      at + DAY
    }
  } else {
    now + 3_600_000
  }
}

/// Items in a sidecar, or `None` when it isn't a readable BunnieHop index.
fn sidecar_items(path: &Path) -> Option<usize> {
  let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
  v["items"].as_array().map(Vec::len)
}

fn index_unreadable() -> Failure {
  Failure::new(
    "vaultUnavailable",
    "BunnieHop couldn't read the index of your backup in the cloud, so it left your backup as it was.",
  )
}

fn now() -> String {
  iso(SystemTime::now())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
  v.get(k).and_then(Value::as_str).unwrap_or("")
}

impl Hub {
  /// Leftover temp files from a previous run are removed at start ("nothing left in temp").
  pub fn new(
    hops_dir: PathBuf,
    temp_dir: PathBuf,
    vault_dir: PathBuf,
    tools: Arc<Tooling>,
    uploaders: Uploaders,
  ) -> Arc<Self> {
    let _ = std::fs::remove_dir_all(&temp_dir);
    let _ = std::fs::create_dir_all(&temp_dir);
    let _ = std::fs::create_dir_all(&hops_dir);
    let (tx, _) = broadcast::channel(4096);
    let exports = Exports::new(temp_dir.join("exports"));
    Arc::new(Self {
      inner: Mutex::new(Inner {
        seq: 0,
        log: VecDeque::new(),
        hops: HashMap::new(),
      }),
      tx,
      temp_dir,
      vault_dir,
      tools,
      uploaders,
      downloads: Semaphore::new(1),
      ledger: Ledger::open(hops_dir.join("usage.json")),
      exports,
      remotes: OnceLock::new(),
      posted: crate::posted::Posted::open(hops_dir.join("posted.json")),
      remote_counts: Mutex::new(HashMap::new()),
      quota_until: Mutex::new(HashMap::new()),
      accounts: OnceLock::new(),
      hops_dir,
    })
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
    self.inner.lock().unwrap_or_else(|e| e.into_inner())
  }

  pub fn emit(&self, mut event: Value) {
    if event.get("at").is_none() {
      event["at"] = json!(now());
    }
    let env = {
      let mut g = self.lock();
      g.seq += 1;
      let env = Envelope { seq: g.seq, event };
      g.log.push_back(env.clone());
      if g.log.len() > LOG_CAP {
        g.log.pop_front();
      }
      env
    };
    let _ = self.tx.send(env);
  }

  /// Events after `since`, then live ones. Subscribes before reading the log so none are lost.
  pub fn subscribe(&self, since: u64) -> (Vec<Envelope>, broadcast::Receiver<Envelope>) {
    let rx = self.tx.subscribe();
    let g = self.lock();
    (
      g.log.iter().filter(|e| e.seq > since).cloned().collect(),
      rx,
    )
  }

  pub fn vault_dir(&self) -> &Path {
    &self.vault_dir
  }

  pub fn set_accounts(&self, a: Accounts) {
    let _ = self.accounts.set(a);
  }

  /// One post's identity across hops: destination, account, source platform, source item. It is
  /// the posted-ledger key and the idempotency key the uploader sees (Bluesky's record key comes
  /// from it), so the same item never lands twice on one account.
  fn post_key(&self, hop: &Hop, item: &str, dest: &str) -> String {
    let conn = hop.plan["destinations"]
      .as_array()
      .into_iter()
      .flatten()
      .find(|d| s(d, "platform") == dest)
      .map(|d| s(d, "connectionId"))
      .unwrap_or("");
    let account = self
      .accounts
      .get()
      .and_then(|a| a(dest, conn))
      .unwrap_or_else(|| conn.to_string());
    let src = match s(&hop.plan["source"], "platform") {
      "" => "source",
      p => p,
    };
    format!("{dest}|{account}|{src}|{item}")
  }

  pub fn set_remotes(&self, r: Remotes) {
    let _ = self.remotes.set(r);
  }

  /// The cloud vault a plan writes to, when it isn't a folder on this computer.
  fn remote_for(&self, plan: &Value) -> Option<Arc<dyn Remote>> {
    let v = plan.get("vault")?;
    if s(v, "kind") == "local" {
      return None;
    }
    (self.remotes.get()?)(s(v, "kind"), s(v, "connectionId"), s(v, "target"))
  }

  /// Where a hop's vault files are written: the vault folder, or a staging copy in temp.
  fn vault_root(&self, hop: &Hop) -> PathBuf {
    if hop.remote.is_some() {
      self.temp_dir.join(&hop.id).join("_vault")
    } else {
      self.vault_dir.clone()
    }
  }

  /// Brings back hops saved by an earlier run (F8 "survives Helper restart"). Running ones carry
  /// on from where they were; a post that was mid-upload is retried only where the destination
  /// can't make a second post, else it comes back `publishedUnverified` for the creator to check.
  /// Stopped and finished hops are loaded so their cells can still be retried from S5.
  pub fn restore(self: &Arc<Self>) -> Vec<String> {
    let mut resumed = Vec::new();
    let Ok(dir) = std::fs::read_dir(&self.hops_dir) else {
      return resumed;
    };
    for e in dir.filter_map(|e| e.ok()) {
      let path = e.path();
      if path.extension().and_then(|x| x.to_str()) != Some("json")
        || path.file_name().and_then(|n| n.to_str()) == Some("usage.json")
      {
        continue;
      }
      let Some(doc) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
      else {
        continue;
      };
      let plan = doc["plan"].clone();
      let id = s(&plan, "id").to_string();
      if id.is_empty() || self.lock().hops.contains_key(&id) {
        continue;
      }
      let status = s(&doc, "status").to_string();
      let mut cells = HashMap::new();
      for (k, v) in doc["cells"].as_object().into_iter().flatten() {
        if let Some((item, dest)) = k.rsplit_once(" → ") {
          cells.insert(key(item, dest), v.clone());
        }
      }
      // in-flight posts from the run that stopped
      for (k, v) in cells.iter_mut() {
        if v["inFlight"] != true {
          continue;
        }
        let dest = k.split('\u{1f}').nth(1).unwrap_or("");
        let conn = plan["destinations"]
          .as_array()
          .into_iter()
          .flatten()
          .find(|d| s(d, "platform") == dest)
          .map(|d| s(d, "connectionId").to_string())
          .unwrap_or_default();
        let safe = (self.uploaders)(dest, &conn).is_some_and(|u| u.safe_to_retry());
        if safe {
          *v = json!({ "state": "pending", "idempotencyKey": v["idempotencyKey"] });
        } else {
          *v = json!({
            "state": "publishedUnverified",
            "idempotencyKey": v["idempotencyKey"],
            "issue": { "code": "publishedUnverified", "message": format!("The Helper stopped while posting this to {dest}. Check {dest}; use Post again only if it isn't there.") },
          });
        }
      }
      let n = plan["items"].as_array().map(Vec::len).unwrap_or(0);
      let dests: Vec<String> = plan["destinations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|d| s(d, "platform").to_string())
        .collect();
      let open = |i: usize| {
        let iid = s(&plan["items"][i], "id");
        dests.iter().any(|d| {
          !matches!(
            cells.get(&key(iid, d)).map(|c| s(c, "state")),
            Some("published" | "publishedUnverified" | "skipped" | "failed")
          )
        })
      };
      let queue: VecDeque<Job> = if status == "running" {
        (0..n).filter(|&i| open(i)).map(Job::Item).collect()
      } else {
        VecDeque::new()
      };
      let remote = self.remote_for(&plan);
      let hop = Arc::new(Hop {
        id: id.clone(),
        plan,
        paused: watch::channel(false).0,
        cancel: watch::channel(status == "stopped").0,
        cells: Mutex::new(cells),
        queue: Mutex::new(queue),
        later: Mutex::new(Vec::new()),
        wake: tokio::sync::Notify::new(),
        running: Mutex::new(false),
        remote,
      });
      let go = !hop
        .queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty();
      self.lock().hops.insert(id.clone(), hop.clone());
      self.persist(&hop);
      if go {
        self.emit(json!({ "type": "hopStarted", "hopId": id }));
        resumed.push(id);
        self.spawn(hop);
      }
    }
    resumed
  }

  pub fn exports(&self) -> &Exports {
    &self.exports
  }

  fn export_zip(&self, hop: &Hop) -> Option<PathBuf> {
    hop
      .plan
      .pointer("/source/exportId")
      .and_then(Value::as_str)
      .and_then(|id| self.exports.path(id))
  }

  /// Checks the plan and starts it. Returns the hop id.
  pub fn start(self: &Arc<Self>, plan: Value) -> Result<String, Failure> {
    let id = s(&plan, "id").to_string();
    if id.is_empty() || id.len() > 100 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
      return Err(Failure::new("unknown", "The hop plan needs an id."));
    }
    let items = plan["items"].as_array().map(Vec::len).unwrap_or(0);
    if items == 0 {
      return Err(Failure::new("unknown", "The hop plan has no items."));
    }
    let remote = self.remote_for(&plan);
    if let Some(v) = plan.get("vault") {
      let kind = s(v, "kind");
      let account = match kind {
        "dropbox" => Some("Dropbox"),
        "google-drive" => Some("Google Drive"),
        _ => None,
      };
      if let (Some(name), None) = (account, &remote) {
        return Err(Failure::new(
          "signInRequired",
          format!("Connect {name} in Settings before using it as the vault."),
        ));
      }
      if kind != "local" && remote.is_none() {
        return Err(Failure::new(
          "notSupported",
          format!("The {kind} vault isn't available in this Helper yet. Use a folder on this computer, Dropbox or Google Drive."),
        ));
      }
    }
    if let Some(x) = plan.pointer("/source/exportId").and_then(Value::as_str) {
      if self.exports.path(x).is_none() {
        return Err(Failure::new(
          "notFound404",
          "The export zip isn't on this Helper any more. Drop it again.",
        ));
      }
    }
    if self.lock().hops.contains_key(&id) {
      return Err(Failure::new("duplicate", "This hop is already running."));
    }
    let hop = Arc::new(Hop {
      id: id.clone(),
      plan,
      paused: watch::channel(false).0,
      cancel: watch::channel(false).0,
      cells: Mutex::new(HashMap::new()),
      queue: Mutex::new((0..items).map(Job::Item).collect()),
      later: Mutex::new(Vec::new()),
      wake: tokio::sync::Notify::new(),
      running: Mutex::new(false),
      remote,
    });
    self.lock().hops.insert(id.clone(), hop.clone());
    self.emit(json!({ "type": "hopStarted", "hopId": id }));
    self.spawn(hop.clone());
    self.persist(&hop);
    Ok(id)
  }

  fn hop(&self, id: &str) -> Result<Arc<Hop>, Failure> {
    self.lock().hops.get(id).cloned().ok_or_else(|| {
      Failure::new(
        "notFound404",
        "No hop with that id is running in this Helper.",
      )
    })
  }

  pub fn pause(&self, id: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    if !*h.paused.borrow() {
      h.paused.send_replace(true);
      self.emit(json!({ "type": "paused", "hopId": id }));
    }
    Ok(())
  }

  pub fn resume(self: &Arc<Self>, id: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    h.paused.send_replace(false);
    Ok(())
  }

  pub fn cancel(&self, id: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    h.cancel.send_replace(true);
    h.queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
    h.later.lock().unwrap_or_else(|e| e.into_inner()).clear();
    if !*h.running.lock().unwrap_or_else(|e| e.into_inner()) {
      self.emit(json!({ "type": "stopped", "hopId": id }));
    }
    Ok(())
  }

  /// F17: stops every hop now; nothing resumes or retries afterwards.
  pub fn stop_all(&self) {
    let hops: Vec<_> = self.lock().hops.values().cloned().collect();
    for h in hops {
      h.cancel.send_replace(true);
      h.queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
      h.later.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
    self.emit(json!({ "type": "stopped" }));
  }

  /// The creator asked to try one cell again (S4). A cell that already reached the
  /// destination is never sent again (D11).
  pub fn retry(self: &Arc<Self>, id: &str, item: &str, dest: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    if *h.cancel.borrow() {
      return Err(Failure::new("stopped", "This hop was stopped."));
    }
    let state = h
      .cells
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .get(&key(item, dest))
      .map(|c| s(c, "state").to_string());
    if matches!(
      state.as_deref(),
      Some("published" | "publishedUnverified" | "skipped")
    ) {
      return Ok(());
    }
    if !plan_has(&h.plan, item, dest) {
      return Err(Failure::new(
        "notFound404",
        "That item isn't part of this hop.",
      ));
    }
    h.queue
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .push_front(Job::Retry(item.into(), dest.into()));
    h.wake.notify_one();
    self.spawn(h);
    Ok(())
  }

  /// The creator chose to post a cell again on purpose ("Post again"): the posted ledger forgets
  /// it and the cell runs once more. The only way past the ledger (D11).
  pub fn post_again(self: &Arc<Self>, id: &str, item: &str, dest: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    if *h.cancel.borrow() {
      return Err(Failure::new("stopped", "This hop was stopped."));
    }
    if !plan_has(&h.plan, item, dest) {
      return Err(Failure::new(
        "notFound404",
        "That item isn't part of this hop.",
      ));
    }
    self.posted.forget(&self.post_key(&h, item, dest));
    self.set_cell(&h, item, dest, json!({ "state": "pending" }));
    self.retry(id, item, dest)
  }

  fn mark_already_posted(&self, hop: &Hop, item: &str, dest: &str, e: Value) {
    let mut st = e.clone();
    st["alreadyPosted"] = e["at"].clone();
    if let Some(o) = st.as_object_mut() {
      o.remove("at");
    }
    self.set_cell(hop, item, dest, st);
  }

  pub fn skip(&self, id: &str, item: &str, dest: &str) -> Result<(), Failure> {
    let h = self.hop(id)?;
    if !plan_has(&h.plan, item, dest) {
      return Err(Failure::new(
        "notFound404",
        "That item isn't part of this hop.",
      ));
    }
    let done = {
      let cells = h.cells.lock().unwrap_or_else(|e| e.into_inner());
      matches!(
        cells.get(&key(item, dest)).map(|c| s(c, "state")),
        Some("published" | "publishedUnverified")
      )
    };
    if !done {
      self.set_cell(&h, item, dest, json!({ "state": "skipped" }));
    }
    Ok(())
  }

  fn spawn(self: &Arc<Self>, hop: Arc<Hop>) {
    {
      let mut r = hop.running.lock().unwrap_or_else(|e| e.into_inner());
      if *r {
        return;
      }
      *r = true;
    }
    let me = self.clone();
    tokio::spawn(async move { me.drive(hop).await });
  }

  async fn drive(self: Arc<Self>, hop: Arc<Hop>) {
    loop {
      if self.wait_unpaused(&hop).await.is_err() {
        break;
      }
      let job = hop
        .queue
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_front();
      let job = match job {
        Some(j) => j,
        None => match self.next_later(&hop).await {
          Ok(Some(j)) => j,
          Ok(None) => continue,
          Err(()) => break,
        },
      };
      match job {
        Job::Item(i) => self.run_item(&hop, i, None).await,
        Job::Retry(item, dest) => {
          if let Some(i) = index_of(&hop.plan, &item) {
            self.run_item(&hop, i, Some(&dest)).await
          }
        }
      }
    }
    *hop.running.lock().unwrap_or_else(|e| e.into_inner()) = false;
    let _ = std::fs::remove_dir_all(self.temp_dir.join(&hop.id));
    if let Some(x) = hop.plan.pointer("/source/exportId").and_then(Value::as_str) {
      let in_use = self.lock().hops.values().any(|h| {
        h.id != hop.id
          && *h.running.lock().unwrap_or_else(|e| e.into_inner())
          && h.plan.pointer("/source/exportId").and_then(Value::as_str) == Some(x)
      });
      if !in_use {
        // an item's vault save failed: the zip is the only full copy, so it is kept too
        let kept = self.kept_dir().join(&hop.id);
        if let (true, Some(zip)) = (kept.is_dir(), self.exports.path(x)) {
          let _ = std::fs::rename(&zip, kept.join("export.zip"));
        }
        self.exports.remove(x);
      }
    }
    if *hop.cancel.borrow() {
      self.emit(json!({ "type": "stopped", "hopId": hop.id }));
    } else {
      self.emit(json!({ "type": "hopFinished", "hopId": hop.id }));
    }
    self.persist(&hop);
  }

  /// The earliest post waiting for its slot, once the slot opens. `Ok(None)`: woken early (a
  /// retry was queued) and the post went back on the list. `Err`: nothing left, or cancelled.
  async fn next_later(&self, hop: &Hop) -> Result<Option<Job>, ()> {
    let first = {
      let mut l = hop.later.lock().unwrap_or_else(|e| e.into_inner());
      let i = (0..l.len()).min_by_key(|&i| l[i].0).ok_or(())?;
      l.swap_remove(i)
    };
    let wait = (first.0 - now_ms()).max(0) as u64;
    let mut c = hop.cancel.subscribe();
    if *c.borrow() {
      return Err(());
    }
    tokio::select! {
      _ = tokio::time::sleep(std::time::Duration::from_millis(wait)) => Ok(Some(Job::Retry(first.1, first.2))),
      _ = c.changed() => Err(()),
      _ = hop.wake.notified() => {
        hop.later.lock().unwrap_or_else(|e| e.into_inner()).push(first);
        Ok(None)
      }
    }
  }

  /// Sleeps `ms` unless the hop is cancelled first.
  async fn sleep(&self, hop: &Hop, ms: i64) -> Result<(), ()> {
    let mut c = hop.cancel.subscribe();
    if *c.borrow() {
      return Err(());
    }
    tokio::select! {
      _ = tokio::time::sleep(std::time::Duration::from_millis(ms.max(0) as u64)) => Ok(()),
      _ = c.changed() => Err(()),
    }
  }

  /// Waits while paused; `Err` once the hop is cancelled.
  async fn wait_unpaused(&self, hop: &Hop) -> Result<(), ()> {
    let mut p = hop.paused.subscribe();
    let mut c = hop.cancel.subscribe();
    loop {
      if *c.borrow() {
        return Err(());
      }
      if !*p.borrow() {
        return Ok(());
      }
      tokio::select! {
        _ = p.changed() => {}
        _ = c.changed() => {}
      }
    }
  }

  fn stage(&self, hop: &Hop, item: &str, dests: &[&Value], stage: &str, progress: Option<f64>) {
    for d in dests {
      let mut ev = json!({ "type": "itemStage", "hopId": hop.id, "itemId": item, "destination": s(d, "platform"), "stage": stage });
      if let Some(p) = progress {
        ev["progress"] = json!((p * 100.0).round() / 100.0);
      }
      self.emit(ev);
    }
  }

  fn set_cell(&self, hop: &Hop, item: &str, dest: &str, mut state: Value) {
    state["idempotencyKey"] = json!(self.post_key(hop, item, dest));
    hop
      .cells
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .insert(key(item, dest), state.clone());
    self.persist(hop);
    self.emit(json!({ "type": "destinationState", "hopId": hop.id, "itemId": item, "destination": dest, "state": state }));
  }

  fn fail_cells(&self, hop: &Hop, item: &str, dests: &[&Value], f: &Failure) {
    for d in dests {
      self.set_cell(
        hop,
        item,
        s(d, "platform"),
        json!({ "state": "failed", "issue": f.issue() }),
      );
    }
  }

  async fn run_item(&self, hop: &Arc<Hop>, idx: usize, only: Option<&str>) {
    let item = &hop.plan["items"][idx];
    let iid = s(item, "id").to_string();
    let all: Vec<&Value> = hop.plan["destinations"]
      .as_array()
      .map(|a| a.iter().collect())
      .unwrap_or_default();
    let mut todo: Vec<&Value> = Vec::new();
    for d in all
      .iter()
      .copied()
      .filter(|d| only.is_none_or(|o| s(d, "platform") == o))
    {
      let p = s(d, "platform");
      let state = hop
        .cells
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key(&iid, p))
        .map(|c| s(c, "state").to_string());
      if matches!(
        state.as_deref(),
        Some("published" | "publishedUnverified" | "skipped")
      ) {
        continue;
      }
      let skipped_in_tune = d
        .pointer("/options/skip")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|x| x == iid.as_str()));
      if skipped_in_tune {
        self.set_cell(hop, &iid, p, json!({ "state": "skipped" }));
        continue;
      }
      todo.push(d);
    }
    let vault_cfg = hop.plan.get("vault").is_some();
    let vault_on = vault_cfg && only.is_none();
    if todo.is_empty() && !vault_on {
      return;
    }
    let folder = hop
      .plan
      .pointer("/vault/folders")
      .and_then(|f| f.get(&iid))
      .and_then(Value::as_str)
      .and_then(vault::safe_folder)
      .unwrap_or_else(|| fallback_folder(&hop.plan, item));
    let root = self.vault_root(hop);
    let vault_item = root.join(&folder);
    let rel = folder.to_string_lossy().replace('\\', "/");
    let temp = self.temp_dir.join(&hop.id).join(
      vault::safe_folder(&iid)
        .map(|_| sanitize(&iid))
        .unwrap_or_else(|| "item".into()),
    );

    // 1. Media: reuse what's already in the vault (incremental re-runs), else download.
    let mut have = vault_cfg && has_media(&vault_item);
    if let (Some(r), false) = (&hop.remote, have) {
      if self
        .pull_media(r.as_ref(), &rel, &vault_item, todo.is_empty())
        .await
      {
        if todo.is_empty() {
          return;
        }
        have = true;
      }
    }
    let media_dir = if have {
      vault_item.clone()
    } else {
      temp.clone()
    };
    // Text posts (an X archive tweet, a Bluesky skeet) have nothing to download.
    let text_only = item.get("url").and_then(Value::as_str).is_none()
      && matches!(s(item, "kind"), "text" | "article" | "link" | "");
    // Export items: media comes out of the zip (or from its own URL), never through yt-dlp,
    // unless the export lacked the file and the item says the Helper must fetch the post.
    let zip = self.export_zip(hop);
    let has_media_entries = item["media"].as_array().is_some_and(|a| !a.is_empty());
    let needs_fetch = item.pointer("/flags/needsHelperFetch") == Some(&json!(true));
    let from_export = zip.is_some() && (has_media_entries || !needs_fetch);
    if from_export && !have {
      let res = match zip {
        Some(z) if has_media_entries => self.export_media(hop, item, &z, &temp, &todo).await,
        _ => std::fs::create_dir_all(&temp)
          .map_err(|e| Failure::new("diskFull", "Couldn't make a temp folder.").with(e)),
      };
      if let Err(f) = res {
        let _ = std::fs::remove_dir_all(&temp);
        self.fail_cells(hop, &iid, &todo, &f);
        if vault_on {
          self.emit(json!({ "type": "issue", "hopId": hop.id, "itemId": iid, "issue": f.issue() }));
        }
        return;
      }
    } else if text_only && !have {
      let _ = std::fs::create_dir_all(&temp);
    } else if !have {
      if let Err(f) = self.download(hop, item, &temp, &todo).await {
        let _ = std::fs::remove_dir_all(&temp);
        if f.code == "stopped" {
          return;
        }
        self.fail_cells(hop, &iid, &todo, &f);
        if vault_on {
          self.emit(json!({ "type": "issue", "hopId": hop.id, "itemId": iid, "issue": f.issue() }));
        }
        return;
      }
    }

    // 2. Vault: move files in, describe them, update bunniehop.json and index.csv.
    let media_dir = if vault_cfg && !have {
      self.stage(hop, &iid, &todo, "sidecar", None);
      let filed = match &hop.remote {
        Some(r) => self.with_remote_sidecar(r.as_ref(), &root, &folder).await,
        None => Ok(()),
      }
      .and_then(|()| self.file_in_vault(hop, &root, item, &folder, &temp));
      let filed = match (filed, &hop.remote) {
        (Ok(()), Some(r)) => self.push_item(r.as_ref(), &root, &folder).await,
        (res, _) => res,
      };
      match filed {
        Ok(()) => vault_item.clone(),
        Err(f) => self.keep_after_vault_failure(hop, &iid, &f, &vault_item, &temp),
      }
    } else {
      media_dir
    };
    let mut media: Vec<PathBuf> = std::fs::read_dir(&media_dir)
      .map(|r| {
        r.filter_map(|e| e.ok().map(|e| e.path()))
          .filter(|p| {
            p.file_name()
              .and_then(|n| n.to_str())
              .and_then(vault::role_of)
              .is_some_and(|(r, _)| r == "media")
          })
          .collect()
      })
      .unwrap_or_default();
    // carousel order: media.1, media.2, … (numeric, so media.10 comes after media.9)
    media.sort_by_key(|p| {
      let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
      let idx = n
        .split('.')
        .nth(1)
        .and_then(|x| x.parse::<u32>().ok())
        .unwrap_or(0);
      (idx, n.to_string())
    });

    // A video or photo post whose media isn't here is never sent as text alone (D12). The download
    // already refuses to finish without media; this also covers vault and export paths.
    let expects_media = if from_export {
      has_media_entries
    } else {
      item.get("url").and_then(Value::as_str).is_some()
        && !matches!(s(item, "kind"), "text" | "article" | "link" | "")
    };
    if expects_media && media.is_empty() && !todo.is_empty() {
      let f = Failure::new(
        "vaultUnavailable",
        "The video or photos for this post weren't found, so nothing was posted. Try it again.",
      );
      self.fail_cells(hop, &iid, &todo, &f);
      let _ = std::fs::remove_dir_all(&temp);
      return;
    }

    // 3. Destinations, one at a time.
    for d in &todo {
      if self.wait_unpaused(hop).await.is_err() {
        break;
      }
      let p = s(d, "platform");
      let state = hop
        .cells
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key(&iid, p))
        .map(|c| s(c, "state").to_string());
      if state.as_deref() == Some("skipped") {
        continue;
      }
      let Some(up) = (self.uploaders)(p, s(d, "connectionId")) else {
        // a platform the Helper posts to, but the planned account isn't connected any more
        let f = if crate::connect::PLATFORMS.contains(&p) {
          Failure::new("signInRequired", format!("The {p} account this hop was planned for isn't connected. Connect it again; BunnieHop never posts to a different account."))
        } else {
          Failure::new(
            "notSupported",
            format!("This Helper can't post to {p} yet."),
          )
        };
        self.set_cell(
          hop,
          &iid,
          p,
          json!({ "state": "failed", "issue": f.issue() }),
        );
        continue;
      };
      // Already on this account from an earlier hop: nothing to send, no pacing slot used (D11).
      let ik = self.post_key(hop, &iid, p);
      if let Some(e) = self.posted.posted(&ik) {
        self.mark_already_posted(hop, &iid, p, e);
        continue;
      }
      // Human pace (F8): the gap since this account's last post, today's cap, posting hours.
      let empty = json!({});
      let pace = Pace::from_plan(d.get("options").unwrap_or(&empty), hop.plan.get("pace"));
      let pkey = format!("{p}:{}", s(d, "connectionId"));
      let slot = self.ledger.slot(&pkey, &pace, now_ms());
      let reset = self
        .quota_until
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&pkey)
        .copied()
        .unwrap_or(0);
      let slot = slot.max(reset);
      let wait = slot - now_ms();
      if wait > 2_000 {
        self.emit(json!({ "type": "itemStage", "hopId": hop.id, "itemId": iid, "destination": p, "stage": "queued", "scheduledAt": iso_ms(slot) }));
      }
      if wait > DEFER_AFTER_MS {
        hop.later.lock().unwrap_or_else(|e| e.into_inner()).push((
          slot,
          iid.clone(),
          p.to_string(),
        ));
        continue;
      }
      if wait > 0
        && (self.sleep(hop, wait).await.is_err() || self.wait_unpaused(hop).await.is_err())
      {
        break;
      }
      match self.posted.reserve(&ik, &now()) {
        Seen::Clear => {}
        Seen::Busy => {
          // another hop is posting this item to this account right now: look again later
          hop.later.lock().unwrap_or_else(|e| e.into_inner()).push((
            now_ms() + 60_000,
            iid.clone(),
            p.to_string(),
          ));
          continue;
        }
        Seen::Posted(e) => {
          self.mark_already_posted(hop, &iid, p, e);
          continue;
        }
        Seen::Interrupted if up.safe_to_retry() => {
          // the platform dedupes on the same key, so posting again finds the first post
          self.posted.finish(&ik, None);
          let _ = self.posted.reserve(&ik, &now());
        }
        Seen::Interrupted => {
          let st = json!({
            "state": "publishedUnverified",
            "issue": { "code": "publishedUnverified", "message": format!("The Helper stopped while posting this to {p}. Check {p}; use Post again only if it isn't there.") },
          });
          self.posted.finish(
            &ik,
            Some(json!({ "state": "publishedUnverified", "at": now() })),
          );
          self.set_cell(hop, &iid, p, st);
          continue;
        }
      }
      let started = now_ms();
      self.ledger.record(&pkey, &pace, started, false);
      // Saved before the upload starts, so a crash mid-post is known after a restart (D11).
      self.set_cell(
        hop,
        &iid,
        p,
        json!({ "state": "pending", "inFlight": true }),
      );
      self.stage(hop, &iid, &[d], "uploading", None);
      let post = d.pointer("/options/posts").and_then(|m| m.get(&iid));
      let res = up
        .publish(Upload {
          item,
          post,
          media: &media,
          idempotency_key: &ik,
          options: d.get("options").unwrap_or(&empty),
        })
        .await;
      match res {
        Ok(pb) => {
          self.ledger.record(&pkey, &pace, started, true);
          let mut st = json!({ "state": if pb.verified { "published" } else { "publishedUnverified" }, "destItemId": pb.dest_item_id });
          if let Some(u) = pb.dest_url {
            st["destUrl"] = json!(u);
          }
          if pb.verified {
            st["verifiedAt"] = json!(now());
          }
          if let Some(n) = pb.note {
            st["issue"] = json!({ "code": "publishedUnverified", "message": n });
          }
          let mut entry = st.clone();
          entry["at"] = json!(now());
          // remembered before the cell is saved, so no later hop can post it again (D11)
          self.posted.finish(&ik, Some(entry));
          self.set_cell(hop, &iid, p, st);
        }
        Err(f) if f.code == "quotaExceeded" => {
          // nothing went out; this post and the account's next ones wait for the reset
          self.posted.finish(&ik, None);
          let until = quota_reset_ms(p, now_ms());
          self
            .quota_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pkey.clone(), until);
          self.set_cell(
            hop,
            &iid,
            p,
            json!({ "state": "pending", "issue": f.issue(), "scheduledAt": iso_ms(until) }),
          );
          self.emit(json!({ "type": "itemStage", "hopId": hop.id, "itemId": iid, "destination": p, "stage": "queued", "scheduledAt": iso_ms(until) }));
          hop.later.lock().unwrap_or_else(|e| e.into_inner()).push((
            until,
            iid.clone(),
            p.to_string(),
          ));
        }
        Err(f) => {
          self.posted.finish(&ik, None);
          self.set_cell(
            hop,
            &iid,
            p,
            json!({ "state": "failed", "issue": f.issue() }),
          )
        }
      }
    }
    let _ = std::fs::remove_dir_all(&temp);
    if hop.remote.is_some() {
      // the staged copy is in the cloud now; only the sidecar stays until the hop ends
      let _ = std::fs::remove_dir_all(&vault_item);
    }
  }

  /// Cloud vault re-runs: is the item's media already there? When posts still need it, the media
  /// comes down into the staging folder (the creator's own copy, not the original platform).
  async fn pull_media(&self, r: &dyn Remote, rel: &str, dest: &Path, list_only: bool) -> bool {
    let names: Vec<String> = match r.list(rel).await {
      Ok(n) => n
        .into_iter()
        .filter(|n| vault::role_of(n).is_some_and(|(role, _)| role == "media"))
        .collect(),
      Err(f) => {
        tracing::warn!(code = f.code, "couldn't list the cloud vault");
        return false;
      }
    };
    if names.is_empty() {
      return false;
    }
    if list_only {
      return true;
    }
    for n in &names {
      if !matches!(r.get(&format!("{rel}/{n}"), &dest.join(n)).await, Ok(true)) {
        let _ = std::fs::remove_dir_all(dest);
        return false;
      }
    }
    true
  }

  /// Brings the cloud copy of `bunniehop.json` into the staging vault once per hop, so the
  /// merge keeps items from earlier hops.
  async fn with_remote_sidecar(
    &self,
    r: &dyn Remote,
    root: &Path,
    folder: &Path,
  ) -> Result<(), Failure> {
    let src = source_rel(folder);
    let local = root.join(&src).join("bunniehop.json");
    if local.is_file() {
      return Ok(());
    }
    let rel = format!(
      "{}/bunniehop.json",
      src.to_string_lossy().replace('\\', "/")
    );
    if !r.get(&rel, &local).await.map_err(vault_failure)? {
      return Ok(());
    }
    match sidecar_items(&local) {
      Some(n) => {
        self
          .remote_counts
          .lock()
          .unwrap_or_else(|e| e.into_inner())
          .insert(local, n);
        Ok(())
      }
      None => {
        // a cut-short or foreign file: merging into it would push a near-empty index back
        let _ = std::fs::remove_file(&local);
        Err(index_unreadable())
      }
    }
  }

  /// Uploads an item folder, then the merged sidecar and index.
  async fn push_item(&self, r: &dyn Remote, root: &Path, folder: &Path) -> Result<(), Failure> {
    let rel = folder.to_string_lossy().replace('\\', "/");
    let dir = root.join(folder);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
      .map_err(|e| Failure::new("vaultUnavailable", "Couldn't read the staged item.").with(e))?
      .filter_map(|e| e.ok().map(|e| e.path()))
      .filter(|p| p.is_file())
      .collect();
    files.sort();
    // one listing per item: a file already in the vault is never replaced, and a listing that
    // fails stops the vault step rather than guessing
    let there: HashSet<String> = r
      .list(&rel)
      .await
      .map_err(vault_failure)?
      .into_iter()
      .collect();
    for f in &files {
      let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("file");
      if there.contains(name) {
        continue;
      }
      r.put(f, &format!("{rel}/{name}"))
        .await
        .map_err(vault_failure)?;
    }
    let src = source_rel(folder);
    let src_rel = src.to_string_lossy().replace('\\', "/");
    let sidecar = root.join(&src).join("bunniehop.json");
    let before = self
      .remote_counts
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .get(&sidecar)
      .copied();
    if let Some(n) = before {
      if sidecar_items(&sidecar).is_none_or(|m| m < n) {
        return Err(index_unreadable());
      }
    }
    for name in ["bunniehop.json", "index.csv"] {
      let p = root.join(&src).join(name);
      if p.is_file() {
        r.put(&p, &format!("{src_rel}/{name}"))
          .await
          .map_err(vault_failure)?;
      }
    }
    Ok(())
  }

  /// An export item's media: out of the zip, else from the entry's own https URL (X media
  /// missing from the archive), as the creator downloading their own post.
  async fn export_media(
    &self,
    hop: &Hop,
    item: &Value,
    zip: &Path,
    temp: &Path,
    dests: &[&Value],
  ) -> Result<(), Failure> {
    let iid = s(item, "id");
    self.stage(hop, iid, dests, "fetching", None);
    let (z, it, t) = (zip.to_path_buf(), item.clone(), temp.to_path_buf());
    let missing = tokio::task::spawn_blocking(move || crate::exports::extract_media(&z, &it, &t))
      .await
      .map_err(|e| Failure::new("unknown", "Reading the export failed.").with(e))??;
    for m in missing {
      let Some(url) = m["url"].as_str().filter(|u| u.starts_with("https://")) else {
        return Err(Failure::new(
          "notFound404",
          "A media file isn't in the export and has no web address to fetch it from.",
        ));
      };
      if *hop.cancel.borrow() {
        return Err(Failure::new("stopped", "Stopped."));
      }
      self.stage(hop, iid, dests, "downloading", None);
      let r = self.tools.http.get(url).send().await.map_err(|e| {
        Failure::new("networkLost", "Couldn't fetch a media file.").with(e.without_url())
      })?;
      if !r.status().is_success() {
        return Err(Failure::new(
          if r.status().as_u16() == 404 {
            "notFound404"
          } else {
            "server5xx"
          },
          format!("The media file answered {}.", r.status()),
        ));
      }
      let bytes = r.bytes().await.map_err(|e| {
        Failure::new("networkLost", "The media download broke off.").with(e.without_url())
      })?;
      std::fs::write(temp.join(crate::exports::fetched_name(&m)), &bytes)
        .map_err(|e| Failure::new("diskFull", "Couldn't write the media file.").with(e))?;
    }
    Ok(())
  }

  async fn download(
    &self,
    hop: &Hop,
    item: &Value,
    temp: &Path,
    dests: &[&Value],
  ) -> Result<(), Failure> {
    let iid = s(item, "id");
    let url = item
      .get("url")
      .and_then(Value::as_str)
      .and_then(ytdlp::checked_url)
      .ok_or_else(|| {
        Failure::new(
          "notFound404",
          "This item has no web address to download from.",
        )
      })?
      .to_string();
    self.stage(hop, iid, dests, "fetching", None);
    let _permit = self
      .downloads
      .acquire()
      .await
      .map_err(|_| Failure::new("stopped", "Stopped."))?;
    if *hop.cancel.borrow() {
      return Err(Failure::new("stopped", "Stopped."));
    }
    let exe = self.tools.ensure(Tool::YtDlp).await.map_err(|e| Failure {
      code: "needsHelper",
      message: e.message,
      verbatim: e.verbatim,
    })?;
    std::fs::create_dir_all(temp)
      .map_err(|e| Failure::new("diskFull", "Couldn't make a temp folder.").with(e))?;
    let youtube = crate::catalog::platform_of(&url, None) == "youtube";
    let tools = ytdlp::Tools {
      ffmpeg: self.tools.ensure(Tool::Ffmpeg).await.ok(),
      deno: if youtube {
        self.tools.ensure(Tool::Deno).await.ok()
      } else {
        None
      },
    };
    let args = ytdlp::download_args(&url, temp, &tools);
    self.stage(hop, iid, dests, "downloading", Some(0.0));
    let mut last = 0.0;
    let res = ytdlp::run(&exe, &args, hop.cancel.subscribe(), |p| {
      if let Some(f) = p.fraction {
        if f - last >= 0.1 || (f >= 1.0 && last < 1.0) {
          last = f;
          self.stage(hop, iid, dests, "downloading", Some(f));
        }
      }
    })
    .await;
    match res {
      Ok(_) if has_media(temp) => Ok(()),
      Ok(_) => Err(Failure::new(
        "unknown",
        "yt-dlp finished but no media file was written.",
      )),
      Err(ytdlp::RunError::Cancelled) => Err(Failure::new("stopped", "Stopped.")),
      Err(ytdlp::RunError::Spawn(v)) => Err(Failure {
        code: "needsHelper",
        message: "The Helper couldn't start yt-dlp.".into(),
        verbatim: Some(v),
      }),
      Err(ytdlp::RunError::Failed { code, verbatim }) => Err(Failure {
        code,
        message: "The download failed.".into(),
        verbatim: Some(verbatim),
      }),
    }
  }

  /// The vault save failed partway. The files may be in temp (the move failed) or in the vault
  /// copy (a later step failed). A local vault copy is the creator's and stays; anything else
  /// moves to `hops/kept/<hop>/<item>`, outside temp, so neither the hop's end nor a restart
  /// deletes it. Returns where the media now is, for the posts.
  fn keep_after_vault_failure(
    &self,
    hop: &Hop,
    iid: &str,
    f: &Failure,
    vault_item: &Path,
    temp: &Path,
  ) -> PathBuf {
    let in_vault = has_media(vault_item);
    if in_vault && hop.remote.is_none() {
      self.emit(json!({ "type": "issue", "hopId": hop.id, "itemId": iid, "issue": f.issue() }));
      return vault_item.to_path_buf();
    }
    let from = if in_vault { vault_item } else { temp };
    let kept = self.kept_dir().join(&hop.id).join(sanitize(iid));
    let moved = vault::move_into(from, &kept);
    let (dir, note) = match moved {
      Ok(_) => (
        kept.clone(),
        " Your files are safe on this computer, in the Helper's Kept folder.",
      ),
      Err(_) => (from.to_path_buf(), ""),
    };
    let mut issue = f.issue();
    issue["message"] = json!(format!("{}{note}", f.message));
    let mut ev = json!({ "type": "issue", "hopId": hop.id, "itemId": iid, "issue": issue });
    if dir == kept {
      ev["keptPath"] = json!(kept.to_string_lossy());
    }
    self.emit(ev);
    dir
  }

  /// Files a failed vault save left behind; never under temp, so they survive restarts.
  fn kept_dir(&self) -> PathBuf {
    self.hops_dir.join("kept")
  }

  fn file_in_vault(
    &self,
    hop: &Hop,
    root: &Path,
    item: &Value,
    folder: &Path,
    temp: &Path,
  ) -> Result<(), Failure> {
    let io = |e: std::io::Error| {
      let code = if e.raw_os_error() == Some(28) {
        "diskFull"
      } else {
        "vaultUnavailable"
      };
      Failure::new(code, "Couldn't write to the vault folder.").with(e)
    };
    let dest = root.join(folder);
    vault::move_into(temp, &dest).map_err(io)?;
    let files = vault::describe(&dest).map_err(io)?;
    let sha = files
      .iter()
      .find(|f| f["role"] == "media")
      .map(|f| f["sha256"].clone());
    let mut entry = item.clone();
    entry["folder"] = json!(folder.to_string_lossy().replace('\\', "/"));
    entry["files"] = Value::Array(files);
    entry["hashes"] = sha.map(|h| json!({ "sha256": h })).unwrap_or(json!({}));
    entry["backedUpAt"] = json!(now());
    let source_dir = root.join(source_rel(folder));
    let src = &hop.plan["source"];
    let handle = folder
      .components()
      .nth(1)
      .and_then(|c| c.as_os_str().to_str())
      .unwrap_or("source")
      .to_string();
    let mut source = json!({ "platform": s(src, "platform"), "handle": if s(src, "handle").is_empty() { handle } else { s(src, "handle").to_string() } });
    if let Some(u) = src.get("url").and_then(Value::as_str) {
      source["url"] = json!(u);
    }
    vault::upsert(&source_dir, source, vec![entry], &now()).map_err(io)?;
    Ok(())
  }

  fn persist(&self, hop: &Hop) {
    let cells: serde_json::Map<String, Value> = hop
      .cells
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .iter()
      .map(|(k, v)| (k.replace('\u{1f}', " → "), v.clone()))
      .collect();
    let status = if *hop.cancel.borrow() {
      "stopped"
    } else if *hop.running.lock().unwrap_or_else(|e| e.into_inner()) {
      "running"
    } else {
      "finished"
    };
    let doc = json!({ "plan": hop.plan, "cells": cells, "status": status, "savedAt": now() });
    let path = self.hops_dir.join(format!("{}.json", hop.id));
    if vault::write_atomic(&path, doc.to_string().as_bytes()).is_ok() {
      let _ = crate::config::restrict(&path);
    }
  }
}

/// `<platform>/<handle>` of an item folder: where bunniehop.json and index.csv live.
fn source_rel(folder: &Path) -> PathBuf {
  folder.components().take(2).collect()
}

/// A cloud vault error keeps its own code when it's about the account (signed out, full).
fn vault_failure(f: Failure) -> Failure {
  match f.code {
    "tokenExpired" | "diskFull" => f,
    _ => Failure {
      code: "vaultUnavailable",
      message: format!("Couldn't save to the cloud vault: {}", f.message),
      verbatim: f.verbatim,
    },
  }
}

pub trait With {
  fn with(self, e: impl std::fmt::Display) -> Self;
}
impl With for Failure {
  fn with(mut self, e: impl std::fmt::Display) -> Self {
    self.verbatim = Some(e.to_string());
    self
  }
}

fn iso_ms(ms: i64) -> String {
  iso(std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64))
}

fn plan_has(plan: &Value, item: &str, dest: &str) -> bool {
  index_of(plan, item).is_some()
    && plan["destinations"]
      .as_array()
      .is_some_and(|a| a.iter().any(|d| s(d, "platform") == dest))
}

fn index_of(plan: &Value, item: &str) -> Option<usize> {
  plan["items"]
    .as_array()?
    .iter()
    .position(|i| s(i, "id") == item)
}

fn has_media(dir: &Path) -> bool {
  std::fs::read_dir(dir).is_ok_and(|r| {
    r.filter_map(|e| e.ok()).any(|e| {
      e.file_name()
        .to_str()
        .and_then(vault::role_of)
        .is_some_and(|(r, _)| r == "media")
    })
  })
}

fn sanitize(s: &str) -> String {
  s.chars()
    .map(|c| {
      if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
        c
      } else {
        '_'
      }
    })
    .take(80)
    .collect()
}

/// Used only when the plan has no folder for an item (older web builds).
fn fallback_folder(plan: &Value, item: &Value) -> PathBuf {
  let src = &plan["source"];
  let platform = sanitize(if s(item, "platform").is_empty() {
    "source"
  } else {
    s(item, "platform")
  });
  let handle = sanitize(if s(src, "handle").is_empty() {
    "source"
  } else {
    s(src, "handle")
  });
  let date = s(item, "publishedAt")
    .get(..10)
    .unwrap_or("undated")
    .to_string();
  let year = date.get(..4).unwrap_or("undated").to_string();
  PathBuf::from(platform)
    .join(handle)
    .join(year)
    .join(format!("{date}_{}", sanitize(s(item, "id"))))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::binaries::Binaries;
  use std::time::Duration;

  /// Writes media.mp4, thumbnail.jpg and info.json into the `-o` folder like yt-dlp would.
  /// URLs containing `fail` error out; `slow` sleeps until killed.
  #[cfg(unix)]
  fn fake_ytdlp(bin: &Path) {
    std::fs::create_dir_all(bin).unwrap();
    let script = bin.join("yt-dlp");
    std::fs::write(
      &script,
      r#"#!/bin/sh
out=""; prev=""
for a; do
  if [ "$prev" = "-o" ] && [ -z "$out" ]; then out="$a"; fi
  prev="$a"; last="$a"
done
dir=$(dirname "$out")
case "$last" in
  *fail*) echo 'ERROR: [youtube] x: Video unavailable. This video has been removed by the uploader' >&2; exit 1 ;;
  *slow*) sleep 30 ;;
esac
printf 'BHP|downloading|5|10|NA|NA|NA\n'
echo media > "$dir/media.mp4"; echo t > "$dir/thumbnail.jpg"; echo '{}' > "$dir/info.info.json"
printf 'BHP|finished|10|10|NA|NA|NA\n'
echo "BHF|$dir/media.mp4"
"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // never fall through to a real ffmpeg/deno on PATH in tests
    for t in ["ffmpeg", "deno"] {
      let p = bin.join(t);
      std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
      std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
  }

  struct Fake {
    calls: Mutex<Vec<String>>,
    times: Mutex<Vec<std::time::Instant>>,
    fail_first: Mutex<bool>,
    fail_code: Mutex<&'static str>,
    safe: bool,
  }
  impl Uploader for Fake {
    fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
      Box::pin(async move {
        self.times.lock().unwrap().push(std::time::Instant::now());
        self.calls.lock().unwrap().push(format!(
          "{}|{}",
          u.idempotency_key,
          u.post
            .map(|p| p["text"].as_str().unwrap_or(""))
            .unwrap_or("-")
        ));
        if u.item.get("url").is_some() && u.item["kind"] != "text" {
          assert!(!u.media.is_empty(), "uploader gets the media file");
        }
        if std::mem::replace(&mut *self.fail_first.lock().unwrap(), false) {
          return Err(Failure::new(
            *self.fail_code.lock().unwrap(),
            "Bluesky answered 502.",
          ));
        }
        Ok(Published {
          note: None,
          dest_item_id: format!("at://{}", s(u.item, "id")),
          dest_url: Some("https://bsky.app/x".into()),
          verified: true,
        })
      })
    }
    fn safe_to_retry(&self) -> bool {
      self.safe
    }
  }

  struct Fx {
    hub: Arc<Hub>,
    fake: Arc<Fake>,
    dir: tempfile::TempDir,
  }

  #[cfg(unix)]
  fn fx(fail_first: bool) -> Fx {
    fx_in(tempfile::tempdir().unwrap(), fail_first, false)
  }

  #[cfg(unix)]
  fn fx_in(dir: tempfile::TempDir, fail_first: bool, safe: bool) -> Fx {
    fake_ytdlp(&dir.path().join("bin"));
    let tools = Arc::new(Tooling::new(Binaries::new(dir.path().join("bin")), false));
    let fake = Arc::new(Fake {
      calls: Mutex::new(vec![]),
      times: Mutex::new(vec![]),
      fail_first: Mutex::new(fail_first),
      fail_code: Mutex::new("server5xx"),
      safe,
    });
    let f2 = fake.clone();
    let ups: Uploaders =
      Arc::new(move |p: &str, _c: &str| (p == "bluesky").then(|| f2.clone() as Arc<dyn Uploader>));
    std::fs::create_dir_all(dir.path().join("tmp/stale")).unwrap();
    let hub = Hub::new(
      dir.path().join("hops"),
      dir.path().join("tmp"),
      dir.path().join("vault"),
      tools,
      ups,
    );
    Fx { hub, fake, dir }
  }

  fn plan(urls: &[(&str, &str)], dests: &[&str]) -> Value {
    json!({
      "id": "hop-1",
      "createdAt": "2026-11-08T00:00:00Z",
      "source": { "platform": "youtube", "handle": "maravee", "url": "https://www.youtube.com/@maravee" },
      "items": urls.iter().map(|(id, u)| json!({ "id": id, "platform": "youtube", "kind": "video", "url": u, "title": format!("Title {id}"), "description": "", "tags": [], "publishedAt": "2026-01-02T10:00:00-05:00" })).collect::<Vec<_>>(),
      "destinations": dests.iter().map(|d| json!({ "platform": d, "connectionId": format!("{d}-1"), "path": "api", "options": { "posts": { "a": { "text": "mapped by the web app" } }, "pace": { "minGapSec": 0, "jitterSec": [0, 0] } } })).collect::<Vec<_>>(),
      "vault": { "kind": "local", "target": "/ignored", "folders": { "a": "youtube/maravee/2026/2026-01-02_title-a_a" } },
    })
  }

  async fn until(hub: &Hub, pred: impl Fn(&Value) -> bool) -> Vec<Value> {
    for _ in 0..200 {
      let (log, _) = hub.subscribe(0);
      let evs: Vec<Value> = log.into_iter().map(|e| e.event).collect();
      if evs.iter().any(&pred) {
        return evs;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
      "timed out; events: {:?}",
      hub
        .subscribe(0)
        .0
        .iter()
        .map(|e| e.event.clone())
        .collect::<Vec<_>>()
    );
  }

  fn finished(e: &Value) -> bool {
    e["type"] == "hopFinished" || e["type"] == "stopped"
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_backs_up_to_the_vault_publishes_once_and_leaves_nothing_in_temp() {
    let f = fx(false);
    assert!(
      !f.dir.path().join("tmp/stale").exists(),
      "stale temp removed at start"
    );
    f.hub
      .start(plan(
        &[
          ("a", "https://www.youtube.com/watch?v=a"),
          ("b", "https://www.youtube.com/watch?v=b"),
        ],
        &["bluesky", "peertube"],
      ))
      .unwrap();
    let evs = until(&f.hub, finished).await;
    assert_eq!(evs.last().unwrap()["type"], "hopFinished");
    let item = f
      .dir
      .path()
      .join("vault/youtube/maravee/2026/2026-01-02_title-a_a");
    assert!(item.join("media.mp4").is_file());
    let side: Value = serde_json::from_str(
      &std::fs::read_to_string(f.dir.path().join("vault/youtube/maravee/bunniehop.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(side["items"].as_array().unwrap().len(), 2);
    let a = side["items"]
      .as_array()
      .unwrap()
      .iter()
      .find(|i| i["id"] == "a")
      .unwrap();
    assert_eq!(a["files"].as_array().unwrap().len(), 3);
    assert_eq!(a["hashes"]["sha256"].as_str().unwrap().len(), 64);
    assert!(f
      .dir
      .path()
      .join("vault/youtube/maravee/index.csv")
      .is_file());
    // b had no folder in the plan: safe fallback layout
    assert!(f
      .dir
      .path()
      .join("vault/youtube/maravee/2026/2026-01-02_b/media.mp4")
      .is_file());
    // the web app's mapped post reaches the uploader (D-033)
    assert_eq!(
      f.fake.calls.lock().unwrap().as_slice(),
      [
        "bluesky|bluesky-1|youtube|a|mapped by the web app",
        "bluesky|bluesky-1|youtube|b|-"
      ]
    );
    let states: Vec<_> = evs
      .iter()
      .filter(|e| e["type"] == "destinationState")
      .map(|e| {
        (
          e["itemId"].as_str().unwrap(),
          e["destination"].as_str().unwrap(),
          e["state"]["state"].as_str().unwrap(),
        )
      })
      .collect();
    assert!(states.contains(&("a", "bluesky", "published")));
    assert!(
      states.contains(&("a", "peertube", "failed")),
      "no PeerTube account connected → honest failure"
    );
    // B2: the planned account isn't connected, so it fails as signed out, never another account
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/hop-1.json")).unwrap())
        .unwrap();
    assert_eq!(
      doc["cells"]["a → peertube"]["issue"]["code"],
      "signInRequired"
    );
    let tmp: Vec<_> = std::fs::read_dir(f.dir.path().join("tmp"))
      .unwrap()
      .collect();
    assert!(tmp.is_empty(), "temp is empty after the hop");
    assert!(f.dir.path().join("hops/hop-1.json").is_file());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_vault_push_failure_keeps_media_and_never_posts_text_only() {
    let f = fx(false);
    let mem = Arc::new(crate::cloud::MemRemote::default());
    *mem.full.lock().unwrap() = true;
    let m2 = mem.clone();
    f.hub
      .set_remotes(Arc::new(move |_: &str, _: &str, _: &str| {
        Some(m2.clone() as Arc<dyn Remote>)
      }));
    let mut p = plan(&[("a", "https://www.youtube.com/watch?v=a")], &["bluesky"]);
    p["vault"] = json!({ "kind": "dropbox", "target": "/BunnieHop", "connectionId": "dropbox-1" });
    f.hub.start(p).unwrap();
    let evs = until(&f.hub, finished).await;
    // the post went out with its video (Fake asserts media is never empty for a video item)
    assert_eq!(f.fake.calls.lock().unwrap().len(), 1);
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/hop-1.json")).unwrap())
        .unwrap();
    assert_eq!(doc["cells"]["a → bluesky"]["state"], "published");
    // the creator is told, and the files survive the hop's end and a restart
    let issue = evs
      .iter()
      .find(|e| e["type"] == "issue" && e["itemId"] == "a")
      .expect("an issue for the failed vault save");
    assert!(issue["issue"]["message"]
      .as_str()
      .unwrap()
      .contains("safe on this computer"));
    let kept = f.dir.path().join("hops/kept/hop-1/a/media.mp4");
    assert!(kept.is_file(), "media kept outside temp");
    let f2 = fx_in(f.dir, false, false);
    assert!(f2.dir.path().join("hops/kept/hop-1/a/media.mp4").is_file());
  }

  #[test]
  fn youtube_quota_resets_after_midnight_pacific_never_before() {
    let h = 3_600_000;
    let day0 = 1_762_560_000_000; // 2025-11-08T00:00:00Z
    assert_eq!(quota_reset_ms("youtube", day0), day0 + 8 * h);
    assert_eq!(quota_reset_ms("youtube", day0 + 8 * h), day0 + 32 * h);
    assert_eq!(quota_reset_ms("youtube", day0 + 20 * h), day0 + 32 * h);
    assert_eq!(quota_reset_ms("bluesky", day0), day0 + h);
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn quota_exceeded_pauses_the_account_until_the_reset_and_posts_nothing_twice() {
    let f = fx(true);
    *f.fake.fail_code.lock().unwrap() = "quotaExceeded";
    f.hub
      .start(plan(
        &[
          ("a", "https://www.youtube.com/watch?v=a"),
          ("b", "https://www.youtube.com/watch?v=b"),
        ],
        &["bluesky"],
      ))
      .unwrap();
    let ev = until(&f.hub, |e| {
      e["type"] == "itemStage" && e["itemId"] == "b" && e["stage"] == "queued"
    })
    .await;
    let soon = iso_ms(now_ms() + 50 * 60_000);
    let queued: Vec<&Value> = ev
      .iter()
      .filter(|e| e["type"] == "itemStage" && e["stage"] == "queued")
      .collect();
    assert_eq!(queued.len(), 2, "both posts wait: {queued:?}");
    assert!(queued
      .iter()
      .all(|e| e["scheduledAt"].as_str().unwrap() > soon.as_str()));
    let a = ev
      .iter()
      .rev()
      .find(|e| e["type"] == "destinationState" && e["itemId"] == "a")
      .unwrap();
    assert_eq!(a["state"]["state"], "pending");
    assert_eq!(a["state"]["issue"]["code"], "quotaExceeded");
    assert_eq!(f.fake.calls.lock().unwrap().len(), 1, "b was never sent");
    assert!(!ev.iter().any(|e| e["type"] == "hopFinished"));
    f.hub.cancel("hop-1").unwrap();
  }

  #[cfg(unix)]
  fn cloud_fx() -> (Fx, Arc<crate::cloud::MemRemote>) {
    let f = fx(false);
    let mem = Arc::new(crate::cloud::MemRemote::default());
    let m2 = mem.clone();
    f.hub
      .set_remotes(Arc::new(move |_: &str, _: &str, _: &str| {
        Some(m2.clone() as Arc<dyn Remote>)
      }));
    (f, mem)
  }

  #[cfg(unix)]
  fn cloud_plan(urls: &[(&str, &str)]) -> Value {
    let mut p = plan(urls, &[]);
    p["vault"]["kind"] = json!("dropbox");
    p["vault"]["target"] = json!("/BunnieHop");
    p["vault"]["connectionId"] = json!("dropbox-1");
    p
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn cloud_listing_error_does_not_overwrite_vault_media() {
    let (f, mem) = cloud_fx();
    let item = "youtube/maravee/2026/2026-01-02_title-a_a";
    mem.files.lock().unwrap().insert(
      format!("{item}/media.mp4"),
      b"the creator's trimmed copy".to_vec(),
    );
    *mem.list_fails.lock().unwrap() = true;
    f.hub
      .start(cloud_plan(&[("a", "https://www.youtube.com/watch?v=a")]))
      .unwrap();
    until(&f.hub, finished).await;
    assert_eq!(
      mem.files.lock().unwrap()[&format!("{item}/media.mp4")],
      b"the creator's trimmed copy",
      "a file already in the vault is never replaced"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn cloud_unreadable_sidecar_never_wipes_the_remote_index() {
    let (f, mem) = cloud_fx();
    let old = vault::new_doc(
      json!({ "platform": "youtube", "handle": "maravee" }),
      "2026-01-01T00:00:00Z",
      vec![
        json!({ "id": "old1", "title": "One", "folder": "youtube/maravee/2025/x" }),
        json!({ "id": "old2", "title": "Two", "folder": "youtube/maravee/2025/y" }),
      ],
    );
    let bytes = vault::serialize(&old).into_bytes();
    mem
      .files
      .lock()
      .unwrap()
      .insert("youtube/maravee/bunniehop.json".into(), bytes.clone());
    *mem.truncate_sidecar.lock().unwrap() = true;
    f.hub
      .start(cloud_plan(&[("a", "https://www.youtube.com/watch?v=a")]))
      .unwrap();
    until(&f.hub, finished).await;
    assert_eq!(
      mem.files.lock().unwrap()["youtube/maravee/bunniehop.json"],
      bytes,
      "the cloud index keeps the earlier items"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn dropbox_vault_hop_merges_the_cloud_sidecar_reuses_media_and_empties_temp() {
    let f = fx(false);
    let mem = Arc::new(crate::cloud::MemRemote::default());
    let old = vault::new_doc(
      json!({ "platform": "youtube", "handle": "maravee" }),
      "2026-01-01T00:00:00Z",
      vec![json!({ "id": "old", "title": "From last year", "folder": "youtube/maravee/2025/x" })],
    );
    mem.files.lock().unwrap().insert(
      "youtube/maravee/bunniehop.json".into(),
      vault::serialize(&old).into_bytes(),
    );
    let m2 = mem.clone();
    f.hub
      .set_remotes(Arc::new(move |kind: &str, conn: &str, target: &str| {
        assert_eq!((kind, conn, target), ("dropbox", "dropbox-1", "/BunnieHop"));
        Some(m2.clone() as Arc<dyn Remote>)
      }));
    let cloud = |mut p: Value, id: &str| {
      p["id"] = json!(id);
      p["vault"]["kind"] = json!("dropbox");
      p["vault"]["target"] = json!("/BunnieHop");
      p["vault"]["connectionId"] = json!("dropbox-1");
      p
    };
    let urls = [("a", "https://www.youtube.com/watch?v=a")];
    f.hub.start(cloud(plan(&urls, &[]), "hop-1")).unwrap();
    until(&f.hub, finished).await;
    let files = mem.files.lock().unwrap().clone();
    let item = "youtube/maravee/2026/2026-01-02_title-a_a";
    assert!(files.contains_key(&format!("{item}/media.mp4")));
    let side: Value = serde_json::from_slice(&files["youtube/maravee/bunniehop.json"]).unwrap();
    let ids: Vec<&str> = side["items"]
      .as_array()
      .unwrap()
      .iter()
      .map(|i| i["id"].as_str().unwrap())
      .collect();
    assert_eq!(ids.len(), 2, "earlier items kept: {ids:?}");
    assert!(ids.contains(&"old") && ids.contains(&"a"));
    assert!(files.contains_key("youtube/maravee/index.csv"));
    assert!(
      !f.dir.path().join("vault/youtube").exists(),
      "nothing in the local vault"
    );
    // a later hop posts from the Dropbox copy; still nothing left behind
    let n = files.len();
    f.hub
      .start(cloud(plan(&urls, &["bluesky"]), "hop-2"))
      .unwrap();
    until(&f.hub, |e| {
      e["type"] == "hopFinished" && e["hopId"] == "hop-2"
    })
    .await;
    assert_eq!(
      f.fake.calls.lock().unwrap().len(),
      1,
      "posted with the cloud media"
    );
    assert_eq!(mem.files.lock().unwrap().len(), n);
    let tmp: Vec<_> = std::fs::read_dir(f.dir.path().join("tmp"))
      .unwrap()
      .collect();
    assert!(tmp.is_empty(), "temp is empty after cloud hops");
  }

  fn paced(mut p: Value, pace: Value) -> Value {
    for d in p["destinations"].as_array_mut().unwrap() {
      d["options"]["pace"] = pace.clone();
    }
    p
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_export_items_take_media_from_the_zip_never_yt_dlp_and_delete_the_copy() {
    let f = fx(false);
    let (id, zp) = f.hub.exports().create().unwrap();
    crate::exports::tests::make_zip(
      &zp,
      &[
        ("twitter-1/data/tweets_media/2-a.jpg", b"JPEG"),
        ("twitter-1/data/tweets_media/2-b.png", b"PNG"),
      ],
    );
    let mut p = plan(&[], &["bluesky"]);
    p["source"] = json!({ "platform": "x", "handle": "maravee", "exportId": id });
    p["items"] = json!([
      { "id": "1", "platform": "x", "kind": "text", "url": "https://x.com/maravee/status/1", "description": "words only", "tags": [], "publishedAt": "2014-05-06T07:08:09Z", "source": { "via": "export" } },
      { "id": "2", "platform": "x", "kind": "carousel", "url": "https://x.com/maravee/status/2", "description": "two pics", "tags": [], "publishedAt": "2015-05-06T07:08:09Z",
        "media": [{ "kind": "image", "path": "twitter-1/data/tweets_media/2-a.jpg" }, { "kind": "image", "path": "twitter-1/data/tweets_media/2-b.png" }], "source": { "via": "export" } },
    ]);
    f.hub.start(p).unwrap();
    let evs = until(&f.hub, finished).await;
    assert_eq!(evs.last().unwrap()["type"], "hopFinished");
    for i in ["1", "2"] {
      assert!(
        evs
          .iter()
          .any(|e| e["itemId"] == i && e["state"]["state"] == "published"),
        "item {i} published: {evs:?}"
      );
    }
    assert!(
      !evs.iter().any(|e| e["stage"] == "downloading"),
      "no yt-dlp for export items"
    );
    let folder = f.dir.path().join("vault/x/maravee/2015/2015-05-06_2");
    assert_eq!(std::fs::read(folder.join("media.1.jpg")).unwrap(), b"JPEG");
    assert_eq!(std::fs::read(folder.join("media.2.png")).unwrap(), b"PNG");
    assert!(!folder.join("media.mp4").exists());
    assert!(
      f.hub.exports().path(&id).is_none(),
      "export copy deleted when the hop ends"
    );
    let left: Vec<_> = std::fs::read_dir(f.dir.path().join("tmp"))
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name() != "exports" || std::fs::read_dir(e.path()).unwrap().next().is_some()
      })
      .collect();
    assert!(left.is_empty(), "nothing left in temp: {left:?}");
  }

  /// A hop file as the previous run left it: `a` posted, `b` mid-upload, `c` not started.
  fn crashed(dir: &Path) {
    let mut p = plan(
      &[
        ("a", "https://www.youtube.com/watch?v=a"),
        ("b", "https://www.youtube.com/watch?v=b"),
        ("c", "https://www.youtube.com/watch?v=c"),
      ],
      &["bluesky"],
    );
    p["id"] = json!("hop-r");
    let doc = json!({
      "plan": p,
      "status": "running",
      "cells": {
        "a → bluesky": { "state": "published", "idempotencyKey": "hop-r:a:bluesky" },
        "b → bluesky": { "state": "pending", "inFlight": true, "idempotencyKey": "hop-r:b:bluesky" },
      },
    });
    std::fs::create_dir_all(dir.join("hops")).unwrap();
    std::fs::write(dir.join("hops/hop-r.json"), doc.to_string()).unwrap();
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_restart_resumes_and_a_post_cut_off_mid_upload_is_never_sent_twice() {
    let dir = tempfile::tempdir().unwrap();
    crashed(dir.path());
    let f = fx_in(dir, false, false);
    assert_eq!(f.hub.restore(), ["hop-r"]);
    let evs = until(&f.hub, finished).await;
    assert_eq!(evs.last().unwrap()["type"], "hopFinished");
    // only c is posted: a was done, b can't be checked on this platform
    assert_eq!(
      f.fake.calls.lock().unwrap().as_slice(),
      ["bluesky|bluesky-1|youtube|c|-"]
    );
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/hop-r.json")).unwrap())
        .unwrap();
    assert_eq!(doc["cells"]["b → bluesky"]["state"], "publishedUnverified");
    assert!(doc["cells"]["b → bluesky"]["issue"]["message"]
      .as_str()
      .unwrap()
      .contains("Post again only if it isn't there"));
    assert_eq!(doc["status"], "finished");
    // a finished hop isn't resumed again, but can still be retried from S5
    assert!(f.hub.restore().is_empty());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_restart_retries_a_cut_off_post_where_the_platform_dedupes() {
    let dir = tempfile::tempdir().unwrap();
    crashed(dir.path());
    let f = fx_in(dir, false, true);
    assert_eq!(f.hub.restore(), ["hop-r"]);
    until(&f.hub, finished).await;
    assert_eq!(
      f.fake.calls.lock().unwrap().as_slice(),
      [
        "bluesky|bluesky-1|youtube|b|-",
        "bluesky|bluesky-1|youtube|c|-"
      ],
      "same idempotency key, so the platform answers with the first post"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn second_hop_of_the_same_item_posts_nothing_until_the_creator_says_post_again() {
    let f = fx(false);
    let urls = [("a", "https://www.youtube.com/watch?v=a")];
    f.hub.start(plan(&urls, &["bluesky"])).unwrap();
    until(&f.hub, finished).await;
    // a new hop (new id, e.g. from another browser) of the same item to the same account
    let mut p2 = plan(&urls, &["bluesky"]);
    p2["id"] = json!("hop-2");
    f.hub.start(p2).unwrap();
    until(&f.hub, |e| {
      e["type"] == "hopFinished" && e["hopId"] == "hop-2"
    })
    .await;
    assert_eq!(
      f.fake.calls.lock().unwrap().len(),
      1,
      "D11: posted once across hops"
    );
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/hop-2.json")).unwrap())
        .unwrap();
    let cell = &doc["cells"]["a → bluesky"];
    assert_eq!(cell["state"], "published");
    assert_eq!(cell["destUrl"], "https://bsky.app/x");
    assert!(cell["alreadyPosted"].is_string());
    // the idempotency key names the account and the source item, not the hop
    assert_eq!(cell["idempotencyKey"], "bluesky|bluesky-1|youtube|a");
    // on purpose: one more post
    f.hub.post_again("hop-2", "a", "bluesky").unwrap();
    for _ in 0..200 {
      if f.fake.calls.lock().unwrap().len() == 2 {
        break;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(f.fake.calls.lock().unwrap().len(), 2);
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_restart_leaves_stopped_hops_stopped() {
    let dir = tempfile::tempdir().unwrap();
    crashed(dir.path());
    let file = dir.path().join("hops/hop-r.json");
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    doc["status"] = json!("stopped");
    std::fs::write(&file, doc.to_string()).unwrap();
    let f = fx_in(dir, false, true);
    assert!(f.hub.restore().is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(f.fake.calls.lock().unwrap().is_empty());
    assert_eq!(
      f.hub.retry("hop-r", "c", "bluesky").unwrap_err().code,
      "stopped"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_export_plan_needs_the_zip_on_this_helper() {
    let f = fx(false);
    let mut p = plan(&[("a", "https://x.com/u/status/1")], &["bluesky"]);
    p["source"]["exportId"] = json!("0123456789abcdef0123456789abcdef");
    assert_eq!(f.hub.start(p).unwrap_err().code, "notFound404");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_pacing_keeps_the_gap_between_posts_on_one_account() {
    let f = fx(false);
    let p = paced(
      plan(
        &[
          ("a", "https://www.youtube.com/watch?v=a"),
          ("b", "https://www.youtube.com/watch?v=b"),
        ],
        &["bluesky"],
      ),
      json!({ "minGapSec": 1, "jitterSec": [0, 0] }),
    );
    f.hub.start(p).unwrap();
    until(&f.hub, finished).await;
    let t = f.fake.times.lock().unwrap().clone();
    assert_eq!(t.len(), 2);
    assert!(
      t[1] - t[0] >= Duration::from_millis(950),
      "second post waited for the gap: {:?}",
      t[1] - t[0]
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_pacing_daily_cap_queues_the_rest_for_tomorrow() {
    let f = fx(false);
    let p = paced(
      plan(
        &[
          ("a", "https://www.youtube.com/watch?v=a"),
          ("b", "https://www.youtube.com/watch?v=b"),
        ],
        &["bluesky"],
      ),
      json!({ "minGapSec": 0, "jitterSec": [0, 0], "dailyCap": 1 }),
    );
    f.hub.start(p).unwrap();
    let evs = until(&f.hub, |e| {
      e["type"] == "itemStage" && e["itemId"] == "b" && e["stage"] == "queued"
    })
    .await;
    let q = evs
      .iter()
      .find(|e| e["type"] == "itemStage" && e["itemId"] == "b" && e["stage"] == "queued")
      .unwrap();
    let at = q["scheduledAt"].as_str().unwrap();
    assert!(
      at > q["at"].as_str().unwrap(),
      "slot is in the future: {at}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
      f.fake.calls.lock().unwrap().len(),
      1,
      "cap of 1: one post today"
    );
    assert!(
      !f.hub.subscribe(0).0.iter().any(|e| finished(&e.event)),
      "the hop waits for tomorrow's slot rather than finishing"
    );
    // b's media is in the vault, so tomorrow's post needs no download; temp is already empty
    assert!(f
      .dir
      .path()
      .join("vault/youtube/maravee/2026/2026-01-02_b/media.mp4")
      .is_file());
    // a second hop on the same account sees today's count (the ledger is shared and on disk)
    let usage: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/usage.json")).unwrap())
        .unwrap();
    assert_eq!(usage["bluesky:bluesky-1"]["count"], 1);
    f.hub.cancel("hop-1").unwrap();
    let evs = until(&f.hub, finished).await;
    assert_eq!(evs.last().unwrap()["type"], "stopped");
    assert_eq!(f.fake.calls.lock().unwrap().len(), 1);
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_retry_is_creator_only_and_never_reposts() {
    let f = fx(true);
    f.hub
      .start(plan(
        &[("a", "https://www.youtube.com/watch?v=a")],
        &["bluesky"],
      ))
      .unwrap();
    let evs = until(&f.hub, finished).await;
    assert!(evs.iter().any(|e| e["type"] == "destinationState"
      && e["state"]["state"] == "failed"
      && e["state"]["issue"]["code"] == "server5xx"));
    assert_eq!(
      f.fake.calls.lock().unwrap().len(),
      1,
      "nothing retries by itself"
    );
    f.hub.retry("hop-1", "a", "bluesky").unwrap();
    until(&f.hub, |e| {
      e["type"] == "destinationState" && e["state"]["state"] == "published"
    })
    .await;
    // retry after success is a no-op (D11)
    f.hub.retry("hop-1", "a", "bluesky").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(f.fake.calls.lock().unwrap().len(), 2);
    // the second run reused the vault copy: still one media file, no temp left
    assert!(std::fs::read_dir(f.dir.path().join("tmp"))
      .unwrap()
      .next()
      .is_none());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_download_errors_are_classified_with_verbatim_text() {
    let f = fx(false);
    f.hub
      .start(plan(
        &[("a", "https://www.youtube.com/watch?v=fail")],
        &["bluesky"],
      ))
      .unwrap();
    let evs = until(&f.hub, finished).await;
    let st = evs
      .iter()
      .find(|e| e["type"] == "destinationState")
      .unwrap();
    assert_eq!(st["state"]["issue"]["code"], "notFound404");
    assert!(st["state"]["issue"]["verbatim"]
      .as_str()
      .unwrap()
      .contains("removed by the uploader"));
    assert!(f.fake.calls.lock().unwrap().is_empty());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_stop_all_kills_the_download_and_cleans_temp() {
    let f = fx(false);
    f.hub
      .start(plan(
        &[
          ("a", "https://www.youtube.com/watch?v=slow"),
          ("b", "https://www.youtube.com/watch?v=b"),
        ],
        &["bluesky"],
      ))
      .unwrap();
    until(&f.hub, |e| e["stage"] == "downloading").await;
    let t0 = std::time::Instant::now();
    f.hub.stop_all();
    let evs = until(&f.hub, |e| e["type"] == "stopped" && e["hopId"] == "hop-1").await;
    assert!(t0.elapsed() < Duration::from_secs(8));
    assert!(!evs.iter().any(|e| e["type"] == "hopFinished"));
    assert!(
      f.fake.calls.lock().unwrap().is_empty(),
      "nothing posted after Stop all"
    );
    assert!(std::fs::read_dir(f.dir.path().join("tmp"))
      .unwrap()
      .next()
      .is_none());
    assert!(
      f.hub.retry("hop-1", "b", "bluesky").is_err(),
      "a stopped hop doesn't restart"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_skip_and_tune_skips_are_never_posted() {
    let f = fx(false);
    let mut p = plan(
      &[
        ("a", "https://www.youtube.com/watch?v=a"),
        ("b", "https://www.youtube.com/watch?v=b"),
      ],
      &["bluesky"],
    );
    p["destinations"][0]["options"]["skip"] = json!(["b"]);
    f.hub.start(p).unwrap();
    let evs = until(&f.hub, finished).await;
    assert!(evs
      .iter()
      .any(|e| e["itemId"] == "b" && e["state"]["state"] == "skipped"));
    assert_eq!(f.fake.calls.lock().unwrap().len(), 1);
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_events_replay_after_a_sequence_number() {
    let f = fx(false);
    f.hub
      .start(plan(
        &[("a", "https://www.youtube.com/watch?v=a")],
        &["bluesky"],
      ))
      .unwrap();
    until(&f.hub, finished).await;
    let (all, _) = f.hub.subscribe(0);
    let (rest, _) = f.hub.subscribe(all[2].seq);
    assert_eq!(rest.len(), all.len() - 3);
    assert!(all.windows(2).all(|w| w[1].seq == w[0].seq + 1));
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn hop_text_posts_publish_without_a_download_and_keep_a_sidecar_entry() {
    let f = fx(false);
    let mut p = plan(&[], &["bluesky"]);
    p["items"] = json!([{ "id": "t1", "platform": "x", "kind": "text", "description": "just words", "tags": [], "publishedAt": "2014-05-06T07:08:09Z" }]);
    f.hub.start(p).unwrap();
    let evs = until(&f.hub, finished).await;
    assert!(evs
      .iter()
      .any(|e| e["itemId"] == "t1" && e["state"]["state"] == "published"));
    assert!(!evs.iter().any(|e| e["stage"] == "downloading"));
    let side =
      std::fs::read_to_string(f.dir.path().join("vault/x/maravee/bunniehop.json")).unwrap();
    assert!(side.contains("just words"));
  }

  #[test]
  fn hop_plan_rejects_an_s3_vault_and_an_unsafe_hop_id() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let dir = tempfile::tempdir().unwrap();
      let tools = Arc::new(Tooling::new(Binaries::new(dir.path().join("bin")), false));
      let hub = Hub::new(
        dir.path().join("h"),
        dir.path().join("t"),
        dir.path().join("v"),
        tools,
        Arc::new(|_: &str, _: &str| None),
      );
      let mut p = plan(&[("a", "https://x.example/a")], &[]);
      p["vault"] = json!({ "kind": "s3", "target": "bucket" });
      assert_eq!(hub.start(p).unwrap_err().code, "notSupported");
      assert_eq!(
        hub
          .start(json!({ "id": "../x", "items": [{}] }))
          .unwrap_err()
          .code,
        "unknown"
      );
    });
  }
}

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
  /// The same-video group this post is for (plan §1.4 item 12), beside the ledger key: the work
  /// the slot was reserved under, else the item's current work. A destination that posts per group
  /// (SoapBox, D-H6P3) derives its dedupe key from it.
  pub work_id: Option<&'a str>,
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

/// Shared with the queue: uploads may be cancelled until the first publishing request starts.
#[derive(Clone)]
pub struct PublishControl {
  cancel: watch::Receiver<bool>,
  publishing: Arc<std::sync::atomic::AtomicBool>,
}

impl PublishControl {
  pub fn new(cancel: watch::Receiver<bool>) -> Self {
    Self {
      cancel,
      publishing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
  }

  pub fn start_publish(&self) -> Result<(), Failure> {
    let stopped = self.cancel.borrow();
    if *stopped {
      return Err(Failure::new("stopped", "Stopped before publishing."));
    }
    self
      .publishing
      .store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stopped);
    Ok(())
  }

  fn started(&self) -> bool {
    self.publishing.load(std::sync::atomic::Ordering::SeqCst)
  }
}

pub trait Uploader: Send + Sync {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>>;
  /// Legacy opaque uploaders are conservatively treated as an in-flight publish. Multi-stage
  /// uploaders override this and call start_publish immediately before their publish request.
  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      control.start_publish()?;
      self.publish(u).await
    })
  }
  /// True when publishing the same upload again can't make a second post (a deterministic
  /// record key, an idempotency key, or a search for the post first). After a crash mid-post
  /// such cells are simply retried; the others come back `publishedUnverified` (D11).
  fn safe_to_retry(&self) -> bool {
    false
  }
  /// The destination posts each same-video group once and needs its group id (D-H6P3, SoapBox):
  /// an item outside a work gets a one-member work before it is reserved.
  fn needs_group_id(&self) -> bool {
    false
  }
  /// A refusal that says the group is already there, with that post's id and link (D-H6P3). The
  /// cell becomes a skip with the link, recorded with `foundThere`.
  fn existing_post(&self, _f: &Failure) -> Option<Published> {
    None
  }
  /// Is a post saved in the ledger still there? `Some` only for destinations that can say so.
  /// `Ok(false)` (gone, a 404) lets the cell post again in the same run; anything else keeps the
  /// skip.
  fn recheck<'a>(&'a self, _dest_item_id: &'a str) -> Option<BoxFut<'a, Result<bool, Failure>>> {
    None
  }
}

/// How long a saved-link re-check may take before the skip is kept.
#[cfg(not(test))]
const RECHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
#[cfg(test)]
const RECHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

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
  /// Same-video groups (O-023, O-024): which items post once between them.
  works: crate::works::Works,
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
      works: crate::works::Works::open(hops_dir.join("works.json")),
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

  /// The posted ledger, for the browser engine to merge (`GET /v1/ledger`, D-082).
  pub fn ledger(&self) -> HashMap<String, Value> {
    self.posted.entries()
  }

  /// The browser engine's posts, merged in so this Helper never posts them again (D11).
  pub fn merge_ledger(&self, entries: &HashMap<String, Value>) -> usize {
    self.posted.merge(entries)
  }

  pub fn set_accounts(&self, a: Accounts) {
    let _ = self.accounts.set(a);
  }

  /// Same-video groups (`/v1/works`).
  pub fn works(&self) -> &crate::works::Works {
    &self.works
  }

  fn account(&self, hop: &Hop, dest: &str) -> String {
    let conn = hop.plan["destinations"]
      .as_array()
      .into_iter()
      .flatten()
      .find(|d| s(d, "platform") == dest)
      .map(|d| s(d, "connectionId"))
      .unwrap_or("");
    self
      .accounts
      .get()
      .and_then(|a| a(dest, conn))
      .unwrap_or_else(|| conn.to_string())
  }

  /// `<source platform>|<item>`: the item as works and the ledger's `fromItem` name it.
  fn item_ref(hop: &Hop, item: &str) -> crate::works::Ref {
    let src = match s(&hop.plan["source"], "platform") {
      "" => "source",
      p => p,
    };
    crate::works::Ref::new(src, item)
  }

  /// One item's own identity across hops: destination, account, source platform, source item (the
  /// 0.2.0 key). It stays valid for good; grouping adds aliases, never replaces it.
  fn post_key(&self, hop: &Hop, item: &str, dest: &str) -> String {
    let r = Self::item_ref(hop, item);
    crate::works::legacy_key(dest, &self.account(hop, dest), &r.platform, &r.id)
  }

  /// Every ledger key the cell answers to, from the current works (plan §1.4), with the cell's
  /// saved key first and its one-time "Post again" flag.
  fn want(&self, hop: &Hop, item: &str, dest: &str) -> crate::posted::Want {
    let cell = hop
      .cells
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .get(&key(item, dest))
      .cloned()
      .unwrap_or(Value::Null);
    let r = Self::item_ref(hop, item);
    let mut w = self.works.aliases(
      &r,
      dest,
      &self.account(hop, dest),
      cell["idempotencyKey"].as_str(),
    );
    w.post_again = cell["postAgain"] == true;
    w
  }

  /// The works copies in the hop's vault, read as a union before the hop (plan §1.2).
  async fn pull_works(&self, hop: &Hop) {
    match (&hop.remote, hop.plan.get("vault")) {
      (Some(r), _) => {
        let temp = self.temp_dir.join(&hop.id);
        if let Err(f) = self.works.pull_remote(r.as_ref(), &temp).await {
          tracing::warn!(code = f.code, "couldn't read the shared same-video lists");
        }
      }
      (None, Some(_)) => {
        self.works.pull_local(&self.vault_dir);
      }
      (None, None) => {}
    }
  }

  /// This Helper's own copy, written into the hop's vault for other devices.
  async fn push_works(&self, hop: &Hop) {
    match (&hop.remote, hop.plan.get("vault")) {
      (Some(r), _) => {
        let temp = self.temp_dir.join(&hop.id);
        if let Err(f) = self.works.push_remote(r.as_ref(), &temp).await {
          tracing::warn!(code = f.code, "couldn't save the shared same-video list");
        }
      }
      (None, Some(_)) => {
        if let Err(e) = self.works.push_local(&self.vault_dir) {
          tracing::warn!(error = %e, "couldn't save the shared same-video list");
        }
      }
      (None, None) => {}
    }
  }

  /// Records what this hop saw of a video (plan §1.3): its sha256 when the file may group, else
  /// only the listing fields the look-alike note reads.
  async fn observe_item(&self, hop: &Hop, item: &Value, media: &[PathBuf], known: Option<String>) {
    if !matches!(s(item, "kind"), "video" | "short") {
      return;
    }
    let size = media
      .first()
      .and_then(|p| std::fs::metadata(p).ok())
      .map(|m| m.len());
    let duration = item.get("durationSec").and_then(Value::as_f64);
    let groupable = crate::works::is_groupable(s(item, "kind"), media.len(), size, duration);
    let sha = match (groupable, known) {
      (false, _) => None,
      (true, Some(h)) => Some(h),
      (true, None) => {
        let p = media[0].clone();
        tokio::task::spawn_blocking(move || vault::sha256_file(&p).ok().map(|(h, _)| h))
          .await
          .ok()
          .flatten()
      }
    };
    let text = |k: &str| {
      item
        .get(k)
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
    };
    let rec = crate::works::SeenRec {
      sha256: sha,
      size_bytes: size.filter(|n| *n > 0),
      duration_sec: duration.and_then(crate::works::js_number),
      title: text("title"),
      text: text("description").map(|t| crate::works::cut_text(&t)),
      url: text("url"),
      seen_at: now(),
    };
    if self
      .works
      .observe(&Self::item_ref(hop, s(item, "id")), rec, groupable)
    {
      self.push_works(hop).await;
    }
  }

  /// "Not the same video" on a cell (plan §3): the item leaves its group and only that cell runs
  /// again. Refused (`workBusy`) while the item is posting.
  pub fn not_same(self: &Arc<Self>, id: &str, item: &str, dest: &str) -> Result<(), Failure> {
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
    let r = Self::item_ref(&h, item);
    self.works.split(&r, self.posted.live_from(&r.key()))?;
    // the cell's rerun pushes the split to the hop's vault when its drive starts again
    self.set_cell(&h, item, dest, json!({ "state": "pending" }));
    self.retry(id, item, dest)
  }

  /// Records items backed up before grouping existed (`Works::backfill`) from the local vault.
  /// Reads sidecars only; it hashes nothing and takes no hop lock.
  pub fn backfill_seen(&self) -> usize {
    self.works.backfill(&self.vault_dir)
  }

  /// No hop is running on this Helper.
  pub fn idle(&self) -> bool {
    !self
      .lock()
      .hops
      .values()
      .any(|h| *h.running.lock().unwrap_or_else(|e| e.into_inner()))
  }

  #[cfg(test)]
  pub fn posted_for_test(&self) -> &crate::posted::Posted {
    &self.posted
  }

  /// Splits a member from Settings → Same videos (`POST /v1/works/split`).
  pub fn split_member(&self, member: &crate::works::Ref) -> Result<(), Failure> {
    self
      .works
      .split(member, self.posted.live_from(&member.key()))
  }

  /// Destinations each `seen` video already reached (finished ledger entries), for the
  /// look-alike note.
  pub fn posted_to(&self, r: &crate::works::Ref) -> Vec<String> {
    let from = r.key();
    let tail = format!("|{from}");
    self
      .posted
      .entries()
      .into_iter()
      .filter(|(k, e)| {
        matches!(
          e["state"].as_str(),
          Some("published" | "publishedUnverified")
        ) && (e["fromItem"].as_str() == Some(from.as_str()) || k.ends_with(&tail))
      })
      .filter_map(|(k, _)| k.split('|').next().map(str::to_string))
      .collect()
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
        || matches!(
          path.file_name().and_then(|n| n.to_str()),
          Some("usage.json" | "works.json")
        )
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
    // a one-time flag on the cell, used and cleared by the next reservation: nothing is deleted,
    // so no other member's record or upload marker is touched (Revision 3, R2)
    self.set_cell(
      &h,
      item,
      dest,
      json!({ "state": "pending", "postAgain": true }),
    );
    self.retry(id, item, dest)
  }

  /// The cell shows the earlier post. When it came from another video of the item's group, the
  /// cell names it (`sameAs`) and offers "Not the same video".
  /// A failed, refused or stopped attempt: the keys are freed only when no attempt under them
  /// could have reached the platform; otherwise they stay a cut-off reservation (D-144).
  fn free_or_release(&self, slot: &crate::posted::Slot) {
    if slot.sent {
      self.posted.release_slot(slot);
    } else {
      self.posted.finish_slot(slot, None);
    }
  }

  fn mark_already_posted(&self, hop: &Hop, item: &str, dest: &str, hit: &str, e: Value) {
    let mut st = e.clone();
    st["alreadyPosted"] = e["at"].clone();
    let own = Self::item_ref(hop, item);
    let from = e["fromItem"].as_str().map(str::to_string).or_else(|| {
      let mut parts = hit.splitn(3, '|');
      let rest = parts.nth(2)?;
      (!rest.starts_with("work|")).then(|| rest.to_string())
    });
    if let Some(r) = from
      .as_deref()
      .and_then(crate::works::Ref::parse)
      .filter(|r| *r != own)
    {
      let via = self
        .works
        .work_of(&own)
        .and_then(|w| {
          w.members
            .iter()
            .find(|m| m.platform == r.platform && m.id == r.id)
            .map(|m| m.via.clone())
        })
        .unwrap_or_else(|| "sha256".into());
      let mut same = json!({ "platform": r.platform, "id": r.id, "via": via });
      if let Some(t) = self.works.seen(&r).and_then(|x| x.title) {
        same["title"] = json!(t);
      }
      st["sameAs"] = same;
    }
    if let Some(o) = st.as_object_mut() {
      for f in ["at", "fromItem", "under", "foundThere"] {
        o.remove(f);
      }
    }
    self.set_cell(hop, item, dest, st);
  }

  /// A saved link the destination can re-check (D-H6P3): `true` only when it answered that the
  /// post is gone. A timeout or any other answer keeps the skip.
  async fn saved_link_gone(&self, up: &dyn Uploader, e: &Value) -> bool {
    let Some(id) = e["destItemId"].as_str().filter(|i| !i.is_empty()) else {
      return false;
    };
    let Some(check) = up.recheck(id) else {
      return false;
    };
    matches!(
      tokio::time::timeout(RECHECK_TIMEOUT, check).await,
      Ok(Ok(false))
    )
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
    self.pull_works(&hop).await;
    if self.works.unreadable() {
      self.emit(json!({ "type": "issue", "hopId": hop.id, "issue": { "code": "worksUnreadable", "message": crate::works::UNREADABLE_LINE } }));
    }
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
    self.push_works(&hop).await;
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

  /// Saves a cell. Its ledger key is kept from the cell (set when the post is reserved), or the
  /// item's own key for a cell that never reserved. A pending "Post again" flag stays on the cell
  /// until a reservation uses it.
  fn set_cell(&self, hop: &Hop, item: &str, dest: &str, mut state: Value) {
    {
      let mut cells = hop.cells.lock().unwrap_or_else(|e| e.into_inner());
      let old = cells.get(&key(item, dest));
      if !state["idempotencyKey"].is_string() {
        state["idempotencyKey"] = old
          .map(|c| c["idempotencyKey"].clone())
          .filter(Value::is_string)
          .unwrap_or_else(|| json!(self.post_key(hop, item, dest)));
      }
      let waiting =
        state["state"] == "failed" || (state["state"] == "pending" && state["inFlight"] != true);
      if state.get("postAgain").is_none() && waiting && old.is_some_and(|c| c["postAgain"] == true)
      {
        state["postAgain"] = json!(true);
      }
      cells.insert(key(item, dest), state.clone());
    }
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
    let mut filed_sha = None;
    let media_dir = if vault_cfg && !have {
      self.stage(hop, &iid, &todo, "sidecar", None);
      let filed = match &hop.remote {
        Some(r) => self.with_remote_sidecar(r.as_ref(), &root, &folder).await,
        None => Ok(()),
      }
      .and_then(|()| self.file_in_vault(hop, &root, item, &folder, &temp));
      let filed = match (filed, &hop.remote) {
        (Ok(sha), Some(r)) => self
          .push_item(r.as_ref(), &root, &folder)
          .await
          .map(|()| sha),
        (res, _) => res,
      };
      match filed {
        Ok(sha) => {
          filed_sha = sha;
          vault_item.clone()
        }
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

    // Same-file grouping (plan §1.3): the file's sha256, before any destination posts.
    if !todo.is_empty() {
      self.observe_item(hop, item, &media, filed_sha).await;
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
      if up.needs_group_id() && self.works.work_of(&Self::item_ref(hop, &iid)).is_none() {
        self.works.own_work(&Self::item_ref(hop, &iid));
      }
      // Already on this account, from an earlier hop or another video of the same group: nothing
      // to send, no pacing slot used (D11). A saved link the destination says is gone posts again.
      let want = self.want(hop, &iid, p);
      if !want.post_again {
        if let Some((hit, e)) = self.posted.posted_any(&want) {
          if self.saved_link_gone(up.as_ref(), &e).await {
            self.set_cell(
              hop,
              &iid,
              p,
              json!({ "state": "pending", "postAgain": true }),
            );
          } else {
            self.mark_already_posted(hop, &iid, p, &hit, e);
            continue;
          }
        }
      }
      // Human pace (F8): the gap since this account's last post, today's cap, posting hours.
      let empty = json!({});
      let pace = Pace::from_plan(d.get("options").unwrap_or(&empty), hop.plan.get("pace"));
      let pkey = format!("{p}:{}", s(d, "connectionId"));
      let t = now_ms();
      let (from, to) = pace.day_of(t);
      let today = self
        .posted
        .finished_between(&format!("{p}|{}|", self.account(hop, p)), from, to);
      let slot = self.ledger.slot(&pkey, &pace, t, today);
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
      // Every alias checked and the slot reserved under one lock, from the works as they are now
      // (a group may have formed during the pace wait).
      let want = self.want(hop, &iid, p);
      let (seen, slot) = self.posted.reserve_any(&want, &now());
      let ik = slot.key.clone();
      match seen {
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
          self.mark_already_posted(hop, &iid, p, &ik, e);
          continue;
        }
        Seen::Interrupted if slot.from_item != want.from_item => {
          // another video of the group was cut off posting here; it resumes in its own hop, and
          // this one waits for the creator rather than risk a second post
          let st = json!({
            "state": "publishedUnverified",
            "issue": { "code": "publishedUnverified", "message": format!("BunnieHop stopped while posting the same video to {p} from your other copy. Check {p}; use Post again only if it isn't there.") },
          });
          self.set_cell(hop, &iid, p, st);
          continue;
        }
        Seen::Interrupted if up.safe_to_retry() => {
          // the platform dedupes on the same key, so posting again finds the first post; every
          // key of the reservation is freed and reserved again together (R1)
          self.posted.retry_slot(&slot, &now());
        }
        Seen::Interrupted => {
          let st = json!({
            "state": "publishedUnverified",
            "issue": { "code": "publishedUnverified", "message": format!("The Helper stopped while posting this to {p}. Check {p}; use Post again only if it isn't there.") },
          });
          self.posted.finish_slot(
            &slot,
            Some(json!({ "state": "publishedUnverified", "at": now() })),
          );
          self.set_cell(hop, &iid, p, st);
          continue;
        }
      }
      // Saved before the upload starts, so a crash mid-post is known after a restart (D11). The
      // cell keeps the key it was reserved under; a used "Post again" flag is dropped here.
      self.set_cell(
        hop,
        &iid,
        p,
        json!({ "state": "pending", "inFlight": true, "idempotencyKey": ik }),
      );
      self.stage(hop, &iid, &[d], "uploading", None);
      // The pace gap runs from the moment the upload starts, after the saves above, so slow
      // disk writes never shorten the time between two posts on one account.
      let started = now_ms();
      self.ledger.record(&pkey, &pace, started, false);
      let post = d.pointer("/options/posts").and_then(|m| m.get(&iid));
      let control = PublishControl::new(hop.cancel.subscribe());
      let mut cancelled = hop.cancel.subscribe();
      let work_id = crate::works::work_id_of_key(&ik)
        .map(str::to_string)
        .or_else(|| self.works.work_of(&Self::item_ref(hop, &iid)).map(|w| w.id));
      let publishing = up.publish_controlled(
        Upload {
          item,
          post,
          media: &media,
          idempotency_key: &ik,
          work_id: work_id.as_deref(),
          options: d.get("options").unwrap_or(&empty),
        },
        control.clone(),
      );
      tokio::pin!(publishing);
      let res = tokio::select! {
        biased;
        _ = async { let _ = cancelled.wait_for(|stopped| *stopped).await; } => {
          if control.started() { publishing.await } else { Err(Failure::new("stopped","Stopped before publishing.")) }
        }
        result = &mut publishing => result,
      };
      // A cancelled publish has an unknown outcome. Keep it in the duplicate ledger even when
      // the uploader couldn't supply an ID; Stop must never turn it into a fresh retry.
      let res = match res {
        Err(f) if control.started() && (f.code == "stopped" || *hop.cancel.borrow()) => {
          Ok(Published {
            dest_item_id: String::new(),
            dest_url: None,
            verified: false,
            note: Some(format!(
              "{} Check {p} before posting again.{}",
              f.message,
              f.verbatim.map(|v| format!("\n{v}")).unwrap_or_default()
            )),
          })
        }
        other => other,
      };
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
          self.posted.finish_slot(&slot, Some(entry));
          self.set_cell(hop, &iid, p, st);
        }
        Err(f) if up.existing_post(&f).is_some() => {
          // the destination already holds this group (D-H6P3): a skip with its link
          let pb = up.existing_post(&f).unwrap_or_else(|| unreachable!());
          let link = pb.dest_url.clone().unwrap_or_default();
          let mut entry = json!({ "state": "published", "destItemId": pb.dest_item_id, "foundThere": true, "at": now() });
          let mut st = json!({ "state": "skipped", "issue": { "code": "duplicate", "message": format!("Already on {p}: {link}") } });
          if let Some(u) = pb.dest_url {
            entry["destUrl"] = json!(u);
            st["destUrl"] = json!(u);
          }
          self.posted.finish_slot(&slot, Some(entry));
          self.set_cell(hop, &iid, p, st);
        }
        Err(f) if f.code == "stopped" => {
          self.posted.discard_upload(&ik);
          self.free_or_release(&slot);
          self.set_cell(hop, &iid, p, json!({"state":"skipped","issue":f.issue()}));
        }
        Err(f) if f.code == "quotaExceeded" => {
          // nothing went out; this post and the account's next ones wait for the reset
          self.free_or_release(&slot);
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
          // a definite refusal (D-069): this attempt posted nothing, so the work key and its twin
          // are freed together (R1), unless an earlier attempt may have (D-144)
          self.free_or_release(&slot);
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
  ) -> Result<Option<String>, Failure> {
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
    entry["hashes"] = sha
      .as_ref()
      .map(|h| json!({ "sha256": h }))
      .unwrap_or(json!({}));
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
    Ok(sha.and_then(|h| h.as_str().map(str::to_string)))
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
case "$last" in *alt*) echo media-alt > "$dir/media.mp4" ;; *) echo media > "$dir/media.mp4" ;; esac; echo t > "$dir/thumbnail.jpg"; echo '{}' > "$dir/info.info.json"
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

  struct StopPhases {
    stage: std::sync::atomic::AtomicUsize,
    upload: tokio::sync::Notify,
    publish: tokio::sync::Notify,
    fail_publish: bool,
  }

  impl Uploader for StopPhases {
    fn publish<'a>(&'a self, _u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
      unreachable!("the Hub must pass publish control")
    }
    fn publish_controlled<'a>(
      &'a self,
      _u: Upload<'a>,
      control: PublishControl,
    ) -> BoxFut<'a, Result<Published, Failure>> {
      Box::pin(async move {
        use std::sync::atomic::Ordering;
        self.stage.store(1, Ordering::SeqCst);
        self.upload.notified().await;
        control.start_publish()?;
        self.stage.store(2, Ordering::SeqCst);
        self.publish.notified().await;
        self.stage.store(3, Ordering::SeqCst);
        if self.fail_publish {
          return Err(Failure::new("stopped", "Publish connection was cancelled."));
        }
        Ok(Published {
          dest_item_id: "post-1".into(),
          dest_url: None,
          verified: true,
          note: None,
        })
      })
    }
  }

  async fn stop_at_phase(during_publish: bool, fail_publish: bool) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let uploader = Arc::new(StopPhases {
      stage: AtomicUsize::new(0),
      upload: tokio::sync::Notify::new(),
      publish: tokio::sync::Notify::new(),
      fail_publish,
    });
    let u = uploader.clone();
    let tools = Arc::new(Tooling::new(Binaries::new(dir.path().join("bin")), false));
    let hub = Hub::new(
      dir.path().join("hops"),
      dir.path().join("tmp"),
      dir.path().join("vault"),
      tools,
      Arc::new(move |_, _| Some(u.clone() as Arc<dyn Uploader>)),
    );
    let mut p = plan(&[], &["facebook"]);
    p["source"]["platform"] = json!("x");
    p["items"] = json!([{"id":"a","platform":"x","kind":"text","description":"words","tags":[],"publishedAt":"2026-01-02T00:00:00Z"}]);
    p.as_object_mut().unwrap().remove("vault");
    let mut another = p.clone();
    hub.start(p).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
      while uploader.stage.load(Ordering::SeqCst) != 1 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .unwrap();
    if during_publish {
      uploader.upload.notify_one();
      tokio::time::timeout(Duration::from_secs(3), async {
        while uploader.stage.load(Ordering::SeqCst) != 2 {
          tokio::task::yield_now().await;
        }
      })
      .await
      .unwrap();
    }
    hub.stop_all();
    if during_publish {
      uploader.publish.notify_one();
    }
    let events = until(&hub, |e| e["type"] == "stopped" && e["hopId"] == "hop-1").await;
    let expected = if !during_publish {
      "skipped"
    } else if fail_publish {
      "publishedUnverified"
    } else {
      "published"
    };
    assert!(
      events
        .iter()
        .any(|e| e["type"] == "destinationState" && e["state"]["state"] == expected),
      "{events:?}"
    );
    assert_eq!(
      uploader.stage.load(Ordering::SeqCst),
      if during_publish { 3 } else { 1 }
    );
    assert!(hub.retry("hop-1", "a", "facebook").is_err());
    if during_publish && fail_publish {
      let posted = crate::posted::Posted::open(dir.path().join("hops/posted.json"));
      assert_eq!(
        posted.posted("facebook|facebook-1|x|a").unwrap()["state"],
        "publishedUnverified"
      );
      another["id"] = json!("hop-2");
      hub.start(another).unwrap();
      until(&hub, |e| {
        e["type"] == "hopFinished" && e["hopId"] == "hop-2"
      })
      .await;
      assert_eq!(
        uploader.stage.load(Ordering::SeqCst),
        3,
        "a second hop never enters the uploader"
      );
    }
  }

  #[tokio::test]
  async fn stop_during_upload_sends_no_publish() {
    stop_at_phase(false, false).await;
  }

  #[tokio::test]
  async fn stop_during_cancelled_publish_is_uncertain_and_never_retried() {
    stop_at_phase(true, true).await;
  }

  #[tokio::test]
  async fn stop_during_publish_lets_its_verified_result_finish() {
    stop_at_phase(true, false).await;
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
  async fn ledger_merge_adds_browser_posts_and_helper_skips_them() {
    let f = fx(false);
    // the browser engine posted item a to this account before the Helper was paired
    let browser: HashMap<String, Value> = serde_json::from_value(json!({
      "bluesky|bluesky-1|youtube|a": { "state": "published", "destUrl": "https://bsky.app/from-browser", "at": "2026-11-09T10:00:00Z" }
    }))
    .unwrap();
    assert_eq!(f.hub.merge_ledger(&browser), 1);
    assert!(f.hub.ledger().contains_key("bluesky|bluesky-1|youtube|a"));
    let urls = [("a", "https://www.youtube.com/watch?v=a")];
    f.hub.start(plan(&urls, &["bluesky"])).unwrap();
    until(&f.hub, finished).await;
    assert!(f.fake.calls.lock().unwrap().is_empty(), "D11: nothing sent");
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(f.dir.path().join("hops/hop-1.json")).unwrap())
        .unwrap();
    let cell = &doc["cells"]["a → bluesky"];
    assert_eq!(cell["state"], "published");
    assert_eq!(cell["destUrl"], "https://bsky.app/from-browser");
    assert!(cell["alreadyPosted"].is_string());
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

  /// The browser's finished posts on the same account, merged into this ledger, count toward the
  /// Helper's cap exactly as the Helper's own posts count in the browser (D-145).
  #[cfg(unix)]
  #[tokio::test]
  async fn hop_pacing_cap_counts_posts_the_browser_made_today() {
    for (cap, browser, expect) in [(1u32, 1usize, 0usize), (2, 1, 1), (3, 1, 2)] {
      let f = fx(false);
      let at = now();
      let mut b = HashMap::new();
      for i in 0..browser {
        b.insert(
          format!("bluesky|bluesky-1|youtube|web{i}"),
          json!({ "state": "published", "at": at }),
        );
      }
      f.hub.posted.merge(&b);
      let p = paced(
        plan(
          &[
            ("a", "https://www.youtube.com/watch?v=a"),
            ("b", "https://www.youtube.com/watch?v=b"),
            ("c", "https://www.youtube.com/watch?v=c"),
          ],
          &["bluesky"],
        ),
        json!({ "minGapSec": 0, "jitterSec": [0, 0], "dailyCap": cap }),
      );
      f.hub.start(p).unwrap();
      let left = ["a", "b", "c"][expect];
      until(&f.hub, |e| {
        e["type"] == "itemStage" && e["itemId"] == left && e["stage"] == "queued"
      })
      .await;
      tokio::time::sleep(Duration::from_millis(200)).await;
      assert_eq!(
        f.fake.calls.lock().unwrap().len(),
        expect,
        "cap {cap} with {browser} browser post today"
      );
      f.hub.cancel("hop-1").unwrap();
      until(&f.hub, finished).await;
    }
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

  // ── same-file grouping (docs/plans/2026-11-11-same-file-grouping.md §2, Revision 3) ──────────

  const G1: &str = "11111111-1111-4111-8111-111111111111";
  const G2: &str = "22222222-2222-4222-8222-222222222222";

  /// A destination for grouping tests: records `(ledger key, item)` per call.
  #[derive(Default)]
  struct Dest {
    calls: Mutex<Vec<(String, String)>>,
    work_ids: Mutex<Vec<Option<String>>>,
    safe: bool,
    group: bool,
    /// Refuses every post as already there (SoapBox's duplicate answer, D-H6P3).
    dup: bool,
    /// The saved-link re-check: `Some(Some(there))` answers, `Some(None)` never answers.
    recheck: Option<Option<bool>>,
    fail_first: Mutex<bool>,
    /// The code of that first failure (`server5xx` when empty).
    fail_code: &'static str,
  }
  impl Dest {
    fn calls(&self) -> Vec<(String, String)> {
      self.calls.lock().unwrap().clone()
    }
    fn items(&self) -> Vec<String> {
      self.calls().into_iter().map(|(_, i)| i).collect()
    }
  }
  impl Uploader for Dest {
    fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
      Box::pin(async move {
        let id = s(u.item, "id").to_string();
        self
          .calls
          .lock()
          .unwrap()
          .push((u.idempotency_key.to_string(), id.clone()));
        self
          .work_ids
          .lock()
          .unwrap()
          .push(u.work_id.map(str::to_string));
        if self.dup {
          return Err(Failure::new("duplicate", "That video is already there."));
        }
        if std::mem::replace(&mut *self.fail_first.lock().unwrap(), false) {
          let code = if self.fail_code.is_empty() {
            "server5xx"
          } else {
            self.fail_code
          };
          return Err(Failure::new(code, "Bluesky refused the post."));
        }
        Ok(Published {
          note: None,
          dest_item_id: format!("post-{id}"),
          dest_url: Some(format!("https://example.test/{id}")),
          verified: true,
        })
      })
    }
    fn safe_to_retry(&self) -> bool {
      self.safe
    }
    fn needs_group_id(&self) -> bool {
      self.group
    }
    fn existing_post(&self, f: &Failure) -> Option<Published> {
      (self.dup && f.code == "duplicate").then(|| Published {
        note: None,
        dest_item_id: "post-there".into(),
        dest_url: Some("https://example.test/there".into()),
        verified: true,
      })
    }
    fn recheck<'a>(&'a self, _id: &'a str) -> Option<BoxFut<'a, Result<bool, Failure>>> {
      let answer = self.recheck?;
      Some(Box::pin(async move {
        match answer {
          Some(there) => Ok(there),
          None => std::future::pending().await,
        }
      }))
    }
  }

  #[cfg(unix)]
  fn hub_with(dir: &Path, dests: &[(&str, Arc<Dest>)]) -> Arc<Hub> {
    fake_ytdlp(&dir.join("bin"));
    let tools = Arc::new(Tooling::new(Binaries::new(dir.join("bin")), false));
    let map: HashMap<String, Arc<Dest>> = dests
      .iter()
      .map(|(p, d)| (p.to_string(), d.clone()))
      .collect();
    let ups: Uploaders =
      Arc::new(move |p: &str, _c: &str| map.get(p).map(|d| d.clone() as Arc<dyn Uploader>));
    Hub::new(
      dir.join("hops"),
      dir.join("tmp"),
      dir.join("vault"),
      tools,
      ups,
    )
  }

  /// A hop from `src` with the given items; a duration makes an item's file groupable.
  fn group_plan(id: &str, src: &str, items: &[(&str, Option<f64>)], dests: &[&str]) -> Value {
    let urls: Vec<(String, String)> = items
      .iter()
      .map(|(i, _)| {
        (
          i.to_string(),
          format!("https://www.youtube.com/watch?v={i}"),
        )
      })
      .collect();
    let refs: Vec<(&str, &str)> = urls.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let mut p = plan(&refs, dests);
    p["id"] = json!(id);
    p["source"]["platform"] = json!(src);
    for (n, (_, d)) in items.iter().enumerate() {
      p["items"][n]["platform"] = json!(src);
      if let Some(d) = d {
        p["items"][n]["durationSec"] = json!(d);
      }
    }
    p
  }

  fn wref(src: &str, id: &str) -> crate::works::Ref {
    crate::works::Ref::new(src, id)
  }

  /// `hops/works.json` with fixed work ids: each group's first member paired with the rest.
  fn works_file(dir: &Path, groups: &[(&str, &[(&str, &str)])]) {
    let mut d = crate::works::WorksDoc::empty(
      "00000000-0000-4000-8000-000000000001",
      "2026-11-01T00:00:00Z",
    );
    for (n, (wid, members)) in groups.iter().enumerate() {
      let at = format!("2026-11-0{}T00:00:00Z", n + 1);
      for m in &members[1..] {
        d = crate::works::same_video(
          &d,
          &wref(members[0].0, members[0].1),
          &wref(m.0, m.1),
          &at,
          wid,
        );
      }
    }
    std::fs::create_dir_all(dir.join("hops")).unwrap();
    std::fs::write(dir.join("hops/works.json"), d.serialize()).unwrap();
  }

  fn ledger_file(dir: &Path, entries: Value) {
    std::fs::create_dir_all(dir.join("hops")).unwrap();
    std::fs::write(dir.join("hops/posted.json"), entries.to_string()).unwrap();
  }

  fn cells_of(dir: &Path, hop: &str) -> Value {
    let doc: Value =
      serde_json::from_str(&std::fs::read_to_string(dir.join(format!("hops/{hop}.json"))).unwrap())
        .unwrap();
    doc["cells"].clone()
  }

  fn hop_done(id: &'static str) -> impl Fn(&Value) -> bool {
    move |e| e["type"] == "hopFinished" && e["hopId"] == id
  }

  async fn calls_reach(d: &Dest, n: usize) {
    for _ in 0..200 {
      if d.calls().len() >= n {
        return;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("calls: {:?}", d.calls());
  }

  fn work_key(dest: &str, wid: &str) -> String {
    format!("{dest}|{dest}-1|work|{wid}")
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn helper_0_2_0_ledger_never_reposts_after_grouping() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/ledger-0.2.0");
    let expected: Value =
      serde_json::from_str(&std::fs::read_to_string(fixture.join("expected.json")).unwrap())
        .unwrap();
    assert_eq!(
      expected["helperVersion"], "0.2.0",
      "written by Helper 0.2.0"
    );
    let dir = tempfile::tempdir().unwrap();
    let hops = dir.path().join("hops");
    std::fs::create_dir_all(hops.join("upload-handles")).unwrap();
    std::fs::copy(fixture.join("hops/posted.json"), hops.join("posted.json")).unwrap();
    for e in std::fs::read_dir(fixture.join("hops/upload-handles")).unwrap() {
      let e = e.unwrap();
      std::fs::copy(e.path(), hops.join("upload-handles").join(e.file_name())).unwrap();
    }
    let marker = hops
      .join("upload-handles")
      .join(expected["aFacebookMarkerFile"].as_str().unwrap());
    let marker_before = std::fs::read(&marker).unwrap();
    works_file(
      dir.path(),
      &[
        (G1, &[("youtube", "a"), ("youtube", "b")]),
        (G2, &[("youtube", "c"), ("youtube", "d")]),
      ],
    );
    let bsky = Arc::new(Dest {
      safe: true,
      ..Default::default()
    });
    let fb = Arc::new(Dest::default());
    let hub = hub_with(
      dir.path(),
      &[("bluesky", bsky.clone()), ("facebook", fb.clone())],
    );
    let c_date = expected["cOriginalDate"].as_str().unwrap();
    let mut p = group_plan(
      "hop-g",
      "youtube",
      &[("a", None), ("b", None), ("c", None), ("d", None)],
      &["bluesky", "facebook"],
    );
    p["items"][2]["publishedAt"] = json!(c_date);
    hub.start(p).unwrap();
    until(&hub, finished).await;

    // Bluesky: only c's cut-off post, under its 0.2.0 key, so its record key is the one 0.2.0 made
    let c_key = expected["keys"]["cBluesky"].as_str().unwrap();
    assert_eq!(bsky.calls(), [(c_key.to_string(), "c".to_string())]);
    assert_eq!(
      crate::uploaders::bluesky::tid_for(Some(c_date), c_key, 0),
      expected["cBlueskyRecordKey"].as_str().unwrap()
    );
    let cells = cells_of(dir.path(), "hop-g");
    for i in ["a", "b", "d"] {
      assert!(
        cells[format!("{i} → bluesky")]["alreadyPosted"].is_string(),
        "{i} skipped on Bluesky: {cells}"
      );
    }
    assert_eq!(cells["b → bluesky"]["sameAs"]["id"], "a");
    // Facebook: a's cut-off upload waits for the creator, its marker untouched; b never posts
    assert_eq!(cells["a → facebook"]["state"], "publishedUnverified");
    assert_eq!(cells["b → facebook"]["state"], "publishedUnverified");
    assert_eq!(std::fs::read(&marker).unwrap(), marker_before);
    assert_eq!(
      fb.items(),
      ["c"],
      "only c reaches Facebook, once for c and d"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn works_split_ignores_the_leaving_members_posts_after_a_ledger_merge() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("b", None)], &["bluesky"]))
      .unwrap();
    until(&hub, hop_done("hop-1")).await;
    let before = hub.ledger();
    assert_eq!(before[&work_key("bluesky", G1)]["fromItem"], "youtube|b");
    hub.split_member(&wref("youtube", "b")).unwrap();
    // another engine's copy from before the split comes back
    hub.merge_ledger(&before);
    hub
      .start(group_plan(
        "hop-2",
        "youtube",
        &[("a", None), ("b", None)],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, hop_done("hop-2")).await;
    assert_eq!(d.items(), ["b", "a"], "a posts once b has left its group");
    let cells = cells_of(dir.path(), "hop-2");
    assert!(cells["b → bluesky"]["alreadyPosted"].is_string());
    assert!(cells["a → bluesky"]["alreadyPosted"].is_null());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn works_split_the_member_left_never_sends_the_leavers_key() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    until(&hub, hop_done("hop-1")).await;
    hub.split_member(&wref("youtube", "a")).unwrap();
    hub
      .start(group_plan("hop-2", "youtube", &[("b", None)], &["bluesky"]))
      .unwrap();
    until(&hub, hop_done("hop-2")).await;
    let calls = d.calls();
    assert_eq!(d.items(), ["a", "b"], "b posts once, after a left");
    // Bluesky's record key and Mastodon's Idempotency-Key come from this key: never a's
    assert_eq!(calls[0].0, work_key("bluesky", G1));
    assert_eq!(calls[1].0, "bluesky|bluesky-1|youtube|b");
    let l = hub.ledger();
    assert_eq!(l[&work_key("bluesky", G1)]["fromItem"], "youtube|a");
    assert_eq!(l["bluesky|bluesky-1|youtube|b"]["state"], "published");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn works_merge_keeps_both_groups_posts() {
    let dir = tempfile::tempdir().unwrap();
    works_file(
      dir.path(),
      &[
        (G1, &[("youtube", "a"), ("youtube", "b")]),
        (G2, &[("youtube", "c"), ("youtube", "d")]),
      ],
    );
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", None), ("c", None)],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, hop_done("hop-1")).await;
    // the creator says the two groups are one video
    hub
      .works()
      .same(&wref("youtube", "a"), &wref("youtube", "c"));
    assert_eq!(hub.works().doc().works.len(), 1);
    hub
      .start(group_plan(
        "hop-2",
        "youtube",
        &[("b", None), ("d", None)],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, hop_done("hop-2")).await;
    assert_eq!(d.items(), ["a", "c"], "nothing posts after the merge");
    let cells = cells_of(dir.path(), "hop-2");
    assert!(cells["b → bluesky"]["alreadyPosted"].is_string());
    assert!(cells["d → bluesky"]["alreadyPosted"].is_string());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn works_change_mid_hop_resumes_the_saved_key() {
    let dir = tempfile::tempdir().unwrap();
    let own = "bluesky|bluesky-1|youtube|a";
    // cut off mid-post before a group formed
    ledger_file(
      dir.path(),
      json!({ own: { "state": "reserved", "at": "2026-11-10T10:00:00Z" } }),
    );
    let p = group_plan(
      "hop-m",
      "youtube",
      &[("a", None), ("b", None)],
      &["bluesky"],
    );
    let doc = json!({
      "plan": p,
      "status": "running",
      "cells": { "a → bluesky": { "state": "pending", "inFlight": true, "idempotencyKey": own } },
    });
    std::fs::write(dir.path().join("hops/hop-m.json"), doc.to_string()).unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest {
      safe: true,
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    assert_eq!(hub.restore(), ["hop-m"]);
    until(&hub, finished).await;
    assert_eq!(d.calls(), [(own.to_string(), "a".to_string())]);
    let cells = cells_of(dir.path(), "hop-m");
    assert_eq!(cells["a → bluesky"]["idempotencyKey"], own);
    assert!(cells["b → bluesky"]["alreadyPosted"].is_string());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn grouping_during_a_pace_wait_never_posts_twice() {
    let dir = tempfile::tempdir().unwrap();
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    let p = paced(
      group_plan(
        "hop-1",
        "youtube",
        &[("a", None), ("b", None)],
        &["bluesky"],
      ),
      json!({ "minGapSec": 2, "jitterSec": [0, 0] }),
    );
    hub.start(p).unwrap();
    calls_reach(&d, 1).await;
    // b is waiting out the gap; the creator groups the two now
    hub
      .works()
      .same(&wref("youtube", "a"), &wref("youtube", "b"));
    until(&hub, finished).await;
    assert_eq!(d.items(), ["a"]);
    let cells = cells_of(dir.path(), "hop-1");
    assert!(cells["b → bluesky"]["alreadyPosted"].is_string());
    assert_eq!(cells["b → bluesky"]["sameAs"]["id"], "a");
    assert_eq!(cells["b → bluesky"]["sameAs"]["via"], "creator");
  }

  /// A reservation under G1 from member `a` and its twin, cut off by a crash.
  fn crashed_under_g1(dir: &Path) {
    let g = work_key("bluesky", G1);
    ledger_file(
      dir,
      json!({
        g.clone(): { "state": "reserved", "at": "2026-11-10T10:00:00Z", "fromItem": "youtube|a" },
        "bluesky|bluesky-1|youtube|a": { "state": "reserved", "at": "2026-11-10T10:00:00Z", "fromItem": "youtube|a", "under": g },
      }),
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn split_after_a_crash_still_finds_the_leaving_members_reservation() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    crashed_under_g1(dir.path());
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub.split_member(&wref("youtube", "a")).unwrap();
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", None), ("b", None)],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, finished).await;
    let cells = cells_of(dir.path(), "hop-1");
    assert_eq!(cells["a → bluesky"]["state"], "publishedUnverified");
    assert_eq!(d.items(), ["b"], "a is never sent; b, now apart, posts");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn a_split_member_resumes_under_its_twin_and_keeps_the_work_key_as_its_record() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    crashed_under_g1(dir.path());
    let d = Arc::new(Dest {
      safe: true,
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub.split_member(&wref("youtube", "a")).unwrap();
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    until(&hub, finished).await;
    let g = work_key("bluesky", G1);
    // the retry sends the key of the first attempt, so the platform finds that post
    assert_eq!(d.calls(), [(g.clone(), "a".to_string())]);
    let ledger = hub.ledger();
    // the key went to the platform, so it stays a's record: inert for b, never sent again (D-143)
    assert_eq!(ledger[&g]["state"], "published");
    assert_eq!(ledger[&g]["fromItem"], "youtube|a");
    let twin = &ledger["bluesky|bluesky-1|youtube|a"];
    assert_eq!(twin["state"], "published");
    assert_eq!(twin["fromItem"], "youtube|a");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn a_cut_off_member_split_and_retried_never_lends_its_key_to_the_member_left() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    crashed_under_g1(dir.path());
    let d = Arc::new(Dest {
      safe: true,
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub.split_member(&wref("youtube", "a")).unwrap();
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    until(&hub, hop_done("hop-1")).await;
    hub
      .start(group_plan("hop-2", "youtube", &[("b", None)], &["bluesky"]))
      .unwrap();
    until(&hub, hop_done("hop-2")).await;
    let g = work_key("bluesky", G1);
    // a platform that dedupes on the key would hand b a's post if b sent g
    assert_eq!(
      d.calls(),
      [
        (g, "a".to_string()),
        ("bluesky|bluesky-1|youtube|b".to_string(), "b".to_string())
      ]
    );
    assert_eq!(
      cells_of(dir.path(), "hop-2")["b → bluesky"]["state"],
      "published"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn a_failed_retry_of_a_cut_off_post_keeps_its_keys() {
    for code in ["tokenExpired", "server5xx"] {
      let dir = tempfile::tempdir().unwrap();
      works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
      crashed_under_g1(dir.path());
      let d = Arc::new(Dest {
        safe: true,
        fail_first: Mutex::new(true),
        fail_code: code,
        ..Default::default()
      });
      let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
      hub.split_member(&wref("youtube", "a")).unwrap();
      hub
        .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
        .unwrap();
      until(&hub, hop_done("hop-1")).await;
      let g = work_key("bluesky", G1);
      let own_a = "bluesky|bluesky-1|youtube|a";
      // the first attempt may be on the platform: the failed retry frees nothing
      let l = hub.ledger();
      assert_eq!(l[&g]["fromItem"], "youtube|a", "{code}");
      assert_eq!(l[own_a]["under"], g.as_str(), "{code}");
      hub
        .start(group_plan("hop-2", "youtube", &[("b", None)], &["bluesky"]))
        .unwrap();
      until(&hub, hop_done("hop-2")).await;
      hub
        .start(group_plan("hop-3", "youtube", &[("a", None)], &["bluesky"]))
        .unwrap();
      until(&hub, hop_done("hop-3")).await;
      // b never sends a's key; a never posts under a second key, it retries the first
      assert_eq!(
        d.calls(),
        [
          (g.clone(), "a".to_string()),
          ("bluesky|bluesky-1|youtube|b".to_string(), "b".to_string()),
          (g.clone(), "a".to_string()),
        ],
        "{code}"
      );
      let l = hub.ledger();
      assert_eq!(l[&g]["state"], "published", "{code}");
      assert_eq!(l[own_a]["state"], "published", "{code}");
    }
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn a_refused_post_frees_the_work_key_and_its_twin() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest {
      fail_first: Mutex::new(true),
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    until(&hub, finished).await;
    let g = work_key("bluesky", G1);
    let own = "bluesky|bluesky-1|youtube|a";
    assert_eq!(d.calls(), [(g.clone(), "a".to_string())]);
    let ledger = hub.ledger();
    assert!(
      !ledger.contains_key(&g) && !ledger.contains_key(own),
      "{ledger:?}"
    );
    hub.retry("hop-1", "a", "bluesky").unwrap();
    calls_reach(&d, 2).await;
    until(&hub, |_| {
      hub
        .ledger()
        .get(own)
        .is_some_and(|e| e["state"] == "published")
    })
    .await;
    let ledger = hub.ledger();
    assert_eq!(ledger[&g]["state"], "published");
    assert_eq!(ledger[own]["under"], g.as_str());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn post_again_on_one_member_never_deletes_another_members_record() {
    let dir = tempfile::tempdir().unwrap();
    let b_key = "bluesky|bluesky-1|youtube|b";
    let b_entry = json!({ "state": "published", "destItemId": "post-b", "destUrl": "https://example.test/b", "at": "2026-11-01T10:00:00Z" });
    ledger_file(dir.path(), json!({ b_key: b_entry }));
    let handles = crate::posted::UploadHandles::new(dir.path().join("hops/upload-handles"));
    assert!(handles.begin(b_key, "video").unwrap());
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    until(&hub, finished).await;
    assert!(d.calls().is_empty(), "b's post covers a");
    hub.post_again("hop-1", "a", "bluesky").unwrap();
    calls_reach(&d, 1).await;
    until(&hub, |_| {
      hub
        .ledger()
        .get("bluesky|bluesky-1|youtube|a")
        .is_some_and(|e| e["state"] == "published")
    })
    .await;
    assert_eq!(d.calls(), [(work_key("bluesky", G1), "a".to_string())]);
    assert_eq!(hub.ledger()[b_key], b_entry, "b's record is untouched");
    assert!(
      handles.load(b_key).unwrap().is_some(),
      "b's upload marker is untouched"
    );
    // the flag was used once
    for _ in 0..200 {
      if cells_of(dir.path(), "hop-1")["a → bluesky"]["state"] == "published" {
        break;
      }
      tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(cells_of(dir.path(), "hop-1")["a → bluesky"]["postAgain"].is_null());
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn identical_file_from_two_sources_posts_once_per_destination() {
    let dir = tempfile::tempdir().unwrap();
    let bsky = Arc::new(Dest::default());
    let masto = Arc::new(Dest::default());
    let hub = hub_with(
      dir.path(),
      &[("bluesky", bsky.clone()), ("mastodon", masto.clone())],
    );
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", Some(30.0))],
        &["bluesky", "mastodon"],
      ))
      .unwrap();
    until(&hub, hop_done("hop-1")).await;
    // the same file, saved again from TikTok
    hub
      .start(group_plan(
        "hop-2",
        "tiktok",
        &[("b", Some(30.0))],
        &["bluesky", "mastodon"],
      ))
      .unwrap();
    until(&hub, hop_done("hop-2")).await;
    assert_eq!(bsky.items(), ["a"]);
    assert_eq!(masto.items(), ["a"]);
    let works = hub.works().doc().works;
    assert_eq!(works.len(), 1);
    assert_eq!(works[0].members.len(), 2);
    let cells = cells_of(dir.path(), "hop-2");
    for dest in ["bluesky", "mastodon"] {
      let c = &cells[format!("b → {dest}")];
      assert!(c["alreadyPosted"].is_string(), "{c}");
      assert_eq!(c["sameAs"]["platform"], "youtube");
      assert_eq!(c["sameAs"]["id"], "a");
      assert_eq!(c["sameAs"]["via"], "sha256");
      assert_eq!(c["destUrl"], "https://example.test/a");
    }
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn upload_carries_the_work_id_beside_the_ledger_key() {
    let dir = tempfile::tempdir().unwrap();
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("youtube", "b")])]);
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", None), ("c", None)],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, finished).await;
    assert_eq!(
      d.calls(),
      [
        (work_key("bluesky", G1), "a".to_string()),
        ("bluesky|bluesky-1|youtube|c".to_string(), "c".to_string())
      ]
    );
    assert_eq!(
      *d.work_ids.lock().unwrap(),
      [Some(G1.to_string()), None],
      "a grouped item names its work; an item in none names nothing"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn grouping_never_changes_the_mastodon_idempotency_key() {
    let dir = tempfile::tempdir().unwrap();
    let own = "mastodon|mastodon-1|youtube|a";
    // a Helper 0.2.0 reservation, cut off before grouping existed
    ledger_file(
      dir.path(),
      json!({ own: { "state": "reserved", "at": "2026-10-01T10:00:00Z" } }),
    );
    works_file(dir.path(), &[(G1, &[("youtube", "a"), ("tiktok", "b")])]);
    let masto = Arc::new(Dest {
      safe: true,
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("mastodon", masto.clone())]);
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", None)],
        &["mastodon"],
      ))
      .unwrap();
    until(&hub, finished).await;
    assert_eq!(masto.calls(), [(own.to_string(), "a".to_string())]);
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn duplicate_refusal_is_a_skip_with_the_link_under_the_work_key() {
    let dir = tempfile::tempdir().unwrap();
    let sb = Arc::new(Dest {
      dup: true,
      group: true,
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("soapbox", sb.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["soapbox"]))
      .unwrap();
    until(&hub, finished).await;
    // a destination that posts per group gives the item a one-member work first
    let wid = hub
      .works()
      .work_of(&wref("youtube", "a"))
      .expect("a one-member work")
      .id;
    let g = work_key("soapbox", &wid);
    assert_eq!(sb.calls(), [(g.clone(), "a".to_string())]);
    let cell = &cells_of(dir.path(), "hop-1")["a → soapbox"];
    assert_eq!(cell["state"], "skipped");
    assert_eq!(cell["issue"]["code"], "duplicate");
    assert_eq!(
      cell["issue"]["message"],
      "Already on soapbox: https://example.test/there"
    );
    assert_eq!(cell["destUrl"], "https://example.test/there");
    let e = &hub.ledger()[&g];
    assert_eq!(e["state"], "published");
    assert_eq!(e["foundThere"], true);
    assert_eq!(e["destItemId"], "post-there");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn unreadable_works_copy_reports_works_unreadable_once() {
    // the app shows the line only for the code `worksUnreadable` (packages/protocol errors.ts)
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("hops")).unwrap();
    std::fs::write(dir.path().join("hops/works.json"), "{ not json").unwrap();
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["bluesky"]))
      .unwrap();
    let evs = until(&hub, finished).await;
    let issues: Vec<&Value> = evs.iter().filter(|e| e["type"] == "issue").collect();
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0]["issue"]["code"], "worksUnreadable");
    assert_eq!(issues[0]["issue"]["message"], crate::works::UNREADABLE_LINE);
  }

  fn saved_post(dir: &Path) {
    ledger_file(
      dir,
      json!({ "soapbox|soapbox-1|youtube|a": { "state": "published", "destItemId": "post-old", "destUrl": "https://example.test/old", "at": "2026-11-01T10:00:00Z" } }),
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn saved_link_gone_404_clears_the_skip() {
    let dir = tempfile::tempdir().unwrap();
    saved_post(dir.path());
    let sb = Arc::new(Dest {
      recheck: Some(Some(false)),
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("soapbox", sb.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["soapbox"]))
      .unwrap();
    until(&hub, finished).await;
    assert_eq!(sb.items(), ["a"], "the post was gone, so it posts again");
    let cell = &cells_of(dir.path(), "hop-1")["a → soapbox"];
    assert_eq!(cell["state"], "published");
    assert!(cell["alreadyPosted"].is_null());
    assert!(cell["postAgain"].is_null());
    assert_eq!(cell["destUrl"], "https://example.test/a");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn saved_link_recheck_timeout_keeps_the_skip() {
    let dir = tempfile::tempdir().unwrap();
    saved_post(dir.path());
    let sb = Arc::new(Dest {
      recheck: Some(None),
      ..Default::default()
    });
    let hub = hub_with(dir.path(), &[("soapbox", sb.clone())]);
    hub
      .start(group_plan("hop-1", "youtube", &[("a", None)], &["soapbox"]))
      .unwrap();
    until(&hub, finished).await;
    assert!(sb.calls().is_empty());
    let cell = &cells_of(dir.path(), "hop-1")["a → soapbox"];
    assert!(cell["alreadyPosted"].is_string());
    assert_eq!(cell["destUrl"], "https://example.test/old");
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn lookalike_never_changes_what_posts() {
    let dir = tempfile::tempdir().unwrap();
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    let mut p = group_plan(
      "hop-1",
      "youtube",
      &[("a", Some(30.0)), ("b-alt", Some(30.5))],
      &["bluesky"],
    );
    for n in 0..2 {
      p["items"][n]["title"] = json!("Sunset over the harbor tonight");
      p["items"][n]["description"] = json!("Filmed from the pier with the new lens");
    }
    let listed = p["items"][1].clone();
    hub.start(p).unwrap();
    until(&hub, finished).await;
    assert_eq!(d.items(), ["a", "b-alt"], "different files both post");
    let doc = hub.works().doc();
    assert!(doc.works.is_empty(), "a look-alike never groups by itself");
    assert_eq!(
      crate::works::find_lookalikes(&doc, &[listed], |r| hub.posted_to(r)).len(),
      1,
      "the pair is still offered as a look-alike"
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn sha256_backfill_never_blocks_a_hop() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("probe");
    std::fs::write(&probe, "media\n").unwrap();
    let (sha, size) = vault::sha256_file(&probe).unwrap();
    let items: Vec<Value> = (0..60)
      .map(|n| json!({ "id": format!("old{n}"), "platform": "youtube", "kind": "video", "title": format!("Old {n}"), "durationSec": 30, "files": [{ "role": "media", "path": "media.mp4", "sizeBytes": size, "sha256": if n == 0 { sha.clone() } else { format!("{n:064x}") } }], "backedUpAt": "2026-01-01T00:00:00Z" }))
      .collect();
    let side = dir.path().join("vault/youtube/old");
    std::fs::create_dir_all(&side).unwrap();
    std::fs::write(
      side.join("bunniehop.json"),
      json!({ "format": "bunniehop.sidecar", "version": 1, "source": { "platform": "youtube", "handle": "old" }, "items": items }).to_string(),
    )
    .unwrap();
    let d = Arc::new(Dest::default());
    let hub = hub_with(dir.path(), &[("bluesky", d.clone())]);
    let h2 = hub.clone();
    let back = tokio::task::spawn_blocking(move || h2.backfill_seen());
    hub
      .start(group_plan(
        "hop-1",
        "youtube",
        &[("a", Some(30.0))],
        &["bluesky"],
      ))
      .unwrap();
    until(&hub, finished).await;
    assert_eq!(back.await.unwrap(), 60);
    assert_eq!(d.items(), ["a"], "the hop posts; old0 was never posted");
    let w = hub.works().work_of(&wref("youtube", "a")).expect("grouped");
    assert!(w.members.iter().any(|m| m.id == "old0"));
    assert!(hub.works().seen(&wref("youtube", "old59")).is_some());
  }
}

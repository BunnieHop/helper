//! Same-video groups ("works", O-023 as narrowed by O-024, D-122 as amended by D-123). The Rust
//! side of `packages/sidecar/src/works.ts`: the same document, the same ordered union, the same
//! ledger aliases and look-alike rule, pinned by the shared fixtures in
//! `packages/sidecar/fixtures/cross/works*.json` and `lookalike.json`.
//!
//! The Helper's working copy is `hops/works.json`; shared copies are `<vault>/.works/<device>.json`
//! (a local vault) and `.works/<device>.json` under a cloud vault's root, one file per device. Each
//! engine writes only its own file and reads every file in the folder as a union. Everything stays
//! on the creator's computer or in their own cloud folder (D8).
//!
//! Only byte-identical files (equal sha256) group without the creator (O-024); a look-alike only
//! raises a note and groups when the creator taps "Same video".

use crate::cloud::Remote;
use crate::hops::{Failure, With};
use crate::posted::Want;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const WORKS_FORMAT: &str = "bunniehop.works";
pub const WORKS_VERSION: u32 = 1;
pub const SEEN_TEXT_MAX: usize = 300;
/// Shown once on a hop while the working copy can't be read (plan §1.2).
pub const UNREADABLE_LINE: &str = "BunnieHop couldn't read its list of same videos, so a video saved twice may post twice until this is fixed.";
pub const WORK_BUSY_MESSAGE: &str = "This video is posting right now. Try again when it finishes.";
/// The shared copies' folder, relative to a vault root.
pub const SHARED_DIR: &str = ".works";

// ── the document ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ref {
  pub platform: String,
  pub id: String,
}

impl Ref {
  pub fn new(platform: impl Into<String>, id: impl Into<String>) -> Self {
    Self {
      platform: platform.into(),
      id: id.into(),
    }
  }
  /// `<platform>|<item id>`: the `seen` key and the ledger's `fromItem`.
  pub fn key(&self) -> String {
    format!("{}|{}", self.platform, self.id)
  }
  pub fn parse(key: &str) -> Option<Self> {
    let (p, id) = key.split_once('|')?;
    (!p.is_empty() && !id.is_empty()).then(|| Self::new(p, id))
  }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
  pub platform: String,
  pub id: String,
  pub via: String,
  pub added_at: String,
}

impl Member {
  fn key(&self) -> String {
    format!("{}|{}", self.platform, self.id)
  }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Work {
  pub id: String,
  pub created_at: String,
  #[serde(default)]
  pub absorbed: Vec<String>,
  pub members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pair {
  pub a: Ref,
  pub b: Ref,
  pub at: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeenRec {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sha256: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub size_bytes: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub duration_sec: Option<serde_json::Number>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub title: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub text: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub url: Option<String>,
  pub seen_at: String,
}

impl SeenRec {
  pub fn duration(&self) -> Option<f64> {
    self
      .duration_sec
      .as_ref()
      .and_then(serde_json::Number::as_f64)
  }
}

/// A number written as JavaScript writes it: whole numbers without a fraction.
pub fn js_number(x: f64) -> Option<serde_json::Number> {
  if x.is_finite() && x.fract() == 0.0 && x.abs() < 9_007_199_254_740_992.0 {
    Some(serde_json::Number::from(x as i64))
  } else {
    serde_json::Number::from_f64(x)
  }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorksDoc {
  pub format: String,
  pub version: u32,
  pub device: String,
  pub updated_at: String,
  pub works: Vec<Work>,
  pub different: Vec<Pair>,
  #[serde(serialize_with = "seen_in_js_order")]
  pub seen: BTreeMap<String, SeenRec>,
}

/// JavaScript's `<` on strings: UTF-16 code units. The TypeScript side sorts with it.
pub fn cmp_js(a: &str, b: &str) -> Ordering {
  a.encode_utf16().cmp(b.encode_utf16())
}

fn seen_in_js_order<S: Serializer>(m: &BTreeMap<String, SeenRec>, s: S) -> Result<S::Ok, S::Error> {
  use serde::ser::SerializeMap;
  let mut keys: Vec<&String> = m.keys().collect();
  keys.sort_by(|a, b| cmp_js(a, b));
  let mut map = s.serialize_map(Some(keys.len()))?;
  for k in keys {
    map.serialize_entry(k, &m[k])?;
  }
  map.end()
}

/// Milliseconds since 1970, as `Date.parse` reads an ISO date-time.
fn t(iso: &str) -> i128 {
  time::OffsetDateTime::parse(iso, &time::format_description::well_known::Rfc3339)
    .map(|d| d.unix_timestamp_nanos().div_euclid(1_000_000))
    .unwrap_or(0)
}

fn iso_ok(s: &str) -> bool {
  time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}

fn uuid_ok(s: &str) -> bool {
  let b = s.as_bytes();
  b.len() == 36
    && s.chars().enumerate().all(|(i, c)| match i {
      8 | 13 | 18 | 23 => c == '-',
      14 => c == '4',
      19 => matches!(c, '8' | '9' | 'a' | 'b'),
      _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
    })
}

fn platform_ok(s: &str) -> bool {
  !s.is_empty()
    && s.split('-').all(|seg| {
      !seg.is_empty()
        && seg
          .chars()
          .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

fn ref_ok(r: &Ref) -> bool {
  platform_ok(&r.platform) && !r.id.is_empty()
}

impl WorksDoc {
  pub fn empty(device: &str, at: &str) -> Self {
    Self {
      format: WORKS_FORMAT.into(),
      version: WORKS_VERSION,
      device: device.into(),
      updated_at: at.into(),
      works: vec![],
      different: vec![],
      seen: BTreeMap::new(),
    }
  }

  /// Reads a `bunniehop.works` file, checking what the TypeScript schema checks.
  pub fn parse(text: &str) -> Result<Self, String> {
    let mut doc: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let bad = |what: &str| Err(format!("not a works file: {what}"));
    if doc.format != WORKS_FORMAT || doc.version != WORKS_VERSION {
      return bad("format");
    }
    if doc.device.is_empty() || !iso_ok(&doc.updated_at) {
      return bad("device");
    }
    for w in &doc.works {
      let members_ok = w.members.iter().all(|m| {
        ref_ok(&Ref::new(&m.platform, &m.id))
          && matches!(m.via.as_str(), "sha256" | "creator")
          && iso_ok(&m.added_at)
      });
      if !uuid_ok(&w.id)
        || !iso_ok(&w.created_at)
        || !w.absorbed.iter().all(|a| uuid_ok(a))
        || !members_ok
      {
        return bad("works");
      }
    }
    if !doc
      .different
      .iter()
      .all(|p| ref_ok(&p.a) && ref_ok(&p.b) && iso_ok(&p.at))
    {
      return bad("different");
    }
    for s in doc.seen.values_mut() {
      let sha_ok = s.sha256.as_ref().is_none_or(|h| {
        h.len() == 64
          && h
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
      });
      let dur_ok = s.duration().is_none_or(|d| d >= 0.0);
      if !sha_ok || !dur_ok || !iso_ok(&s.seen_at) {
        return bad("seen");
      }
      s.duration_sec = s.duration().and_then(js_number);
    }
    Ok(doc)
  }

  /// 2-space JSON with a trailing newline, in canonical form (as `serializeWorks`).
  pub fn serialize(&self) -> String {
    let mut s = serde_json::to_string_pretty(&canonical(self)).unwrap_or_default();
    s.push('\n');
    s
  }
}

fn pair_key(a: &Ref, b: &Ref) -> String {
  let (x, y) = (a.key(), b.key());
  if cmp_js(&x, &y) == Ordering::Greater {
    format!("{y}\n{x}")
  } else {
    format!("{x}\n{y}")
  }
}

fn orient(p: &Pair) -> String {
  format!("{}\n{}", p.a.key(), p.b.key())
}

/// Sorted, field order fixed: the form every copy is written in (`canonicalWorks`).
pub fn canonical(doc: &WorksDoc) -> WorksDoc {
  let mut works: Vec<Work> = doc
    .works
    .iter()
    .map(|w| {
      let mut absorbed: Vec<String> = w
        .absorbed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
      absorbed.sort_by(|a, b| cmp_js(a, b));
      let mut members = w.members.clone();
      members.sort_by(|a, b| cmp_js(&a.key(), &b.key()));
      Work {
        id: w.id.clone(),
        created_at: w.created_at.clone(),
        absorbed,
        members,
      }
    })
    .collect();
  works.sort_by(|a, b| cmp_js(&a.id, &b.id));
  let mut different = doc.different.clone();
  different.sort_by(|x, y| {
    cmp_js(&pair_key(&x.a, &x.b), &pair_key(&y.a, &y.b))
      .then_with(|| cmp_js(&orient(x), &orient(y)))
  });
  WorksDoc {
    format: WORKS_FORMAT.into(),
    version: WORKS_VERSION,
    device: doc.device.clone(),
    updated_at: doc.updated_at.clone(),
    works,
    different,
    seen: doc.seen.clone(),
  }
}

// ── union ───────────────────────────────────────────────────────────────────────────────────────

/// Per member, the latest record wins; a tie prefers `creator`.
fn later_member(x: &Member, y: &Member) -> Member {
  match t(&x.added_at).cmp(&t(&y.added_at)) {
    Ordering::Greater => x.clone(),
    Ordering::Less => y.clone(),
    Ordering::Equal if x.via == "creator" => x.clone(),
    Ordering::Equal => y.clone(),
  }
}

fn merge_seen(x: &SeenRec, y: &SeenRec) -> SeenRec {
  let json = |s: &SeenRec| serde_json::to_string(s).unwrap_or_default();
  let xy = t(&x.seen_at)
    .cmp(&t(&y.seen_at))
    .then_with(|| cmp_js(&json(x), &json(y)));
  let (newer, older) = if xy != Ordering::Less { (x, y) } else { (y, x) };
  SeenRec {
    sha256: newer.sha256.clone().or_else(|| older.sha256.clone()),
    size_bytes: newer.size_bytes.or(older.size_bytes),
    duration_sec: newer
      .duration_sec
      .clone()
      .or_else(|| older.duration_sec.clone()),
    title: newer.title.clone().or_else(|| older.title.clone()),
    text: newer.text.clone().or_else(|| older.text.clone()),
    url: newer.url.clone().or_else(|| older.url.clone()),
    seen_at: newer.seen_at.clone(),
  }
}

fn add_member(members: &mut HashMap<String, Member>, m: &Member) {
  let k = m.key();
  let next = match members.get(&k) {
    Some(have) => later_member(have, m),
    None => m.clone(),
  };
  members.insert(k, next);
}

#[derive(Clone)]
struct Draft {
  id: String,
  created_at: String,
  absorbed: BTreeSet<String>,
  members: HashMap<String, Member>,
}

fn older(a: &Draft, b: &Draft) -> bool {
  let (ta, tb) = (t(&a.created_at), t(&b.created_at));
  ta < tb || (ta == tb && cmp_js(&a.id, &b.id) == Ordering::Less)
}

/// Step 2: inside any work holding both sides of a pair, side `b` leaves again, unless its record
/// there is a creator "Same video" newer than the pair.
fn apply_different(drafts: &mut [Draft], pairs: &[Pair]) {
  for w in drafts.iter_mut() {
    for p in pairs {
      let Some(b) = w.members.get(&p.b.key()) else {
        continue;
      };
      if !w.members.contains_key(&p.a.key()) {
        continue;
      }
      if b.via == "creator" && t(&b.added_at) > t(&p.at) {
        continue;
      }
      w.members.remove(&p.b.key());
    }
  }
}

/// Step 3: works sharing a member, or one naming the other in `absorbed`, become one; the older
/// survives.
fn merge_shared(drafts: &[Draft]) -> Vec<Draft> {
  let mut parent: Vec<usize> = (0..drafts.len()).collect();
  fn find(parent: &mut [usize], i: usize) -> usize {
    if parent[i] == i {
      i
    } else {
      let r = find(parent, parent[i]);
      parent[i] = r;
      r
    }
  }
  fn join(parent: &mut [usize], i: usize, j: usize) {
    let (a, b) = (find(parent, i), find(parent, j));
    if a != b {
      parent[a.max(b)] = a.min(b);
    }
  }
  let by_id: HashMap<&str, usize> = drafts
    .iter()
    .enumerate()
    .map(|(i, d)| (d.id.as_str(), i))
    .collect();
  let mut by_member: HashMap<&str, usize> = HashMap::new();
  for (i, d) in drafts.iter().enumerate() {
    for k in d.members.keys() {
      match by_member.get(k.as_str()) {
        None => {
          by_member.insert(k.as_str(), i);
        }
        Some(&j) => join(&mut parent, i, j),
      }
    }
    for a in &d.absorbed {
      if let Some(&j) = by_id.get(a.as_str()) {
        join(&mut parent, i, j);
      }
    }
  }
  let mut groups: BTreeMap<usize, Vec<&Draft>> = BTreeMap::new();
  for (i, d) in drafts.iter().enumerate() {
    let r = find(&mut parent, i);
    groups.entry(r).or_default().push(d);
  }
  groups
    .into_values()
    .map(|g| {
      if g.len() == 1 {
        return g[0].clone();
      }
      let survivor = g
        .iter()
        .skip(1)
        .fold(g[0], |s, &d| if older(d, s) { d } else { s });
      let mut out = Draft {
        id: survivor.id.clone(),
        created_at: survivor.created_at.clone(),
        absorbed: BTreeSet::new(),
        members: HashMap::new(),
      };
      for d in &g {
        if d.id != survivor.id {
          out.absorbed.insert(d.id.clone());
        }
        out.absorbed.extend(d.absorbed.iter().cloned());
        for m in d.members.values() {
          add_member(&mut out.members, m);
        }
      }
      out.absorbed.remove(&survivor.id);
      out
    })
    .collect()
}

/// The union of every copy (plan §1.5), in the order `unionWorks` uses: union `seen`, `different`
/// and works by id; apply `different`; merge works that still share a member, and repeat both
/// while anything merged; `absorbed` ends closed transitively. Independent of the order of `docs`.
pub fn union(docs: &[&WorksDoc], device: &str, updated_at: &str) -> WorksDoc {
  let mut seen: BTreeMap<String, SeenRec> = BTreeMap::new();
  let mut different: HashMap<String, Pair> = HashMap::new();
  let mut works: HashMap<String, Draft> = HashMap::new();
  for doc in docs {
    for (k, s) in &doc.seen {
      let next = match seen.get(k) {
        Some(have) => merge_seen(have, s),
        None => s.clone(),
      };
      seen.insert(k.clone(), next);
    }
    for p in &doc.different {
      let k = pair_key(&p.a, &p.b);
      let replace = match different.get(&k) {
        None => true,
        Some(have) => {
          t(&p.at) > t(&have.at)
            || (t(&p.at) == t(&have.at) && cmp_js(&orient(p), &orient(have)) == Ordering::Greater)
        }
      };
      if replace {
        different.insert(k, p.clone());
      }
    }
    for w in &doc.works {
      let d = works.entry(w.id.clone()).or_insert_with(|| Draft {
        id: w.id.clone(),
        created_at: w.created_at.clone(),
        absorbed: BTreeSet::new(),
        members: HashMap::new(),
      });
      if t(&w.created_at) < t(&d.created_at) {
        d.created_at = w.created_at.clone();
      }
      d.absorbed.extend(w.absorbed.iter().cloned());
      for m in &w.members {
        add_member(&mut d.members, m);
      }
    }
  }
  let mut pairs: Vec<(String, Pair)> = different.into_iter().collect();
  pairs.sort_by(|a, b| cmp_js(&a.0, &b.0));
  let pairs: Vec<Pair> = pairs.into_iter().map(|(_, p)| p).collect();
  let mut drafts: Vec<Draft> = works.into_values().collect();
  drafts.sort_by(|a, b| cmp_js(&a.id, &b.id));
  loop {
    apply_different(&mut drafts, &pairs);
    let mut next = merge_shared(&drafts);
    if next.len() == drafts.len() {
      break;
    }
    next.sort_by(|a, b| cmp_js(&a.id, &b.id));
    drafts = next;
  }
  canonical(&WorksDoc {
    format: WORKS_FORMAT.into(),
    version: WORKS_VERSION,
    device: device.into(),
    updated_at: updated_at.into(),
    works: drafts
      .into_iter()
      .map(|d| Work {
        id: d.id,
        created_at: d.created_at,
        absorbed: d.absorbed.into_iter().collect(),
        members: d.members.into_values().collect(),
      })
      .collect(),
    different: pairs,
    seen,
  })
}

/// Re-applies the union rules to one copy (after any local change).
pub fn normalize(doc: &WorksDoc, updated_at: &str) -> WorksDoc {
  union(&[doc], &doc.device, updated_at)
}

// ── lookups and changes ─────────────────────────────────────────────────────────────────────────

pub fn work_of<'a>(doc: &'a WorksDoc, r: &Ref) -> Option<&'a Work> {
  let k = r.key();
  doc
    .works
    .iter()
    .find(|w| w.members.iter().any(|m| m.key() == k))
}

pub fn is_different(doc: &WorksDoc, a: &Ref, b: &Ref) -> bool {
  let k = pair_key(a, b);
  doc.different.iter().any(|p| pair_key(&p.a, &p.b) == k)
}

fn with_members(
  doc: &WorksDoc,
  a: &Ref,
  b: &Ref,
  via: &str,
  at: &str,
  new_id: &str,
  force_b: bool,
) -> WorksDoc {
  let wa = work_of(doc, a).map(|w| w.id.clone());
  let wb = work_of(doc, b).map(|w| w.id.clone());
  let member = |r: &Ref| Member {
    platform: r.platform.clone(),
    id: r.id.clone(),
    via: via.into(),
    added_at: at.into(),
  };
  let (ma, mb) = (member(a), member(b));
  let mut works = doc.works.clone();
  let target = wa
    .and_then(|id| works.iter().position(|w| w.id == id))
    .or_else(|| wb.and_then(|id| works.iter().position(|w| w.id == id)));
  match target {
    None => works.push(Work {
      id: new_id.into(),
      created_at: at.into(),
      absorbed: vec![],
      members: vec![ma, mb],
    }),
    Some(i) => {
      let put = |w: &mut Work, m: Member, force: bool| match w
        .members
        .iter()
        .position(|x| x.key() == m.key())
      {
        None => w.members.push(m),
        Some(j) if force => w.members[j] = m,
        Some(_) => {}
      };
      put(&mut works[i], ma, false);
      put(&mut works[i], mb, force_b);
    }
  }
  normalize(
    &WorksDoc {
      works,
      ..doc.clone()
    },
    at,
  )
}

/// Cuts `seen.text` to 300 code points.
pub fn cut_text(text: &str) -> String {
  text.chars().take(SEEN_TEXT_MAX).collect()
}

/// Records what BunnieHop saw of an item and groups it with every item of equal sha256, unless
/// the creator marked the two as different (`addSeen`). Pass a sha256 only for a groupable file.
pub fn add_seen(doc: &WorksDoc, r: &Ref, record: &SeenRec, new_id: &str) -> WorksDoc {
  let k = r.key();
  let mut rec = record.clone();
  rec.text = rec.text.as_deref().map(cut_text);
  let mut out = doc.clone();
  let merged = match out.seen.get(&k) {
    Some(prev) => merge_seen(prev, &rec),
    None => rec.clone(),
  };
  out.seen.insert(k.clone(), merged);
  out.updated_at = record.seen_at.clone();
  let Some(sha) = rec.sha256.clone() else {
    return out;
  };
  let mut others: Vec<String> = out.seen.keys().cloned().collect();
  others.sort_by(|a, b| cmp_js(a, b));
  for other in others {
    if other == k || out.seen[&other].sha256.as_deref() != Some(sha.as_str()) {
      continue;
    }
    let Some(o) = Ref::parse(&other) else {
      continue;
    };
    let blocked = is_different(&out, r, &o)
      || work_of(&out, &o).is_some_and(|w| {
        w.members
          .iter()
          .any(|m| is_different(&out, r, &Ref::new(&m.platform, &m.id)))
      });
    if blocked {
      continue;
    }
    out = with_members(&out, &o, r, "sha256", &record.seen_at, new_id, false);
  }
  out
}

/// The creator tapped "Same video": `b` joins `a`'s work (or they form one).
pub fn same_video(doc: &WorksDoc, a: &Ref, b: &Ref, at: &str, new_id: &str) -> WorksDoc {
  with_members(doc, a, b, "creator", at, new_id, true)
}

/// The creator tapped "Different" on a look-alike: never offered or grouped again.
pub fn mark_different(doc: &WorksDoc, a: &Ref, b: &Ref, at: &str) -> WorksDoc {
  let mut d = doc.clone();
  d.different.push(Pair {
    a: a.clone(),
    b: b.clone(),
    at: at.into(),
  });
  normalize(&d, at)
}

/// "Not the same video": the member leaves its work and is marked different from every member that
/// stays. No ledger entry moves (plan §1.5).
pub fn split_member(doc: &WorksDoc, member: &Ref, at: &str) -> WorksDoc {
  let Some(w) = work_of(doc, member) else {
    return doc.clone();
  };
  let k = member.key();
  let stay: Vec<Member> = w.members.iter().filter(|m| m.key() != k).cloned().collect();
  let id = w.id.clone();
  let mut d = doc.clone();
  for x in d.works.iter_mut().filter(|x| x.id == id) {
    x.members = stay.clone();
  }
  for m in &stay {
    d.different.push(Pair {
      a: Ref::new(&m.platform, &m.id),
      b: member.clone(),
      at: at.into(),
    });
  }
  normalize(&d, at)
}

/// Whether an item's file may be hashed for grouping (plan §1.3): a video or short with exactly one
/// media file, a size above 0 and a known duration above 0.
pub fn is_groupable(
  kind: &str,
  media_files: usize,
  size: Option<u64>,
  duration: Option<f64>,
) -> bool {
  matches!(kind, "video" | "short")
    && media_files == 1
    && size.unwrap_or(0) > 0
    && duration.unwrap_or(0.0) > 0.0
}

// ── ledger aliases (plan §1.4) ──────────────────────────────────────────────────────────────────

/// `<destination>|<account>|<source platform>|<source item>`, as in 0.2.0.
pub fn legacy_key(dest: &str, account: &str, src: &str, item: &str) -> String {
  let src = if src.is_empty() { "source" } else { src };
  format!("{dest}|{account}|{src}|{item}")
}

pub fn work_key(dest: &str, account: &str, work_id: &str) -> String {
  format!("{dest}|{account}|work|{work_id}")
}

/// The work id in a `<destination>|<account>|work|<id>` key.
pub fn work_id_of_key(key: &str) -> Option<&str> {
  let mut parts = key.splitn(4, '|');
  let (_, _, kind, id) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
  (kind == "work" && !id.is_empty()).then_some(id)
}

/// Every alias of one cell, in lookup order, and where a new reservation goes (`ledgerAliases`).
pub fn ledger_aliases(
  doc: &WorksDoc,
  r: &Ref,
  dest: &str,
  account: &str,
  saved: Option<&str>,
) -> Want {
  let own = legacy_key(dest, account, &r.platform, &r.id);
  let w = work_of(doc, r);
  let mut list: Vec<String> = saved
    .filter(|s| !s.is_empty())
    .map(str::to_string)
    .into_iter()
    .collect();
  if let Some(w) = w {
    list.push(work_key(dest, account, &w.id));
    let mut absorbed = w.absorbed.clone();
    absorbed.sort_by(|a, b| cmp_js(a, b));
    list.extend(absorbed.iter().map(|id| work_key(dest, account, id)));
  }
  list.push(own.clone());
  if let Some(w) = w {
    let mut members = w.members.clone();
    members.sort_by(|a, b| cmp_js(&a.key(), &b.key()));
    for m in members.iter().filter(|m| m.key() != r.key()) {
      list.push(legacy_key(dest, account, &m.platform, &m.id));
    }
  }
  let mut seen = HashSet::new();
  list.retain(|k| seen.insert(k.clone()));
  Want {
    aliases: list,
    members: w
      .map(|w| w.members.iter().map(Member::key).collect())
      .unwrap_or_default(),
    from_item: r.key(),
    own,
    work: w.map(|w| work_key(dest, account, &w.id)),
    post_again: false,
  }
}

/// SoapBox's dedupe key for one group and account (D-H6P3): hex sha256 of `<groupId>|<account>`.
pub fn destination_key(group_id: &str, account: &str) -> String {
  crate::sigv4::sha256_hex(format!("{group_id}|{account}").as_bytes())
}

// ── look-alikes (plan §3; proposed threshold, unmeasured) ───────────────────────────────────────

pub const MAX_DURATION_GAP_SEC: f64 = 1.0;
pub const MIN_JACCARD: f64 = 0.6;
pub const MIN_WORDS: usize = 4;

/// JavaScript's `\s`.
fn js_space(c: char) -> bool {
  matches!(
    c,
    '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
      ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
  )
}

fn letter_or_digit(c: char) -> bool {
  use icu_properties::props::{GeneralCategory, GeneralCategoryGroup};
  let gc = icu_properties::CodePointMapData::<GeneralCategory>::new().get(c);
  GeneralCategoryGroup::Letter.contains(gc) || GeneralCategoryGroup::Number.contains(gc)
}

/// Title plus text (text cut to 300 code points first), NFKC, lower case, links removed, split on
/// anything that is not a letter or a digit; the distinct words, sorted (`captionWords`).
pub fn caption_words(title: Option<&str>, text: Option<&str>) -> Vec<String> {
  let raw = format!("{}\n{}", title.unwrap_or(""), cut_text(text.unwrap_or("")));
  let raw = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc()
    .normalize(&raw)
    .to_lowercase();
  let mut no_links = String::with_capacity(raw.len());
  let mut rest = raw.as_str();
  while !rest.is_empty() {
    let link = ["https://", "http://", "www."]
      .iter()
      .find(|p| rest.starts_with(*p));
    if let Some(p) = link {
      let after = &rest[p.len()..];
      let end = after.find(js_space).unwrap_or(after.len());
      no_links.push(' ');
      rest = &after[end..];
    } else {
      let c = rest.chars().next().unwrap_or(' ');
      no_links.push(c);
      rest = &rest[c.len_utf8()..];
    }
  }
  let mut words: Vec<String> = no_links
    .split(|c: char| !letter_or_digit(c))
    .filter(|w| !w.is_empty())
    .map(str::to_string)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
  words.sort_by(|a, b| cmp_js(a, b));
  words
}

/// `(shared, union)` of two word sets.
pub fn caption_overlap(a: &[String], b: &[String]) -> (usize, usize) {
  let sb: HashSet<&String> = b.iter().collect();
  let shared = a.iter().filter(|w| sb.contains(w)).count();
  (shared, a.len() + b.len() - shared)
}

pub struct LookCandidate<'a> {
  pub kind: &'a str,
  pub duration: Option<f64>,
  pub title: Option<&'a str>,
  pub text: Option<&'a str>,
}

pub fn is_lookalike(a: &LookCandidate, b: &LookCandidate) -> bool {
  let video = |k: &str| matches!(k, "video" | "short");
  if !video(a.kind) || !video(b.kind) {
    return false;
  }
  let (da, db) = (a.duration.unwrap_or(0.0), b.duration.unwrap_or(0.0));
  if !(da > 0.0 && db > 0.0) || (da - db).abs() > MAX_DURATION_GAP_SEC {
    return false;
  }
  let wa = caption_words(a.title, a.text);
  let wb = caption_words(b.title, b.text);
  if wa.len().min(wb.len()) < MIN_WORDS {
    return false;
  }
  let (shared, union) = caption_overlap(&wa, &wb);
  union > 0 && shared as f64 / union as f64 >= MIN_JACCARD
}

/// Listed items paired with seen videos they look like (`findLookAlikes`). Never changes what posts.
pub fn find_lookalikes(
  doc: &WorksDoc,
  listed: &[Value],
  posted_to: impl Fn(&Ref) -> Vec<String>,
) -> Vec<Value> {
  let mut keys: Vec<&String> = doc.seen.keys().collect();
  keys.sort_by(|a, b| cmp_js(a, b));
  let mut out = Vec::new();
  for l in listed {
    let s_ = |k: &str| l.get(k).and_then(Value::as_str);
    let (Some(platform), Some(id)) = (s_("platform"), s_("id")) else {
      continue;
    };
    let lr = Ref::new(platform, id);
    let lw = work_of(doc, &lr);
    let mine = LookCandidate {
      kind: s_("kind").unwrap_or(""),
      duration: l.get("durationSec").and_then(Value::as_f64),
      title: s_("title"),
      text: s_("description"),
    };
    for k in &keys {
      if **k == lr.key() {
        continue;
      }
      let s = &doc.seen[*k];
      let Some(sr) = Ref::parse(k) else { continue };
      let theirs = LookCandidate {
        kind: "video",
        duration: s.duration(),
        title: s.title.as_deref(),
        text: s.text.as_deref(),
      };
      if !is_lookalike(&mine, &theirs) {
        continue;
      }
      if lw.is_some_and(|w| w.members.iter().any(|m| m.key() == **k)) || is_different(doc, &lr, &sr)
      {
        continue;
      }
      let mut dests = posted_to(&sr);
      if dests.is_empty() {
        continue;
      }
      dests.sort_by(|a, b| cmp_js(a, b));
      dests.dedup();
      let mut pair = serde_json::json!({ "item": lr, "seen": sr, "destinations": dests });
      if let Some(title) = &s.title {
        pair["title"] = title.clone().into();
      }
      if let Some(u) = &s.url {
        pair["url"] = u.clone().into();
      }
      out.push(pair);
    }
  }
  out
}

// ── the Helper's copy ───────────────────────────────────────────────────────────────────────────

fn now() -> String {
  crate::server::iso(std::time::SystemTime::now())
}

fn new_id() -> String {
  uuid::Uuid::new_v4().to_string()
}

/// The Helper's working copy (`hops/works.json`) and its shared copies.
pub struct Works {
  file: PathBuf,
  device: String,
  doc: Mutex<WorksDoc>,
  /// The working copy couldn't be read: it was kept aside and nothing groups (plan §1.2).
  unreadable: bool,
}

impl Works {
  /// Opens the working copy. A device id is made once and kept beside it (`works-device`).
  pub fn open(file: PathBuf) -> Self {
    let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
    let id_file = dir.join("works-device");
    let device = match std::fs::read_to_string(&id_file) {
      Ok(s) if uuid_ok(s.trim()) => s.trim().to_string(),
      _ => {
        let id = new_id();
        let _ = std::fs::create_dir_all(&dir);
        if crate::vault::write_atomic(&id_file, id.as_bytes()).is_ok() {
          let _ = crate::config::restrict(&id_file);
        }
        id
      }
    };
    let aside = Self::aside_path(&file);
    let mut unreadable = aside.exists();
    let doc = match std::fs::read_to_string(&file) {
      Ok(text) => match WorksDoc::parse(&text) {
        Ok(d) => d,
        Err(_) => {
          // kept for whoever fixes it; never overwritten by a fresh copy
          if !aside.exists() {
            let _ = std::fs::rename(&file, &aside);
          }
          unreadable = true;
          WorksDoc::empty(&device, &now())
        }
      },
      Err(_) => WorksDoc::empty(&device, &now()),
    };
    let mut doc = doc;
    doc.device = device.clone();
    Self {
      file,
      device,
      doc: Mutex::new(doc),
      unreadable,
    }
  }

  fn aside_path(file: &Path) -> PathBuf {
    file.with_extension("json.unreadable")
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, WorksDoc> {
    self.doc.lock().unwrap_or_else(|e| e.into_inner())
  }

  pub fn device(&self) -> &str {
    &self.device
  }

  pub fn unreadable(&self) -> bool {
    self.unreadable
  }

  pub fn doc(&self) -> WorksDoc {
    self.lock().clone()
  }

  fn save(&self, doc: &WorksDoc) {
    if crate::vault::write_atomic(&self.file, doc.serialize().as_bytes()).is_ok() {
      let _ = crate::config::restrict(&self.file);
    }
  }

  /// Applies a change under the lock and saves it. Nothing changes while the copy is unreadable.
  fn change(&self, f: impl FnOnce(&WorksDoc) -> WorksDoc) -> bool {
    if self.unreadable {
      return false;
    }
    let mut g = self.lock();
    let next = f(&g);
    let changed = next.works != g.works || next.different != g.different || next.seen != g.seen;
    if changed {
      *g = next;
      self.save(&g);
    }
    changed
  }

  /// What a hop or the background pass learned of an item. The sha256 is used only for a groupable
  /// file (`is_groupable`); everything else is a `seen` record without one, which never groups.
  pub fn observe(&self, r: &Ref, mut rec: SeenRec, groupable: bool) -> bool {
    if !groupable {
      rec.sha256 = None;
    }
    let id = new_id();
    self.change(|d| add_seen(d, r, &rec, &id))
  }

  /// "Same video": returns the work id.
  pub fn same(&self, a: &Ref, b: &Ref) -> Option<String> {
    let id = new_id();
    self.change(|d| same_video(d, a, b, &now(), &id));
    work_of(&self.lock(), a).map(|w| w.id.clone())
  }

  /// Items backed up before grouping existed (plan §1.3): reads `<platform>/<handle>/bunniehop.json`
  /// under a local vault and records each item not yet in `seen`, with the sha256 the sidecar
  /// already holds. Nothing is hashed or downloaded. Returns how many items were added.
  pub fn backfill(&self, vault: &Path) -> usize {
    let mut added = 0;
    let dirs = |p: &Path| -> Vec<PathBuf> {
      std::fs::read_dir(p)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .collect()
    };
    for platform in dirs(vault) {
      for handle in dirs(&platform) {
        let Ok(text) = std::fs::read_to_string(handle.join("bunniehop.json")) else {
          continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
          continue;
        };
        if doc["format"] != "bunniehop.sidecar" {
          continue;
        }
        let src = doc["source"]["platform"].as_str().unwrap_or("");
        for item in doc["items"].as_array().into_iter().flatten() {
          let str_ = |k: &str| {
            item
              .get(k)
              .and_then(Value::as_str)
              .filter(|t| !t.is_empty())
          };
          let Some(id) = str_("id") else { continue };
          let r = Ref::new(str_("platform").unwrap_or(src), id);
          if self.lock().seen.contains_key(&r.key()) {
            continue;
          }
          let media: Vec<&Value> = item["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["role"] == "media")
            .collect();
          let size = media.first().and_then(|f| f["sizeBytes"].as_u64());
          let duration = item.get("durationSec").and_then(Value::as_f64);
          let groupable = is_groupable(str_("kind").unwrap_or(""), media.len(), size, duration);
          let rec = SeenRec {
            sha256: media
              .first()
              .and_then(|f| f["sha256"].as_str())
              .map(str::to_string),
            size_bytes: size.filter(|n| *n > 0),
            duration_sec: duration.and_then(js_number),
            title: str_("title").map(str::to_string),
            text: str_("description").map(cut_text),
            url: str_("url").map(str::to_string),
            seen_at: str_("backedUpAt").map(str::to_string).unwrap_or_else(now),
          };
          if self.observe(&r, rec, groupable) {
            added += 1;
          }
        }
      }
    }
    added
  }

  /// A one-member work for an item that is in none, for destinations that post per group
  /// (SoapBox, D-H6P3). Returns the item's work id.
  pub fn own_work(&self, r: &Ref) -> Option<String> {
    let id = new_id();
    self.change(|d| {
      if work_of(d, r).is_some() {
        return d.clone();
      }
      let at = now();
      let mut out = d.clone();
      out.works.push(Work {
        id: id.clone(),
        created_at: at.clone(),
        absorbed: vec![],
        members: vec![Member {
          platform: r.platform.clone(),
          id: r.id.clone(),
          via: "sha256".into(),
          added_at: at.clone(),
        }],
      });
      normalize(&out, &at)
    });
    work_of(&self.lock(), r).map(|w| w.id.clone())
  }

  pub fn different(&self, a: &Ref, b: &Ref) {
    self.change(|d| mark_different(d, a, b, &now()));
  }

  /// "Not the same video". Refused (`workBusy`) only while `busy` says the member is posting.
  pub fn split(&self, member: &Ref, busy: bool) -> Result<(), Failure> {
    if busy {
      return Err(Failure::new("workBusy", WORK_BUSY_MESSAGE));
    }
    self.change(|d| split_member(d, member, &now()));
    Ok(())
  }

  /// Takes in other copies (another engine's, other devices' files). Returns whether ours changed.
  pub fn merge(&self, incoming: &[WorksDoc]) -> bool {
    let device = self.device.clone();
    self.change(|d| {
      let mut all: Vec<&WorksDoc> = vec![d];
      all.extend(incoming.iter());
      union(&all, &device, &now())
    })
  }

  /// The cell's aliases and reservation keys (`posted::Want`).
  pub fn aliases(&self, r: &Ref, dest: &str, account: &str, saved: Option<&str>) -> Want {
    ledger_aliases(&self.lock(), r, dest, account, saved)
  }

  /// The work an item is in, with its other members.
  pub fn work_of(&self, r: &Ref) -> Option<Work> {
    work_of(&self.lock(), r).cloned()
  }

  pub fn seen(&self, r: &Ref) -> Option<SeenRec> {
    self.lock().seen.get(&r.key()).cloned()
  }

  fn own_name(&self) -> String {
    format!("{}.json", self.device)
  }

  /// Reads every `.works/*.json` in a local vault as a union with ours. A file that isn't a works
  /// copy is left alone and read as nothing.
  pub fn pull_local(&self, vault: &Path) -> bool {
    let Ok(dir) = std::fs::read_dir(vault.join(SHARED_DIR)) else {
      return false;
    };
    let docs: Vec<WorksDoc> = dir
      .filter_map(|e| e.ok().map(|e| e.path()))
      .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
      .filter_map(|p| std::fs::read_to_string(p).ok())
      .filter_map(|t| WorksDoc::parse(&t).ok())
      .collect();
    !docs.is_empty() && self.merge(&docs)
  }

  /// Writes our copy to `<vault>/.works/<device>.json`; never touches another device's file.
  pub fn push_local(&self, vault: &Path) -> std::io::Result<()> {
    if self.unreadable {
      return Ok(());
    }
    let dir = vault.join(SHARED_DIR);
    std::fs::create_dir_all(&dir)?;
    let text = self.doc().serialize();
    crate::vault::write_atomic(&dir.join(self.own_name()), text.as_bytes())
  }

  /// The same for a cloud vault: every device file comes down to `temp`, ours goes up.
  pub async fn pull_remote(&self, r: &dyn Remote, temp: &Path) -> Result<bool, Failure> {
    let names = r.list(SHARED_DIR).await?;
    let mut docs = Vec::new();
    for n in names
      .iter()
      .filter(|n| n.ends_with(".json") && !n.contains('/'))
    {
      let local = temp.join(SHARED_DIR).join(n);
      if r.get(&format!("{SHARED_DIR}/{n}"), &local).await? {
        if let Some(d) = std::fs::read_to_string(&local)
          .ok()
          .and_then(|t| WorksDoc::parse(&t).ok())
        {
          docs.push(d);
        }
      }
      let _ = std::fs::remove_file(&local);
    }
    Ok(!docs.is_empty() && self.merge(&docs))
  }

  pub async fn push_remote(&self, r: &dyn Remote, temp: &Path) -> Result<(), Failure> {
    if self.unreadable {
      return Ok(());
    }
    let local = temp.join(SHARED_DIR).join(self.own_name());
    std::fs::create_dir_all(local.parent().unwrap_or(temp))
      .and_then(|()| std::fs::write(&local, self.doc().serialize()))
      .map_err(|e| Failure::new("diskFull", "Couldn't stage the list of same videos.").with(e))?;
    let res = r
      .put(&local, &format!("{SHARED_DIR}/{}", self.own_name()))
      .await;
    let _ = std::fs::remove_file(&local);
    res
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  /// The shared fixtures: in the monorepo, or `fixtures/sidecar-cross` in the published Helper.
  fn fixture(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mono = root.join("../../packages/sidecar/fixtures/cross");
    let dir = if mono.is_dir() {
      mono
    } else {
      root.join("fixtures/sidecar-cross")
    };
    // a Windows checkout may turn the fixture's line endings into CRLF; the file format is LF
    std::fs::read_to_string(dir.join(name))
      .unwrap()
      .replace("\r\n", "\n")
  }

  fn rec(sha: Option<&str>, at: &str) -> SeenRec {
    SeenRec {
      sha256: sha.map(|s| s.repeat(64)),
      size_bytes: Some(1000),
      duration_sec: js_number(30.0),
      seen_at: at.into(),
      ..SeenRec::default()
    }
  }

  const A1: &str = "11111111-1111-4111-8111-111111111111";
  const A2: &str = "22222222-2222-4222-8222-222222222222";

  #[test]
  fn works_file_round_trips_the_shared_fixture() {
    let text = fixture("works.json");
    let doc = WorksDoc::parse(&text).unwrap();
    assert_eq!(doc.serialize(), text, "byte for byte");
    assert_eq!(doc.works[0].absorbed, [A2]);
    // not a works file: refused, never half read
    assert!(WorksDoc::parse(&text.replace("bunniehop.works", "bunniehop.sidecar")).is_err());
    assert!(WorksDoc::parse(&text.replace(A1, "not-a-uuid")).is_err());
  }

  #[test]
  fn works_identical_sha256_joins_one_work_and_keeps_the_id() {
    let d = WorksDoc::empty("dev", "2026-11-01T00:00:00Z");
    let a = Ref::new("youtube", "a");
    let b = Ref::new("tiktok", "b");
    let c = Ref::new("instagram", "c");
    let d = add_seen(&d, &a, &rec(Some("a"), "2026-11-01T01:00:00Z"), A1);
    assert!(d.works.is_empty(), "one item is no group");
    let d = add_seen(&d, &b, &rec(Some("a"), "2026-11-01T02:00:00Z"), A1);
    assert_eq!(d.works.len(), 1);
    assert_eq!(d.works[0].id, A1);
    assert!(d.works[0].members.iter().all(|m| m.via == "sha256"));
    let d = add_seen(&d, &c, &rec(Some("a"), "2026-11-01T03:00:00Z"), A2);
    assert_eq!(d.works.len(), 1);
    assert_eq!(
      d.works[0].id, A1,
      "a later copy joins; the id never changes"
    );
    assert_eq!(d.works[0].members.len(), 3);
    // a different file stays out
    let d = add_seen(
      &d,
      &Ref::new("youtube", "z"),
      &rec(Some("b"), "2026-11-01T04:00:00Z"),
      A2,
    );
    assert_eq!(d.works.len(), 1);
    assert_eq!(d.works[0].members.len(), 3);
  }

  #[test]
  fn works_never_groups_photos_text_multi_file_or_zero_length_items() {
    assert!(is_groupable("video", 1, Some(10), Some(3.0)));
    assert!(is_groupable("short", 1, Some(10), Some(3.0)));
    assert!(!is_groupable("photo", 1, Some(10), Some(3.0)));
    assert!(!is_groupable("text", 0, None, None));
    assert!(!is_groupable("video", 2, Some(10), Some(3.0)));
    assert!(!is_groupable("video", 1, Some(0), Some(3.0)));
    assert!(!is_groupable("video", 1, Some(10), None));
    assert!(!is_groupable("video", 1, Some(10), Some(0.0)));
    let dir = tempfile::tempdir().unwrap();
    let w = Works::open(dir.path().join("works.json"));
    w.observe(
      &Ref::new("instagram", "p1"),
      rec(Some("a"), "2026-11-01T01:00:00Z"),
      false,
    );
    w.observe(
      &Ref::new("instagram", "p2"),
      rec(Some("a"), "2026-11-01T01:00:00Z"),
      false,
    );
    let doc = w.doc();
    assert!(doc.works.is_empty());
    assert!(
      doc.seen["instagram|p1"].sha256.is_none(),
      "no checksum kept"
    );
  }

  #[test]
  fn works_different_pair_is_never_grouped_again() {
    let dir = tempfile::tempdir().unwrap();
    let w = Works::open(dir.path().join("works.json"));
    let a = Ref::new("youtube", "a");
    let b = Ref::new("tiktok", "b");
    w.observe(&a, rec(Some("a"), "2026-11-01T01:00:00Z"), true);
    w.observe(&b, rec(Some("a"), "2026-11-01T01:00:00Z"), true);
    assert_eq!(w.doc().works[0].members.len(), 2);
    w.split(&b, false).unwrap();
    assert!(is_different(&w.doc(), &a, &b));
    // the same file seen again, and a merge of a copy from before the split
    w.observe(&b, rec(Some("a"), "2026-11-02T01:00:00Z"), true);
    let mut stale = w.doc();
    stale.works[0].members.push(Member {
      platform: "tiktok".into(),
      id: "b".into(),
      via: "sha256".into(),
      added_at: "2026-11-01T01:00:00Z".into(),
    });
    stale.different.clear();
    w.merge(&[stale]);
    let doc = w.doc();
    assert!(work_of(&doc, &b).is_none_or(|x| x.members.iter().all(|m| m.key() != a.key())));
    // the look-alike "Different" works the same way
    let c = Ref::new("youtube", "c");
    w.different(&a, &c);
    w.observe(&c, rec(Some("a"), "2026-11-03T01:00:00Z"), true);
    assert!(work_of(&w.doc(), &c).is_none_or(|x| x.members.iter().all(|m| m.key() != a.key())));
  }

  #[test]
  fn works_merge_keeps_the_older_id_and_absorbs_the_other() {
    let d = WorksDoc::empty("dev", "2026-11-01T00:00:00Z");
    let (a, b, c, e) = (
      Ref::new("youtube", "a"),
      Ref::new("tiktok", "b"),
      Ref::new("youtube", "c"),
      Ref::new("tiktok", "e"),
    );
    let d = add_seen(&d, &a, &rec(Some("a"), "2026-11-01T01:00:00Z"), A2);
    let d = add_seen(&d, &b, &rec(Some("a"), "2026-11-01T01:00:00Z"), A2);
    let d = add_seen(&d, &c, &rec(Some("b"), "2026-11-02T01:00:00Z"), A1);
    let d = add_seen(&d, &e, &rec(Some("b"), "2026-11-02T01:00:00Z"), A1);
    assert_eq!(d.works.len(), 2);
    // the creator says a and c are the same video: A2 (older) survives and absorbs A1
    let d = same_video(
      &d,
      &a,
      &c,
      "2026-11-03T00:00:00Z",
      "33333333-3333-4333-8333-333333333333",
    );
    assert_eq!(d.works.len(), 1);
    assert_eq!(d.works[0].id, A2);
    assert_eq!(d.works[0].absorbed, [A1]);
    assert_eq!(d.works[0].members.len(), 4);
    // both old work keys are aliases of every member
    let w = ledger_aliases(&d, &e, "bluesky", "acc", None);
    assert_eq!(
      w.aliases[..3],
      [
        format!("bluesky|acc|work|{A2}"),
        format!("bluesky|acc|work|{A1}"),
        "bluesky|acc|tiktok|e".to_string()
      ]
    );
    assert_eq!(
      w.work.as_deref(),
      Some(format!("bluesky|acc|work|{A2}").as_str())
    );
  }

  #[test]
  fn works_unreadable_file_is_kept_aside_groups_nothing_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("works.json");
    std::fs::write(&f, b"{\"format\":\"bunniehop.works\",\"vers").unwrap();
    let w = Works::open(f.clone());
    assert!(w.unreadable());
    assert_eq!(
      std::fs::read(dir.path().join("works.json.unreadable")).unwrap(),
      b"{\"format\":\"bunniehop.works\",\"vers",
      "kept aside as it was"
    );
    w.observe(
      &Ref::new("youtube", "a"),
      rec(Some("a"), "2026-11-01T01:00:00Z"),
      true,
    );
    w.observe(
      &Ref::new("tiktok", "b"),
      rec(Some("a"), "2026-11-01T01:00:00Z"),
      true,
    );
    assert!(w.doc().works.is_empty(), "groups nothing");
    assert!(!f.exists(), "no fresh copy replaces it");
    w.push_local(dir.path()).unwrap();
    assert!(!dir.path().join(SHARED_DIR).exists(), "shares nothing");
    // still unreadable after a restart, until someone deals with the kept copy
    assert!(Works::open(f).unreadable());
    assert!(UNREADABLE_LINE.starts_with("BunnieHop couldn't read its list of same videos"));
  }

  #[test]
  fn works_split_is_refused_only_for_a_live_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let w = Works::open(dir.path().join("works.json"));
    let a = Ref::new("youtube", "a");
    let b = Ref::new("tiktok", "b");
    w.observe(&a, rec(Some("a"), "2026-11-01T01:00:00Z"), true);
    w.observe(&b, rec(Some("a"), "2026-11-01T01:00:00Z"), true);
    let e = w.split(&b, true).unwrap_err();
    assert_eq!(e.code, "workBusy");
    assert_eq!(e.message, WORK_BUSY_MESSAGE);
    assert_eq!(w.doc().works[0].members.len(), 2, "nothing changed");
    // joins and merges are never refused, and an idle member splits
    assert!(w.same(&a, &Ref::new("instagram", "c")).is_some());
    w.split(&b, false).unwrap();
    assert!(work_of(&w.doc(), &b).is_none());
    assert_eq!(work_of(&w.doc(), &a).unwrap().members.len(), 2);
  }

  #[test]
  fn works_union_matches_the_shared_fixture_in_both_orders() {
    let v: Value = serde_json::from_str(&fixture("works-union.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    let mut stale_case = false;
    for c in cases {
      let name = c["name"].as_str().unwrap();
      stale_case |= name.contains("stale copy");
      let docs: Vec<WorksDoc> = c["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| WorksDoc::parse(&d.to_string()).unwrap())
        .collect();
      let expected = WorksDoc::parse(&c["expected"].to_string()).unwrap();
      let (dev, at) = (
        c["device"].as_str().unwrap(),
        c["updatedAt"].as_str().unwrap(),
      );
      let fwd: Vec<&WorksDoc> = docs.iter().collect();
      let back: Vec<&WorksDoc> = docs.iter().rev().collect();
      assert_eq!(
        union(&fwd, dev, at).serialize(),
        expected.serialize(),
        "{name}"
      );
      assert_eq!(
        union(&back, dev, at).serialize(),
        expected.serialize(),
        "{name}, reversed"
      );
    }
    assert!(
      stale_case,
      "the stale-copy-after-split case is in the fixture"
    );
  }

  #[test]
  fn works_device_files_are_read_as_a_union() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let shared = vault.join(SHARED_DIR);
    std::fs::create_dir_all(&shared).unwrap();
    let w = Works::open(dir.path().join("hops/works.json"));
    let a = Ref::new("youtube", "a");
    let b = Ref::new("tiktok", "b");
    let c = Ref::new("instagram", "c");
    w.observe(&a, rec(Some("a"), "2026-11-01T01:00:00Z"), true);
    // two other devices: one saw b with the same file, one grouped c with a by hand
    let one = add_seen(
      &WorksDoc::empty("phone", "2026-11-01T02:00:00Z"),
      &b,
      &rec(Some("a"), "2026-11-01T02:00:00Z"),
      A1,
    );
    let mut two = WorksDoc::empty("laptop", "2026-11-01T03:00:00Z");
    two = same_video(&two, &a, &c, "2026-11-01T03:00:00Z", A2);
    std::fs::write(shared.join("phone.json"), one.serialize()).unwrap();
    std::fs::write(shared.join("laptop.json"), two.serialize()).unwrap();
    std::fs::write(shared.join("notes.json"), "not ours").unwrap();
    assert!(w.pull_local(&vault));
    // b joins a by sha256 once the union has both records
    w.observe(&a, rec(Some("a"), "2026-11-01T04:00:00Z"), true);
    let doc = w.doc();
    let work = work_of(&doc, &a).unwrap();
    let keys: HashSet<String> = work.members.iter().map(Member::key).collect();
    assert_eq!(keys, HashSet::from([a.key(), b.key(), c.key()]));
    w.push_local(&vault).unwrap();
    let own = shared.join(format!("{}.json", w.device()));
    assert_eq!(std::fs::read_to_string(own).unwrap(), w.doc().serialize());
    assert_eq!(
      std::fs::read_to_string(shared.join("phone.json")).unwrap(),
      one.serialize(),
      "other files untouched"
    );
    assert_eq!(
      std::fs::read_to_string(shared.join("notes.json")).unwrap(),
      "not ours"
    );
    // the device id is kept across restarts
    assert_eq!(
      Works::open(dir.path().join("hops/works.json")).device(),
      w.device()
    );
  }

  #[test]
  fn lookalike_vectors_match_the_shared_fixture() {
    let v: Value = serde_json::from_str(&fixture("lookalike.json")).unwrap();
    assert_eq!(
      v["rule"],
      json!({ "maxDurationGapSec": 1, "minJaccard": 0.6, "minWords": 4 })
    );
    let vectors = v["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for c in vectors {
      let name = c["name"].as_str().unwrap();
      let cand = |x: &'static str| {
        let o = &c[x];
        LookCandidate {
          kind: o["kind"].as_str().unwrap(),
          duration: o["durationSec"].as_f64(),
          title: o["title"].as_str(),
          text: o["text"].as_str(),
        }
      };
      let (a, b) = (cand("a"), cand("b"));
      let wa = caption_words(a.title, a.text);
      let wb = caption_words(b.title, b.text);
      assert_eq!(json!(wa), c["wordsA"], "{name}: words a");
      assert_eq!(json!(wb), c["wordsB"], "{name}: words b");
      let (shared, union) = caption_overlap(&wa, &wb);
      assert_eq!(json!(shared), c["shared"], "{name}: shared");
      assert_eq!(json!(union), c["union"], "{name}: union");
      assert_eq!(json!(is_lookalike(&a, &b)), c["pair"], "{name}: pair");
    }
  }

  #[test]
  fn soapbox_key_is_sha256_of_group_id_and_account() {
    assert_eq!(
      destination_key(A1, "acc"),
      crate::sigv4::sha256_hex(format!("{A1}|acc").as_bytes())
    );
    // `printf 'g|a' | shasum -a 256`, so a change of separator or encoding shows
    assert_eq!(
      destination_key("g", "a"),
      "97f81cd52eff9b9866dcf9df9e48246cfe8c17a7e9cef9f71ec209601c63ed55"
    );
  }
}

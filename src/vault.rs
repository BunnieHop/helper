//! The Backup Vault on disk (PLAN §8, F2): item folders, `bunniehop.json` per source and
//! `index.csv`. Mirrors packages/sidecar exactly (fixtures in packages/sidecar/fixtures/cross).
//! The vault belongs to the creator: nothing here deletes or overwrites a file already in it.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const SIDECAR: &str = "bunniehop.json";
pub const INDEX: &str = "index.csv";

/// A folder from the web app's plan (D-033), accepted only as a plain relative path.
pub fn safe_folder(rel: &str) -> Option<PathBuf> {
  let p = Path::new(rel);
  if rel.is_empty() || rel.len() > 600 || rel.contains('\0') || rel.contains('\\') {
    return None;
  }
  let ok = p.components().all(|c| matches!(c, Component::Normal(_)));
  ok.then(|| p.to_path_buf())
}

fn ts(item: &Value) -> Option<i128> {
  let s = item.get("publishedAt")?.as_str()?;
  let d = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
  Some(d.unix_timestamp_nanos() / 1_000_000)
}

fn id(item: &Value) -> &str {
  item.get("id").and_then(Value::as_str).unwrap_or("")
}

/// Newest first, then id in code-point order (same as `sortItems`).
pub fn sort_items(items: &mut [Value]) {
  items.sort_by(|a, b| match (ts(a), ts(b)) {
    (Some(x), Some(y)) if x != y => y.cmp(&x),
    (Some(_), None) => Ordering::Less,
    (None, Some(_)) => Ordering::Greater,
    _ => id(a).cmp(id(b)),
  });
}

/// Incremental merge (same as `mergeSidecar`): items keyed by id; a re-run refreshes facts but
/// keeps every file already recorded and the folder the item first went to.
pub fn merge(existing: &Value, incoming: &Value) -> Value {
  let mut items: Vec<Value> = existing["items"].as_array().cloned().unwrap_or_default();
  for inc in incoming["items"].as_array().into_iter().flatten() {
    match items.iter_mut().find(|p| id(p) == id(inc)) {
      None => items.push(inc.clone()),
      Some(prev) => {
        let mut files = prev["files"].as_array().cloned().unwrap_or_default();
        for f in inc["files"].as_array().into_iter().flatten() {
          if !files.iter().any(|p| p["path"] == f["path"]) {
            files.push(f.clone());
          }
        }
        let mut hashes = prev["hashes"].as_object().cloned().unwrap_or_default();
        hashes.extend(inc["hashes"].as_object().cloned().unwrap_or_default());
        let folder = prev["folder"].clone();
        let mut next = prev.as_object().cloned().unwrap_or_default();
        next.extend(inc.as_object().cloned().unwrap_or_default());
        next.insert("files".into(), Value::Array(files));
        next.insert("hashes".into(), Value::Object(hashes));
        next.insert("folder".into(), folder);
        *prev = Value::Object(next);
      }
    }
  }
  sort_items(&mut items);
  let mut source = existing["source"].as_object().cloned().unwrap_or_default();
  source.extend(incoming["source"].as_object().cloned().unwrap_or_default());
  let mut doc = existing.as_object().cloned().unwrap_or_default();
  doc.insert("generatedAt".into(), incoming["generatedAt"].clone());
  doc.insert("source".into(), Value::Object(source));
  doc.insert("items".into(), Value::Array(items));
  Value::Object(doc)
}

pub fn new_doc(source: Value, generated_at: &str, items: Vec<Value>) -> Value {
  json!({ "format": "bunniehop.sidecar", "version": 1, "source": source, "generatedAt": generated_at, "items": items })
}

/// 2-space JSON with a trailing newline, items sorted (same as `serializeSidecar`).
pub fn serialize(doc: &Value) -> String {
  let mut d = doc.clone();
  if let Some(items) = d.get_mut("items").and_then(Value::as_array_mut) {
    sort_items(items);
  }
  serde_json::to_string_pretty(&d).unwrap_or_default() + "\n"
}

const COLUMNS: [&str; 14] = [
  "id",
  "platform",
  "kind",
  "title",
  "published_at",
  "duration_sec",
  "visibility",
  "views",
  "likes",
  "comments",
  "tags",
  "url",
  "folder",
  "sha256",
];

/// JavaScript's `String(n)` for the numbers BunnieHop writes (integers and plain decimals).
fn js_number(n: &serde_json::Number) -> String {
  if let Some(i) = n.as_i64() {
    return i.to_string();
  }
  if let Some(u) = n.as_u64() {
    return u.to_string();
  }
  let f = n.as_f64().unwrap_or(0.0);
  if f.fract() == 0.0 && f.abs() < 1e21 {
    format!("{}", f as i64)
  } else {
    format!("{f}")
  }
}

fn text(v: Option<&Value>) -> String {
  match v {
    Some(Value::String(s)) => s.clone(),
    Some(Value::Number(n)) => js_number(n),
    Some(Value::Bool(b)) => b.to_string(),
    _ => String::new(),
  }
}

/// Spreadsheet formula triggers get one leading apostrophe (CSV injection), as in csv.ts.
fn protect(v: &str) -> String {
  let rest = v.trim_start_matches('\'');
  let trigger = rest.starts_with(['=', '+', '-', '@', '\t', '\r']);
  if trigger {
    format!("'{v}")
  } else {
    v.to_string()
  }
}

fn cell(v: &str) -> String {
  let p = protect(v);
  if p.contains(['"', ',', '\r', '\n']) {
    format!("\"{}\"", p.replace('"', "\"\""))
  } else {
    p
  }
}

/// `index.csv`: RFC 4180, UTF-8 with BOM, CRLF (same as `writeIndexCsv`).
pub fn index_csv(items: &[Value]) -> String {
  let mut out = String::from("\u{feff}");
  out.push_str(&COLUMNS.join(","));
  out.push_str("\r\n");
  for i in items {
    let tags: Vec<String> = i["tags"]
      .as_array()
      .map(|a| a.iter().map(|t| text(Some(t))).collect())
      .unwrap_or_default();
    let row = [
      text(i.get("id")),
      text(i.get("platform")),
      text(i.get("kind")),
      text(i.get("title")),
      text(i.get("publishedAt")),
      text(i.get("durationSec")),
      text(i.get("visibility")),
      text(i.pointer("/stats/views")),
      text(i.pointer("/stats/likes")),
      text(i.pointer("/stats/comments")),
      tags.join("|"),
      text(i.get("url")),
      text(i.get("folder")),
      text(i.pointer("/hashes/sha256")),
    ];
    out.push_str(&row.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
    out.push_str("\r\n");
  }
  out
}

/// Writes `path` via a temp file + rename so a crash never leaves half a sidecar.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
  let dir = path.parent().unwrap_or(Path::new("."));
  std::fs::create_dir_all(dir)?;
  let tmp = dir.join(format!(
    ".{}.part",
    path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
  ));
  let mut f = std::fs::File::create(&tmp)?;
  f.write_all(contents)?;
  f.sync_all()?;
  std::fs::rename(&tmp, path)
}

/// Merges `items` into `<source_dir>/bunniehop.json` and rewrites `index.csv` next to it.
/// An unreadable existing sidecar is kept aside (`bunniehop.json.bad-<ts>`), never discarded.
pub fn upsert(
  source_dir: &Path,
  source: Value,
  items: Vec<Value>,
  now: &str,
) -> std::io::Result<Value> {
  let path = source_dir.join(SIDECAR);
  let incoming = new_doc(source.clone(), now, items);
  let existing = match std::fs::read_to_string(&path) {
    Ok(s) => match serde_json::from_str::<Value>(&s) {
      Ok(v) if v["format"] == "bunniehop.sidecar" => Some(v),
      _ => {
        let aside = source_dir.join(format!("{SIDECAR}.bad-{}", now.replace(':', "")));
        std::fs::rename(&path, aside)?;
        None
      }
    },
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
    Err(e) => return Err(e),
  };
  let doc = match existing {
    Some(e) => merge(&e, &incoming),
    None => merge(&new_doc(source, now, vec![]), &incoming),
  };
  write_atomic(&path, serialize(&doc).as_bytes())?;
  let items = doc["items"].as_array().cloned().unwrap_or_default();
  write_atomic(&source_dir.join(INDEX), index_csv(&items).as_bytes())?;
  Ok(doc)
}

pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
  let mut f = std::fs::File::open(path)?;
  let mut h = Sha256::new();
  let mut buf = vec![0u8; 1 << 16];
  let mut n = 0u64;
  loop {
    let k = f.read(&mut buf)?;
    if k == 0 {
      break;
    }
    h.update(&buf[..k]);
    n += k as u64;
  }
  Ok((hex::encode(h.finalize()), n))
}

/// Role of a file written by `ytdlp::download_args`, from its name.
pub fn role_of(name: &str) -> Option<(&'static str, Option<String>)> {
  if name.ends_with(".info.json") {
    return Some(("info", None));
  }
  if let Some(rest) = name.strip_prefix("captions.") {
    let lang = rest.rsplit_once('.').map(|(l, _)| l.to_string());
    return Some(("caption", lang.filter(|l| !l.is_empty())));
  }
  if name.starts_with("thumbnail.") {
    return Some(("thumbnail", None));
  }
  if name.starts_with("media.") && !name.ends_with(".part") && !name.ends_with(".ytdl") {
    return Some(("media", None));
  }
  None
}

/// `VaultFile` entries for an item folder, with sizes and SHA-256.
pub fn describe(folder: &Path) -> std::io::Result<Vec<Value>> {
  let mut out = Vec::new();
  let mut names: Vec<String> = std::fs::read_dir(folder)?
    .filter_map(|e| e.ok())
    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
    .filter_map(|e| e.file_name().to_str().map(String::from))
    .collect();
  names.sort();
  for name in names {
    let Some((role, lang)) = role_of(&name) else {
      continue;
    };
    let (sha, size) = sha256_file(&folder.join(&name))?;
    let mut m = Map::new();
    m.insert("role".into(), json!(role));
    m.insert("path".into(), json!(name));
    m.insert("sizeBytes".into(), json!(size));
    m.insert("sha256".into(), json!(sha));
    if let Some(l) = lang {
      m.insert("lang".into(), json!(l));
    }
    out.push(Value::Object(m));
  }
  Ok(out)
}

/// Moves finished files from temp into the vault folder. A file already in the vault is kept
/// as it is (the creator's copy wins); the temp copy is dropped with the temp folder.
pub fn move_into(from: &Path, to: &Path) -> std::io::Result<Vec<PathBuf>> {
  std::fs::create_dir_all(to)?;
  let mut moved = Vec::new();
  for e in std::fs::read_dir(from)? {
    let e = e?;
    if !e.file_type()?.is_file() {
      continue;
    }
    let name = e.file_name();
    let Some(n) = name.to_str() else { continue };
    if role_of(n).is_none() {
      continue;
    }
    let dest = to.join(&name);
    if dest.exists() {
      continue;
    }
    if std::fs::rename(e.path(), &dest).is_err() {
      // different volume (external drive vault): copy, then the temp folder is removed
      let part = to.join(format!(".{n}.part"));
      std::fs::copy(e.path(), &part)?;
      std::fs::rename(&part, &dest)?;
    }
    moved.push(dest);
  }
  Ok(moved)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The shared fixtures live in `packages/sidecar` in the monorepo and are copied to
  /// `fixtures/sidecar-cross` in the published Helper source (scripts/publish-helper.sh).
  fn cross(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mono = root.join("../../packages/sidecar/fixtures/cross");
    let dir = if mono.is_dir() {
      mono
    } else {
      root.join("fixtures/sidecar-cross")
    };
    std::fs::read_to_string(dir.join(name)).unwrap()
  }

  #[test]
  fn sidecar_merge_matches_the_typescript_package() {
    let existing: Value = serde_json::from_str(&cross("existing.json")).unwrap();
    let incoming: Value = serde_json::from_str(&cross("incoming.json")).unwrap();
    let want: Value = serde_json::from_str(&cross("merged.json")).unwrap();
    let got = merge(&existing, &incoming);
    assert_eq!(got, want);
    let ids = |v: &Value| {
      v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].clone())
        .collect::<Vec<_>>()
    };
    assert_eq!(ids(&got), ids(&want), "same order");
  }

  #[test]
  fn sidecar_index_csv_is_byte_identical_to_the_typescript_package() {
    let merged: Value = serde_json::from_str(&cross("merged.json")).unwrap();
    assert_eq!(
      index_csv(merged["items"].as_array().unwrap()),
      cross("index.csv")
    );
  }

  #[test]
  fn sidecar_serialize_round_trips_the_fixture() {
    let merged: Value = serde_json::from_str(&cross("merged.json")).unwrap();
    let back: Value = serde_json::from_str(&serialize(&merged)).unwrap();
    assert_eq!(back, merged);
    assert!(serialize(&merged).ends_with("}\n"));
  }

  #[test]
  fn sidecar_csv_protects_formulas() {
    let items = vec![
      json!({ "id": "1", "title": "=HYPERLINK(\"x\")", "tags": ["a", "b"], "durationSec": 61.0, "folder": "f" }),
    ];
    let csv = index_csv(&items);
    assert!(csv.contains("\"'=HYPERLINK(\"\"x\"\")\""), "{csv}");
    assert!(csv.contains(",61,"));
    assert!(csv.contains("a|b"));
  }

  #[test]
  fn vault_folder_must_be_plain_relative() {
    assert!(safe_folder("youtube/creator/2026/2026-01-02_hi_abc").is_some());
    for bad in ["", "/etc", "../x", "a/../../b", "a\\b", "./a"] {
      assert!(safe_folder(bad).is_none(), "{bad}");
    }
  }

  #[test]
  fn vault_upsert_merges_and_never_loses_files() {
    let dir = tempfile::tempdir().unwrap();
    let src = json!({ "platform": "youtube", "handle": "creator" });
    let item = |title: &str, file: &str| json!({ "id": "v1", "platform": "youtube", "kind": "video", "title": title, "tags": [], "folder": "youtube/creator/2026/x_v1", "files": [{ "role": "media", "path": file }], "hashes": {}, "backedUpAt": "2026-11-08T00:00:00Z" });
    upsert(
      dir.path(),
      src.clone(),
      vec![item("One", "media.mp4")],
      "2026-11-08T00:00:00Z",
    )
    .unwrap();
    let doc = upsert(
      dir.path(),
      src,
      vec![item("One (edited)", "thumbnail.jpg")],
      "2026-11-09T00:00:00Z",
    )
    .unwrap();
    assert_eq!(doc["items"][0]["title"], "One (edited)");
    assert_eq!(doc["items"][0]["files"].as_array().unwrap().len(), 2);
    let csv = std::fs::read_to_string(dir.path().join(INDEX)).unwrap();
    assert!(csv.contains("One (edited)"));
    // a corrupt sidecar is set aside, not overwritten
    std::fs::write(dir.path().join(SIDECAR), "{oops").unwrap();
    upsert(
      dir.path(),
      json!({ "platform": "youtube", "handle": "creator" }),
      vec![],
      "2026-11-10T00:00:00Z",
    )
    .unwrap();
    assert!(std::fs::read_dir(dir.path()).unwrap().any(|e| e
      .unwrap()
      .file_name()
      .to_str()
      .unwrap()
      .starts_with("bunniehop.json.bad-")));
  }

  #[test]
  fn vault_move_keeps_existing_files_and_describes_roles() {
    let dir = tempfile::tempdir().unwrap();
    let (tmp, dest) = (dir.path().join("tmp"), dir.path().join("vault/item"));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    for (n, c) in [
      ("media.mp4", "new"),
      ("thumbnail.jpg", "t"),
      ("captions.en.vtt", "WEBVTT"),
      ("info.info.json", "{}"),
      ("media.f137.mp4.part", "x"),
    ] {
      std::fs::write(tmp.join(n), c).unwrap();
    }
    std::fs::write(dest.join("media.mp4"), "creator's own copy").unwrap();
    let moved = move_into(&tmp, &dest).unwrap();
    assert_eq!(moved.len(), 3);
    assert_eq!(
      std::fs::read_to_string(dest.join("media.mp4")).unwrap(),
      "creator's own copy"
    );
    let files = describe(&dest).unwrap();
    let roles: Vec<_> = files.iter().map(|f| f["role"].as_str().unwrap()).collect();
    assert_eq!(roles, ["caption", "info", "media", "thumbnail"]);
    assert_eq!(files[0]["lang"], "en");
    assert_eq!(files[2]["sha256"].as_str().unwrap().len(), 64);
  }
}

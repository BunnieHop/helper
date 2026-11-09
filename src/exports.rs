//! Export zips handed over by the web app for "leave a platform" hops (PLAN §6.1, §9.1). The zip
//! is copied to the Helper's temp folder, each post's media is taken out of it into the item's
//! temp folder, and the copy is deleted when the hop ends (or at the next start).

use crate::hops::{Failure, With};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct Exports {
  dir: PathBuf,
}

/// Ids are ours (uuid); anything else is refused before it touches a path.
fn valid_id(id: &str) -> bool {
  id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

impl Exports {
  pub fn new(dir: PathBuf) -> Self {
    Self { dir }
  }

  pub fn path(&self, id: &str) -> Option<PathBuf> {
    valid_id(id)
      .then(|| self.dir.join(format!("{id}.zip")))
      .filter(|p| p.is_file())
  }

  /// A fresh file to stream an upload into; returns (id, path).
  pub fn create(&self) -> std::io::Result<(String, PathBuf)> {
    std::fs::create_dir_all(&self.dir)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let p = self.dir.join(format!("{id}.zip"));
    Ok((id, p))
  }

  pub fn remove(&self, id: &str) {
    if valid_id(id) {
      let _ = std::fs::remove_file(self.dir.join(format!("{id}.zip")));
    }
  }
}

/// Checks the upload is a readable zip.
pub fn check_zip(path: &Path) -> Result<usize, String> {
  let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
  let z = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
  Ok(z.len())
}

fn norm(p: &str) -> String {
  p.replace('\\', "/")
    .trim_start_matches("./")
    .trim_start_matches('/')
    .to_string()
}

fn ext_of(member: &str, mime: Option<&str>) -> String {
  let from_name = member
    .rsplit_once('.')
    .map(|(_, e)| e.to_ascii_lowercase())
    .filter(|e| (2..=5).contains(&e.len()) && e.chars().all(|c| c.is_ascii_alphanumeric()));
  from_name.unwrap_or_else(|| {
    match mime.unwrap_or("") {
      "video/mp4" => "mp4",
      "image/jpeg" => "jpg",
      "image/png" => "png",
      "image/gif" => "gif",
      "audio/mpeg" => "mp3",
      _ => "bin",
    }
    .into()
  })
}

/// Takes an item's `media[].path` members out of the zip into `dest` as `media.<ext>` (or
/// `media.1.<ext>`, `media.2.<ext>` … for several, in the post's order). Returns the media
/// entries that weren't in the zip, so the caller can fetch them from their `url`.
pub fn extract_media(zip_path: &Path, item: &Value, dest: &Path) -> Result<Vec<Value>, Failure> {
  let media: Vec<&Value> = item["media"]
    .as_array()
    .map(|a| a.iter().collect())
    .unwrap_or_default();
  let many = media.len() > 1;
  let f = std::fs::File::open(zip_path).map_err(|e| {
    Failure::new(
      "unknown",
      "The export copy on this computer is gone. Drop the zip again.",
    )
    .with(e)
  })?;
  let mut z = zip::ZipArchive::new(f)
    .map_err(|e| Failure::new("unknown", "The export zip can't be read.").with(e))?;
  std::fs::create_dir_all(dest)
    .map_err(|e| Failure::new("diskFull", "Couldn't make a temp folder.").with(e))?;
  let mut missing = Vec::new();
  for (i, m) in media.iter().enumerate() {
    let Some(member) = m.get("path").and_then(Value::as_str).map(norm) else {
      missing.push(((*m).clone(), i));
      continue;
    };
    let name = if many {
      format!("media.{}.{}", i + 1, ext_of(&member, m["mime"].as_str()))
    } else {
      format!("media.{}", ext_of(&member, m["mime"].as_str()))
    };
    let mut entry = match z.by_name(&member) {
      Ok(e) if e.is_file() => e,
      _ => {
        missing.push(((*m).clone(), i));
        continue;
      }
    };
    let out = dest.join(&name);
    let mut w = std::fs::File::create(&out)
      .map_err(|e| Failure::new("diskFull", "Couldn't write the media file.").with(e))?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
      let n = entry
        .read(&mut buf)
        .map_err(|e| Failure::new("unknown", "The export zip is damaged.").with(e))?;
      if n == 0 {
        break;
      }
      w.write_all(&buf[..n])
        .map_err(|e| Failure::new("diskFull", "The disk is full.").with(e))?;
    }
  }
  Ok(
    missing
      .into_iter()
      .map(|(mut m, i)| {
        m["index"] = Value::from(i);
        m["many"] = Value::from(many);
        m
      })
      .collect(),
  )
}

/// File name for a media entry fetched from its URL (same naming as `extract_media`).
pub fn fetched_name(m: &Value) -> String {
  let url = m["url"].as_str().unwrap_or("");
  let path = url.split(['?', '#']).next().unwrap_or("");
  let ext = ext_of(path.rsplit('/').next().unwrap_or(""), m["mime"].as_str());
  match (m["many"].as_bool().unwrap_or(false), m["index"].as_u64()) {
    (true, Some(i)) => format!("media.{}.{ext}", i + 1),
    _ => format!("media.{ext}"),
  }
}

#[cfg(test)]
pub mod tests {
  use super::*;
  use serde_json::json;

  pub fn make_zip(path: &Path, files: &[(&str, &[u8])]) {
    let f = std::fs::File::create(path).unwrap();
    let mut z = zip::ZipWriter::new(f);
    for (name, data) in files {
      z.start_file(*name, zip::write::SimpleFileOptions::default())
        .unwrap();
      z.write_all(data).unwrap();
    }
    z.finish().unwrap();
  }

  #[test]
  fn export_media_comes_out_of_the_zip_in_post_order() {
    let dir = tempfile::tempdir().unwrap();
    let zp = dir.path().join("x.zip");
    make_zip(
      &zp,
      &[
        ("twitter-2024/data/tweets_media/1-a.jpg", b"A"),
        ("twitter-2024/data/tweets_media/1-b.png", b"B"),
      ],
    );
    let item = json!({ "id": "1", "media": [
      { "kind": "image", "path": "twitter-2024/data/tweets_media/1-a.jpg" },
      { "kind": "image", "path": "twitter-2024/data/tweets_media/1-b.png" },
      { "kind": "image", "url": "https://pbs.twimg.com/media/c.jpg?name=orig" },
    ] });
    let out = dir.path().join("out");
    let missing = extract_media(&zp, &item, &out).unwrap();
    assert_eq!(std::fs::read(out.join("media.1.jpg")).unwrap(), b"A");
    assert_eq!(std::fs::read(out.join("media.2.png")).unwrap(), b"B");
    assert_eq!(missing.len(), 1);
    assert_eq!(fetched_name(&missing[0]), "media.3.jpg");
    assert_eq!(check_zip(&zp).unwrap(), 2);
  }

  #[test]
  fn export_ids_never_become_arbitrary_paths() {
    let dir = tempfile::tempdir().unwrap();
    let e = Exports::new(dir.path().to_path_buf());
    assert!(e.path("../../etc/passwd").is_none());
    let (id, p) = e.create().unwrap();
    std::fs::write(&p, b"z").unwrap();
    assert_eq!(e.path(&id).unwrap(), p);
    e.remove(&id);
    assert!(e.path(&id).is_none());
    assert!(check_zip(dir.path()).is_err());
  }
}

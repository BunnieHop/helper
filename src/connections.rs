//! Destination accounts on this computer (PLAN §9.3, F10). The list (platform, label, last
//! check) is a JSON file; credentials live in the OS keychain, one entry per connection, and are
//! never logged, returned over HTTP or written anywhere else (D8).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub const KEYCHAIN_SERVICE: &str = "party.bunniehop.helper";

pub trait Secrets: Send + Sync {
  fn get(&self, id: &str) -> Option<String>;
  fn set(&self, id: &str, value: &str) -> Result<(), String>;
  fn delete(&self, id: &str);
}

/// macOS Keychain, Windows Credential Manager, or the Secret Service on Linux.
pub struct Keychain;

impl Secrets for Keychain {
  fn get(&self, id: &str) -> Option<String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, id)
      .ok()?
      .get_password()
      .ok()
  }
  fn set(&self, id: &str, value: &str) -> Result<(), String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, id)
      .and_then(|e| e.set_password(value))
      .map_err(|e| e.to_string())
  }
  fn delete(&self, id: &str) {
    if let Ok(e) = keyring::Entry::new(KEYCHAIN_SERVICE, id) {
      let _ = e.delete_credential();
    }
  }
}

/// For tests.
#[derive(Default)]
pub struct MemorySecrets(Mutex<HashMap<String, String>>);

impl Secrets for MemorySecrets {
  fn get(&self, id: &str) -> Option<String> {
    self.0.lock().ok()?.get(id).cloned()
  }
  fn set(&self, id: &str, value: &str) -> Result<(), String> {
    self
      .0
      .lock()
      .map_err(|e| e.to_string())?
      .insert(id.into(), value.into());
    Ok(())
  }
  fn delete(&self, id: &str) {
    if let Ok(mut m) = self.0.lock() {
      m.remove(id);
    }
  }
}

/// What the web app sees (apps/web `Connection`). No credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
  pub id: String,
  pub platform: String,
  pub label: String,
  pub path: String,
  pub checked_at: String,
  #[serde(default, skip_serializing_if = "HashMap::is_empty")]
  pub choices: HashMap<String, String>,
  /// A hash of the platform's own id for the account (Bluesky DID, YouTube channel …): the same
  /// account reconnected gets the same value, so its posting history and queued posts carry over.
  #[serde(default, skip_serializing_if = "String::is_empty")]
  pub account: String,
}

/// The stable account key for `c` with its `secret`. Built from the platform's own account id
/// where the sign-in returns one, else the label. Hashed: no ids or secrets in the key.
pub fn account_key(platform: &str, label: &str, secret: &Value) -> String {
  let field = |k: &str| {
    secret
      .get(k)
      .and_then(Value::as_str)
      .filter(|v| !v.is_empty())
  };
  let stable = match platform {
    "bluesky" => field("did").or(field("identifier")),
    "youtube" => field("channelId"),
    "linkedin" => field("author"),
    "facebook" => field("pageId"),
    "threads" | "instagram" | "pinterest" => field("userId"),
    "tiktok" => field("openId"),
    "tumblr" => field("blogId"),
    "telegram" => field("channelId"),
    "ghost" | "wordpress" => field("url"),
    "discord" => field("url"),
    "mastodon" | "peertube" => None,
    _ => None,
  };
  let raw = match stable {
    Some(v) => format!("{platform}|id|{v}"),
    None => format!("{platform}|label|{label}"),
  };
  crate::sigv4::sha256_hex(raw.as_bytes())[..20].to_string()
}

pub struct Store {
  pub telegram: crate::connect::TelegramSignIns,
  file: PathBuf,
  secrets: Box<dyn Secrets>,
  list: Mutex<Vec<Connection>>,
}

impl Store {
  pub fn open(file: PathBuf, secrets: Box<dyn Secrets>) -> Self {
    let mut list: Vec<Connection> = std::fs::read_to_string(&file)
      .ok()
      .and_then(|s| serde_json::from_str(&s).ok())
      .unwrap_or_default();
    for c in list.iter_mut().filter(|c| c.account.is_empty()) {
      // saved before accounts were keyed: the secret decides when it carries the account id
      let secret = secrets
        .get(&c.id)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
      c.account = account_key(&c.platform, &c.label, &secret);
    }
    Self {
      telegram: Default::default(),
      file,
      secrets,
      list: Mutex::new(list),
    }
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Connection>> {
    self.list.lock().unwrap_or_else(|e| e.into_inner())
  }

  pub fn list(&self) -> Vec<Connection> {
    self.lock().clone()
  }

  pub fn get(&self, id: &str) -> Option<Connection> {
    self.lock().iter().find(|c| c.id == id).cloned()
  }

  /// The connection with this id on this platform. Never another account on the same platform:
  /// a post on the wrong account can't be undone, so a missing one fails as signed out.
  pub fn find(&self, platform: &str, id: &str) -> Option<Connection> {
    self
      .lock()
      .iter()
      .find(|c| c.id == id && c.platform == platform)
      .cloned()
  }

  pub fn secret(&self, id: &str) -> Option<Value> {
    serde_json::from_str(&self.secrets.get(id)?).ok()
  }

  pub fn set_secret(&self, id: &str, v: &Value) -> Result<(), String> {
    self.secrets.set(id, &v.to_string())
  }

  /// Adds or replaces. The same account (same platform + account key, or same label) keeps its
  /// connection id, so reconnecting doesn't duplicate it or break queued hops.
  pub fn save(&self, mut c: Connection, secret: &Value) -> Result<Connection, String> {
    c.account = account_key(&c.platform, &c.label, secret);
    let mut l = self.lock();
    let label_key = account_key(&c.platform, &c.label, &Value::Null);
    if let Some(prev) = l.iter().find(|p| {
      p.platform == c.platform
        && (p.account == c.account
          || (p.label == c.label && (p.account == label_key || c.account == label_key)))
    }) {
      c.id = prev.id.clone();
    }
    self.secrets.set(&c.id, &secret.to_string())?;
    l.retain(|p| p.id != c.id);
    l.push(c.clone());
    self.write(&l);
    Ok(c)
  }

  pub fn touch(&self, id: &str, checked_at: &str) {
    let mut l = self.lock();
    if let Some(c) = l.iter_mut().find(|c| c.id == id) {
      c.checked_at = checked_at.into();
    }
    self.write(&l);
  }

  pub fn remove(&self, id: &str) -> bool {
    let mut l = self.lock();
    let before = l.len();
    l.retain(|c| c.id != id);
    self.secrets.delete(id);
    self.write(&l);
    l.len() != before
  }

  fn write(&self, l: &[Connection]) {
    if let Ok(s) = serde_json::to_string_pretty(l) {
      if crate::vault::write_atomic(&self.file, s.as_bytes()).is_ok() {
        let _ = crate::config::restrict(&self.file);
      }
    }
  }
}

pub fn new_id(platform: &str) -> String {
  format!(
    "{platform}-{}",
    &uuid::Uuid::new_v4().simple().to_string()[..12]
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  /// The browser engine keys its ledger the same way (apps/web engine-site/accounts.ts), so the
  /// two ledgers merge (D-082). Fixture shared in packages/sidecar/fixtures/cross.
  #[test]
  fn account_key_matches_the_browser_engine() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mono = root.join("../../packages/sidecar/fixtures/cross");
    let dir = if mono.is_dir() {
      mono
    } else {
      root.join("fixtures/sidecar-cross")
    };
    let fx: Value =
      serde_json::from_str(&std::fs::read_to_string(dir.join("accounts.json")).unwrap()).unwrap();
    for row in fx["accounts"].as_array().unwrap() {
      let platform = row["platform"].as_str().unwrap();
      let field = match platform {
        "youtube" => "channelId",
        "bluesky" => "did",
        _ => "url",
      };
      let secret = match row["stable"].as_str() {
        Some(v) => json!({ field: v }),
        None => json!({}),
      };
      assert_eq!(
        account_key(platform, row["label"].as_str().unwrap(), &secret),
        row["account"].as_str().unwrap(),
        "{platform} {}",
        row["label"]
      );
    }
  }

  #[test]
  fn connections_keep_secrets_out_of_the_list_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("connections.json");
    let s = Store::open(file.clone(), Box::new(MemorySecrets::default()));
    let c = Connection {
      id: new_id("bluesky"),
      platform: "bluesky".into(),
      label: "@mara.bsky.social".into(),
      path: "api".into(),
      checked_at: "2026-11-08T00:00:00Z".into(),
      choices: HashMap::new(),
      account: String::new(),
    };
    let saved = s
      .save(c.clone(), &json!({ "appPassword": "abcd-efgh-ijkl-mnop" }))
      .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
      !text.contains("abcd-efgh"),
      "no credential in the list file"
    );
    assert_eq!(
      s.secret(&saved.id).unwrap()["appPassword"],
      "abcd-efgh-ijkl-mnop"
    );
    // reconnecting the same account keeps one entry
    let again = s
      .save(
        Connection {
          id: new_id("bluesky"),
          ..c
        },
        &json!({ "appPassword": "new" }),
      )
      .unwrap();
    assert_eq!(again.id, saved.id);
    assert_eq!(s.list().len(), 1);
    assert!(s.remove(&saved.id));
    assert!(s.secret(&saved.id).is_none());
    assert!(s.list().is_empty());
  }

  #[test]
  fn find_never_falls_back_to_another_account() {
    let dir = tempfile::tempdir().unwrap();
    let st = Store::open(
      dir.path().join("c.json"),
      Box::new(MemorySecrets::default()),
    );
    let b = st
      .save(
        Connection {
          id: "youtube-b".into(),
          platform: "youtube".into(),
          label: "Channel B".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: HashMap::new(),
          account: String::new(),
        },
        &json!({ "channelId": "UCb" }),
      )
      .unwrap();
    assert_eq!(st.find("youtube", &b.id).unwrap().label, "Channel B");
    // the hop was planned for channel A, which was disconnected
    assert!(st.find("youtube", "youtube-a").is_none());
    assert!(st.find("youtube", "youtube").is_none());
    assert!(st.find("mastodon", &b.id).is_none());
  }

  #[test]
  fn reconnecting_the_same_account_keeps_its_connection_id() {
    let dir = tempfile::tempdir().unwrap();
    let st = Store::open(
      dir.path().join("c.json"),
      Box::new(MemorySecrets::default()),
    );
    let c = |label: &str| Connection {
      id: new_id("bluesky"),
      platform: "bluesky".into(),
      label: label.into(),
      path: "api".into(),
      checked_at: "t".into(),
      choices: HashMap::new(),
      account: String::new(),
    };
    let a = st
      .save(c("@mara.test"), &json!({ "did": "did:plc:mara" }))
      .unwrap();
    // the handle changed, the DID didn't: same account, same id
    let b = st
      .save(c("@mara.example"), &json!({ "did": "did:plc:mara" }))
      .unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(st.list().len(), 1);
    let other = st
      .save(c("@sam.test"), &json!({ "did": "did:plc:sam" }))
      .unwrap();
    assert_ne!(other.account, a.account);
    assert!(!a.account.contains("mara"), "hashed, no ids in the key");
  }

  #[test]
  fn renamed_page_blog_or_channel_keeps_duplicate_post_history() {
    for (platform, field) in [
      ("facebook", "pageId"),
      ("threads", "userId"),
      ("instagram", "userId"),
      ("pinterest", "userId"),
      ("tiktok", "openId"),
      ("tumblr", "blogId"),
      ("telegram", "channelId"),
    ] {
      let dir = tempfile::tempdir().unwrap();
      let st = Store::open(
        dir.path().join("connections.json"),
        Box::new(MemorySecrets::default()),
      );
      let conn = |label: &str| Connection {
        id: new_id(platform),
        platform: platform.into(),
        label: label.into(),
        path: "api".into(),
        checked_at: "t".into(),
        choices: HashMap::new(),
        account: String::new(),
      };
      let secret = json!({field:"account-1","accessToken":"secret"});
      let first = st.save(conn("Old name"), &secret).unwrap();
      let ledger = crate::posted::Posted::open(dir.path().join("posted.json"));
      let key = |c: &Connection| format!("{platform}|{}|source|item-1", c.account);
      assert!(matches!(
        ledger.reserve(&key(&first), "t"),
        crate::posted::Seen::Clear
      ));
      ledger.finish(
        &key(&first),
        Some(json!({"state":"published","destItemId":"post-1"})),
      );
      let renamed = st.save(conn("New name"), &secret).unwrap();
      assert_eq!(first.id, renamed.id, "{platform}");
      assert_eq!(
        ledger.posted(&key(&renamed)).unwrap()["destItemId"],
        "post-1"
      );
      let other = st
        .save(conn("New name"), &json!({field:"account-2"}))
        .unwrap();
      assert_ne!(
        other.id, renamed.id,
        "different {platform} targets may share a name"
      );
      assert!(ledger.posted(&key(&other)).is_none());
    }
  }
}

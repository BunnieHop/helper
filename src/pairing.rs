//! Browser pairing (docs/helper-api.md). A 6-digit code shown by the Helper is exchanged for a
//! random token; only `sha256(token)` is kept on disk.

use crate::config::restrict;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

pub const CODE_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_ATTEMPTS: u8 = 5;
/// A second start this soon returns the code already showing instead of a new one.
pub const RESTART_GAP: Duration = Duration::from_secs(30);
/// New codes and wrong codes allowed per rolling hour, across codes (bottom-up review S5).
pub const HOURLY_STARTS: usize = 10;
pub const HOURLY_WRONG: usize = 10;
const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
  NotStarted,
  Expired,
  Wrong {
    left: u8,
  },
  TooManyAttempts,
  /// Too many codes or wrong tries this hour; try again in this many minutes.
  Limited {
    minutes: u64,
  },
  Storage,
}

impl PairError {
  pub fn message(&self) -> String {
    match self {
      PairError::NotStarted => "Start pairing again; no code is waiting.".into(),
      PairError::Expired => "That code expired. Start pairing again for a new one.".into(),
      PairError::Wrong { left } => format!("That code doesn't match. {left} tries left."),
      PairError::TooManyAttempts => {
        "Too many wrong codes. Start pairing again for a new one.".into()
      }
      PairError::Limited { minutes } => format!(
        "Pairing is paused after too many tries. Try again in {minutes} minute{}.",
        if *minutes == 1 { "" } else { "s" }
      ),
      PairError::Storage => {
        "The Helper couldn't save the pairing. Check disk space and permissions.".into()
      }
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paired {
  pub hash: String,
  pub label: String,
  pub created_at: u64,
}

struct Pending {
  code: String,
  expires: SystemTime,
  attempts: u8,
}

struct State {
  pending: Option<Pending>,
  paired: Vec<Paired>,
  /// When codes were issued and wrong codes typed, within the last hour.
  starts: Vec<SystemTime>,
  wrong: Vec<SystemTime>,
}

impl State {
  fn prune(&mut self, now: SystemTime) {
    let recent = |t: &SystemTime| now.duration_since(*t).map(|d| d < HOUR).unwrap_or(true);
    self.starts.retain(recent);
    self.wrong.retain(recent);
  }

  /// `Limited` when this hour's allowance is used up.
  fn allowance(&self, now: SystemTime) -> Result<(), PairError> {
    let full = |v: &[SystemTime], cap: usize| v.len() >= cap;
    if !full(&self.starts, HOURLY_STARTS) && !full(&self.wrong, HOURLY_WRONG) {
      return Ok(());
    }
    // the allowance frees up when the oldest entry that keeps it full turns an hour old
    let oldest = [&self.starts, &self.wrong]
      .iter()
      .zip([HOURLY_STARTS, HOURLY_WRONG])
      .filter(|(v, cap)| full(v, *cap))
      .filter_map(|(v, cap)| v.get(v.len() - cap).copied())
      .max()
      .unwrap_or(now);
    let left = (oldest + HOUR).duration_since(now).unwrap_or_default();
    Err(PairError::Limited {
      minutes: left.as_secs().div_ceil(60).max(1),
    })
  }
}

pub struct Pairing {
  file: PathBuf,
  state: Mutex<State>,
  /// Injected so tests control the code and the clock.
  code_source: Box<dyn Fn() -> String + Send + Sync>,
  now: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

pub fn hash_token(token: &str) -> String {
  hex::encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time equality for equal-length hex digests.
fn same(a: &str, b: &str) -> bool {
  a.len() == b.len()
    && a
      .bytes()
      .zip(b.bytes())
      .fold(0u8, |acc, (x, y)| acc | (x ^ y))
      == 0
}

fn random_code() -> String {
  let n: u32 = rand::random_range(0..1_000_000);
  format!("{n:06}")
}

impl Pairing {
  pub fn open(file: PathBuf) -> Self {
    Self::with(file, Box::new(random_code), Box::new(SystemTime::now))
  }

  pub fn with(
    file: PathBuf,
    code_source: Box<dyn Fn() -> String + Send + Sync>,
    now: Box<dyn Fn() -> SystemTime + Send + Sync>,
  ) -> Self {
    let paired = std::fs::read(&file)
      .ok()
      .and_then(|b| serde_json::from_slice::<Vec<Paired>>(&b).ok())
      .unwrap_or_default();
    Self {
      file,
      state: Mutex::new(State {
        pending: None,
        paired,
        starts: Vec::new(),
        wrong: Vec::new(),
      }),
      code_source,
      now,
    }
  }

  /// Starts (or restarts) pairing. Returns the code to show the creator and when it expires.
  /// A restart within 30 seconds keeps the code already showing; at most 10 new codes an hour.
  pub fn start(&self) -> Result<(String, SystemTime), PairError> {
    let now = (self.now)();
    let mut s = self.state.lock().expect("pairing lock");
    s.prune(now);
    s.allowance(now)?;
    if let (Some(p), Some(last)) = (&s.pending, s.starts.last()) {
      let soon = now
        .duration_since(*last)
        .map(|d| d < RESTART_GAP)
        .unwrap_or(true);
      if soon && p.expires > now {
        return Ok((p.code.clone(), p.expires));
      }
    }
    let code = (self.code_source)();
    let expires = now + CODE_TTL;
    s.starts.push(now);
    s.pending = Some(Pending {
      code: code.clone(),
      expires,
      attempts: 0,
    });
    Ok((code, expires))
  }

  /// The code waiting to be typed, while it is still valid (shown on the Helper's own page).
  pub fn pending_code(&self) -> Option<String> {
    let s = self.state.lock().expect("pairing lock");
    s.pending
      .as_ref()
      .filter(|p| p.expires > (self.now)())
      .map(|p| p.code.clone())
  }

  pub fn finish(&self, code: &str, label: &str) -> Result<String, PairError> {
    let now = (self.now)();
    let mut s = self.state.lock().expect("pairing lock");
    s.prune(now);
    if s.wrong.len() >= HOURLY_WRONG {
      s.pending = None;
      return Err(s.allowance(now).err().unwrap_or(PairError::TooManyAttempts));
    }
    let p = s.pending.as_mut().ok_or(PairError::NotStarted)?;
    if now > p.expires {
      s.pending = None;
      return Err(PairError::Expired);
    }
    if !same(&hash_token(code.trim()), &hash_token(&p.code)) {
      p.attempts += 1;
      let attempts = p.attempts;
      s.wrong.push(now);
      if attempts >= MAX_ATTEMPTS || s.wrong.len() >= HOURLY_WRONG {
        s.pending = None;
        return Err(PairError::TooManyAttempts);
      }
      return Err(PairError::Wrong {
        left: (MAX_ATTEMPTS - attempts).min((HOURLY_WRONG - s.wrong.len()) as u8),
      });
    }
    s.pending = None;
    let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let created_at = (self.now)()
      .duration_since(SystemTime::UNIX_EPOCH)
      .map(|d| d.as_secs())
      .unwrap_or(0);
    let label: String = label.chars().take(80).collect();
    s.paired.push(Paired {
      hash: hash_token(&token),
      label,
      created_at,
    });
    self.save(&s.paired).map_err(|_| PairError::Storage)?;
    Ok(token)
  }

  pub fn verify(&self, token: &str) -> bool {
    let h = hash_token(token);
    let s = self.state.lock().expect("pairing lock");
    s.paired.iter().any(|p| same(&p.hash, &h))
  }

  pub fn unpair(&self, token: &str) -> bool {
    let h = hash_token(token);
    let mut s = self.state.lock().expect("pairing lock");
    let before = s.paired.len();
    s.paired.retain(|p| !same(&p.hash, &h));
    let changed = s.paired.len() != before;
    if changed {
      let _ = self.save(&s.paired);
    }
    changed
  }

  pub fn paired(&self) -> Vec<Paired> {
    self.state.lock().expect("pairing lock").paired.clone()
  }

  fn save(&self, paired: &[Paired]) -> std::io::Result<()> {
    if let Some(dir) = self.file.parent() {
      std::fs::create_dir_all(dir)?;
    }
    let tmp = self.file.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(paired)?)?;
    restrict(&tmp)?;
    std::fs::rename(&tmp, &self.file)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::sync::Arc;

  fn fixture(dir: &std::path::Path) -> (Pairing, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000));
    let c = clock.clone();
    let p = Pairing::with(
      dir.join("pairings.json"),
      Box::new(|| "123456".into()),
      Box::new(move || SystemTime::UNIX_EPOCH + Duration::from_secs(c.load(Ordering::SeqCst))),
    );
    (p, clock)
  }

  #[test]
  fn pairing_code_exchanges_for_a_token_and_only_its_hash_is_stored() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = fixture(dir.path());
    p.start().unwrap();
    let token = p.finish(" 123456 ", "Chrome on Mac").unwrap();
    assert!(p.verify(&token));
    assert!(!p.verify("nope"));
    let disk = std::fs::read_to_string(dir.path().join("pairings.json")).unwrap();
    assert!(!disk.contains(&token));
    assert!(disk.contains(&hash_token(&token)));
    // survives a restart
    let (again, _) = fixture(dir.path());
    assert!(again.verify(&token));
  }

  #[test]
  fn pairing_code_expires_after_five_minutes() {
    let dir = tempfile::tempdir().unwrap();
    let (p, clock) = fixture(dir.path());
    p.start().unwrap();
    clock.fetch_add(301, Ordering::SeqCst);
    assert_eq!(p.finish("123456", ""), Err(PairError::Expired));
    assert_eq!(p.finish("123456", ""), Err(PairError::NotStarted));
  }

  #[test]
  fn pairing_five_wrong_codes_cancel_the_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = fixture(dir.path());
    p.start().unwrap();
    for left in (1..MAX_ATTEMPTS).rev() {
      assert_eq!(p.finish("000000", ""), Err(PairError::Wrong { left }));
    }
    assert_eq!(p.finish("000000", ""), Err(PairError::TooManyAttempts));
    assert_eq!(p.finish("123456", ""), Err(PairError::NotStarted));
  }

  #[test]
  fn pairing_unpair_forgets_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = fixture(dir.path());
    p.start().unwrap();
    let t = p.finish("123456", "").unwrap();
    assert!(p.unpair(&t));
    assert!(!p.verify(&t));
    assert!(!p.unpair(&t));
  }

  #[test]
  fn pairing_start_is_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let n = Arc::new(AtomicU64::new(0));
    let (n2, clock) = (n.clone(), Arc::new(AtomicU64::new(1_000)));
    let c = clock.clone();
    let p = Pairing::with(
      dir.path().join("pairings.json"),
      Box::new(move || format!("{:06}", n2.fetch_add(1, Ordering::SeqCst))),
      Box::new(move || SystemTime::UNIX_EPOCH + Duration::from_secs(c.load(Ordering::SeqCst))),
    );
    let (first, _) = p.start().unwrap();
    clock.fetch_add(29, Ordering::SeqCst);
    assert_eq!(
      p.start().unwrap().0,
      first,
      "a quick second start keeps the same code"
    );
    for _ in 1..HOURLY_STARTS {
      clock.fetch_add(31, Ordering::SeqCst);
      assert_ne!(p.start().unwrap().0, first);
    }
    clock.fetch_add(31, Ordering::SeqCst);
    assert!(matches!(p.start(), Err(PairError::Limited { .. })));
    // an hour after the first start, one more code is allowed
    clock.store(1_000 + 3_600, Ordering::SeqCst);
    assert!(p.start().is_ok());
  }

  #[test]
  fn pairing_wrong_codes_count_across_new_codes() {
    let dir = tempfile::tempdir().unwrap();
    let (p, clock) = fixture(dir.path());
    // two codes, four wrong tries each: under the per-code limit, at the hourly one after 10
    for _ in 0..2 {
      p.start().unwrap();
      for _ in 0..4 {
        assert!(matches!(
          p.finish("000000", ""),
          Err(PairError::Wrong { .. })
        ));
      }
      clock.fetch_add(31, Ordering::SeqCst);
    }
    p.start().unwrap();
    assert!(matches!(
      p.finish("000000", ""),
      Err(PairError::Wrong { left: 1 })
    ));
    assert_eq!(p.finish("000000", ""), Err(PairError::TooManyAttempts));
    assert!(matches!(p.start(), Err(PairError::Limited { minutes: 59 })));
    assert!(matches!(
      p.finish("123456", ""),
      Err(PairError::Limited { .. })
    ));
    clock.fetch_add(3_600, Ordering::SeqCst);
    p.start().unwrap();
    assert!(p.finish("123456", "").is_ok());
  }

  #[test]
  fn pairing_random_codes_are_six_digits() {
    for _ in 0..100 {
      let c = random_code();
      assert_eq!(c.len(), 6);
      assert!(c.chars().all(|ch| ch.is_ascii_digit()));
    }
  }
}

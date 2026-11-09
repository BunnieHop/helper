//! Human pace and daily caps (F8, PLAN §5.3). The web app sends each destination's pace (from
//! packages/limits) in the hop plan; the Helper enforces it per destination account and keeps the
//! count of posts made today on disk, so a restart or a second hop never resets "N left today".

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

const MIN_MS: i64 = 60_000;
const DAY_MS: i64 = 24 * 60 * MIN_MS;

#[derive(Debug, Clone, PartialEq)]
pub struct Pace {
  pub min_gap_ms: i64,
  pub jitter_ms: (i64, i64),
  /// Posts per local calendar day; `None` = only the platform's API limits.
  pub cap: Option<u32>,
  pub utc_offset_min: i64,
  /// Local posting window `[start, end)` in hours; `None` = any time.
  pub hours: Option<(i64, i64)>,
}

impl Pace {
  /// From `destination.options.pace` and `plan.pace`. Missing values use the API defaults in
  /// packages/limits/pacing.json (20 s gap, 5–40 s jitter, no cap).
  pub fn from_plan(dest_options: &Value, plan_pace: Option<&Value>) -> Self {
    let p = dest_options.get("pace").cloned().unwrap_or(Value::Null);
    let num = |v: &Value, k: &str| v.get(k).and_then(Value::as_f64);
    let jitter = p
      .get("jitterSec")
      .and_then(Value::as_array)
      .and_then(|a| Some((a.first()?.as_f64()?, a.get(1)?.as_f64()?)))
      .unwrap_or((5.0, 40.0));
    let ms = |s: f64| (s.max(0.0) * 1000.0) as i64;
    let cap = num(&p, "dailyCap")
      .or_else(|| num(dest_options, "dailyCap"))
      .filter(|c| *c >= 1.0)
      .map(|c| c as u32);
    let spread = plan_pace
      .and_then(|v| v.get("spread"))
      .and_then(Value::as_bool)
      .unwrap_or(false);
    let hours = plan_pace
      .filter(|_| spread)
      .and_then(|v| v.get("postingHours"))
      .and_then(Value::as_array)
      .and_then(|a| Some((a.first()?.as_i64()?, a.get(1)?.as_i64()?)))
      .filter(|(a, b)| (0..24).contains(a) && (1..=24).contains(b) && a < b);
    let (j0, j1) = (ms(jitter.0), ms(jitter.1));
    Self {
      min_gap_ms: ms(num(&p, "minGapSec").unwrap_or(20.0)),
      jitter_ms: (j0.min(j1), j0.max(j1)),
      cap,
      utc_offset_min: num(&p, "utcOffsetMin")
        .map(|o| o.clamp(-14.0 * 60.0, 14.0 * 60.0) as i64)
        .unwrap_or(0),
      hours,
    }
  }

  fn local_day(&self, t: i64) -> i64 {
    (t + self.utc_offset_min * MIN_MS).div_euclid(DAY_MS)
  }

  fn day_start(&self, day: i64) -> i64 {
    day * DAY_MS - self.utc_offset_min * MIN_MS
  }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Usage {
  /// Local day number (days since 1970-01-01 in the creator's zone).
  pub day: i64,
  /// Posts published on `day`.
  pub count: u32,
  /// Unix ms of the last post attempt.
  pub last: i64,
}

/// The earliest time (unix ms) the next post may go out. `jitter` is one draw from
/// `pace.jitter_ms`, chosen by the caller so tests are deterministic.
pub fn next_slot(pace: &Pace, usage: Option<&Usage>, now: i64, jitter: i64) -> i64 {
  let mut t = match usage {
    Some(u) if u.last > 0 => now.max(u.last + pace.min_gap_ms + jitter),
    _ => now,
  };
  // Bounded: at most a year of days (a cap of 0 is rejected in `from_plan`).
  for _ in 0..366 {
    let day = pace.local_day(t);
    let used = usage.filter(|u| u.day == day).map_or(0, |u| u.count);
    let next_day = pace.day_start(day + 1);
    if pace.cap.is_some_and(|c| used >= c) {
      t = next_day + pace.hours.map_or(0, |h| h.0 * 60 * MIN_MS) + jitter;
      continue;
    }
    if let Some((start, end)) = pace.hours {
      let ws = pace.day_start(day) + start * 60 * MIN_MS;
      let we = pace.day_start(day) + end * 60 * MIN_MS;
      if t < ws {
        t = ws + jitter;
      } else if t >= we {
        t = next_day + start * 60 * MIN_MS + jitter;
        continue;
      }
    }
    return t;
  }
  t
}

/// Per destination account (`platform:connectionId`), on disk.
pub struct Ledger {
  file: PathBuf,
  map: Mutex<HashMap<String, Usage>>,
}

impl Ledger {
  pub fn open(file: PathBuf) -> Self {
    let map = std::fs::read_to_string(&file)
      .ok()
      .and_then(|s| serde_json::from_str(&s).ok())
      .unwrap_or_default();
    Self {
      file,
      map: Mutex::new(map),
    }
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Usage>> {
    self.map.lock().unwrap_or_else(|e| e.into_inner())
  }

  pub fn get(&self, key: &str) -> Option<Usage> {
    self.lock().get(key).cloned()
  }

  pub fn slot(&self, key: &str, pace: &Pace, now: i64) -> i64 {
    let (a, b) = pace.jitter_ms;
    let jitter = if b > a { rand::random_range(a..=b) } else { a };
    next_slot(pace, self.get(key).as_ref(), now, jitter)
  }

  /// A post attempt at `at`; `published` counts it toward today's cap.
  pub fn record(&self, key: &str, pace: &Pace, at: i64, published: bool) {
    let mut m = self.lock();
    let day = pace.local_day(at);
    let u = m.entry(key.to_string()).or_default();
    if u.day != day {
      u.day = day;
      u.count = 0;
    }
    if published {
      u.count += 1;
    }
    u.last = at;
    if let Ok(s) = serde_json::to_string_pretty(&*m) {
      let _ = crate::vault::write_atomic(&self.file, s.as_bytes());
    }
  }
}

pub fn now_ms() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_millis() as i64)
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  // 2026-11-08T00:00:00Z
  const T0: i64 = 1_794_096_000_000;
  const H: i64 = 60 * MIN_MS;

  fn pace(cap: Option<u32>, hours: Option<(i64, i64)>, off: i64) -> Pace {
    Pace {
      min_gap_ms: 30_000,
      jitter_ms: (0, 0),
      cap,
      utc_offset_min: off,
      hours,
    }
  }

  #[test]
  fn pacing_reads_the_plan_and_falls_back_to_api_defaults() {
    let p = Pace::from_plan(
      &json!({ "pace": { "minGapSec": 600, "jitterSec": [60, 900], "dailyCap": 15, "utcOffsetMin": -300 } }),
      Some(&json!({ "spread": true, "postingHours": [9, 21] })),
    );
    assert_eq!(p.min_gap_ms, 600_000);
    assert_eq!(p.jitter_ms, (60_000, 900_000));
    assert_eq!(p.cap, Some(15));
    assert_eq!(p.utc_offset_min, -300);
    assert_eq!(p.hours, Some((9, 21)));
    let d = Pace::from_plan(&json!({}), None);
    assert_eq!(
      (d.min_gap_ms, d.jitter_ms, d.cap, d.hours),
      (20_000, (5_000, 40_000), None, None)
    );
    // spread off = post any time; a cap of 0 is ignored rather than blocking forever
    let off = Pace::from_plan(
      &json!({ "pace": { "dailyCap": 0 } }),
      Some(&json!({ "spread": false, "postingHours": [9, 21] })),
    );
    assert_eq!((off.cap, off.hours), (None, None));
  }

  #[test]
  fn pacing_keeps_the_gap_between_posts() {
    let p = pace(None, None, 0);
    assert_eq!(next_slot(&p, None, T0, 0), T0);
    let u = Usage {
      day: 0,
      count: 0,
      last: T0,
    };
    assert_eq!(next_slot(&p, Some(&u), T0 + 1_000, 5_000), T0 + 35_000);
    assert_eq!(next_slot(&p, Some(&u), T0 + 60_000, 5_000), T0 + 60_000);
  }

  #[test]
  fn pacing_cap_rolls_to_the_next_local_day() {
    // UTC−5: local midnight is 05:00Z
    let p = pace(Some(2), None, -300);
    let day = p.local_day(T0 + 12 * H);
    let u = Usage {
      day,
      count: 2,
      last: T0 + 12 * H,
    };
    assert_eq!(
      next_slot(&p, Some(&u), T0 + 12 * H + MIN_MS, 0),
      T0 + 29 * H
    );
    // yesterday's count doesn't block today
    let old = Usage { day: day - 1, ..u };
    assert_eq!(
      next_slot(&p, Some(&old), T0 + 12 * H + MIN_MS, 0),
      T0 + 12 * H + MIN_MS
    );
  }

  #[test]
  fn pacing_waits_for_posting_hours() {
    let p = pace(Some(5), Some((9, 21)), 0);
    // 03:00 → 09:00 same day
    assert_eq!(next_slot(&p, None, T0 + 3 * H, 0), T0 + 9 * H);
    // 22:00 → 09:00 next day
    assert_eq!(next_slot(&p, None, T0 + 22 * H, 0), T0 + 33 * H);
    // in the window → now
    assert_eq!(next_slot(&p, None, T0 + 10 * H, 0), T0 + 10 * H);
    // cap hit → next day's window start
    let u = Usage {
      day: p.local_day(T0),
      count: 5,
      last: T0 + 10 * H,
    };
    assert_eq!(next_slot(&p, Some(&u), T0 + 11 * H, 0), T0 + 33 * H);
  }

  #[test]
  fn pacing_ledger_counts_published_posts_and_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("usage.json");
    let p = pace(Some(1), None, 0);
    let l = Ledger::open(f.clone());
    l.record("bluesky:a", &p, T0 + H, false);
    assert_eq!(
      l.get("bluesky:a").unwrap().count,
      0,
      "a failure isn't a post"
    );
    l.record("bluesky:a", &p, T0 + 2 * H, true);
    let again = Ledger::open(f);
    let u = again.get("bluesky:a").unwrap();
    assert_eq!((u.count, u.last), (1, T0 + 2 * H));
    assert_eq!(again.slot("bluesky:a", &p, T0 + 3 * H), T0 + 24 * H);
    // a new day resets the count
    again.record("bluesky:a", &p, T0 + 25 * H, true);
    assert_eq!(again.get("bluesky:a").unwrap().count, 1);
  }
}

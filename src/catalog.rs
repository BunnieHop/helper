//! Catalog listing (PLAN §7.1): flat yt-dlp windows of ≤200 items, mapped to `CatalogItem`
//! (packages/protocol catalog.ts). A YouTube channel root is listed tab by tab (Videos, Shorts,
//! Live) so nested tabs never collapse into one ambiguous list; Shorts are de-duplicated.

use serde_json::{json, Map, Value};

pub const PAGE: u32 = 200;

/// Where the next window starts: which tab (for YouTube channels) and the 1-based offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
  pub tab: usize,
  pub start: u32,
}

impl Cursor {
  pub fn parse(s: Option<&str>) -> Cursor {
    s.and_then(|s| {
      let (t, o) = s.split_once(':')?;
      Some(Cursor {
        tab: t.parse().ok()?,
        start: o.parse::<u32>().ok()?.max(1),
      })
    })
    .unwrap_or(Cursor { tab: 0, start: 1 })
  }
  pub fn encode(&self) -> String {
    format!("{}:{}", self.tab, self.start)
  }
}

/// The URLs to list, in order. YouTube channel roots expand to their tabs.
pub fn tabs(url: &str) -> Vec<(String, Option<&'static str>)> {
  let u = url.trim().trim_end_matches('/');
  let yt_channel = (u.contains("youtube.com/@")
    || u.contains("youtube.com/channel/")
    || u.contains("youtube.com/c/"))
    && !["/videos", "/shorts", "/streams", "/playlists", "/watch"]
      .iter()
      .any(|t| u.contains(t));
  if yt_channel {
    let base = u.split(['?', '#']).next().unwrap_or(u);
    vec![
      (format!("{base}/videos"), Some("videos")),
      (format!("{base}/shorts"), Some("shorts")),
      (format!("{base}/streams"), Some("streams")),
    ]
  } else {
    vec![(u.to_string(), None)]
  }
}

pub fn platform_of(url: &str, extractor: Option<&str>) -> String {
  let host = url
    .split("://")
    .nth(1)
    .and_then(|r| r.split('/').next())
    .unwrap_or("")
    .trim_start_matches("www.")
    .trim_start_matches("m.");
  let known = [
    ("youtube.com", "youtube"),
    ("youtu.be", "youtube"),
    ("tiktok.com", "tiktok"),
    ("instagram.com", "instagram"),
    ("vimeo.com", "vimeo"),
    ("dailymotion.com", "dailymotion"),
    ("rumble.com", "rumble"),
    ("odysee.com", "odysee"),
    ("twitch.tv", "twitch"),
    ("x.com", "x"),
    ("twitter.com", "x"),
    ("facebook.com", "facebook"),
    ("soundcloud.com", "soundcloud"),
  ];
  if let Some((_, p)) = known
    .iter()
    .find(|(h, _)| host == *h || host.ends_with(&format!(".{h}")))
  {
    return p.to_string();
  }
  let e = extractor.unwrap_or("web").to_ascii_lowercase();
  let slug: String = e
    .chars()
    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
    .collect();
  slug
    .trim_matches('-')
    .split('-')
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("-")
}

fn iso_from_ts(ts: f64) -> Option<String> {
  time::OffsetDateTime::from_unix_timestamp(ts as i64)
    .ok()?
    .format(&time::format_description::well_known::Rfc3339)
    .ok()
}

/// `YYYYMMDD` → midnight UTC ISO.
fn iso_from_date(d: &str) -> Option<String> {
  (d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()))
    .then(|| format!("{}-{}-{}T00:00:00Z", &d[..4], &d[4..6], &d[6..8]))
}

/// One flat entry → `CatalogItem` JSON. `None` for entries that aren't items (nested playlists).
pub fn map_entry(e: &Value, tab: Option<&str>, fallback_platform: &str) -> Option<Value> {
  let s = |k: &str| e.get(k).and_then(Value::as_str);
  let n = |k: &str| {
    e.get(k)
      .and_then(Value::as_f64)
      .filter(|v| v.is_finite() && *v >= 0.0)
  };
  let id = s("id")?;
  if s("_type") == Some("playlist") || s("ie_key").is_some_and(|k| k.ends_with("Tab")) {
    return None;
  }
  let url = s("webpage_url")
    .or(s("url"))
    .map(str::to_string)
    .filter(|u| u.starts_with("http"));
  let url = url.or_else(|| {
    (fallback_platform == "youtube").then(|| format!("https://www.youtube.com/watch?v={id}"))
  });
  let platform = url
    .as_deref()
    .map(|u| platform_of(u, s("ie_key")))
    .unwrap_or_else(|| fallback_platform.to_string());
  let is_short = tab == Some("shorts") || url.as_deref().is_some_and(|u| u.contains("/shorts/"));
  let live = s("live_status");
  let mut item = Map::new();
  item.insert("id".into(), json!(id));
  item.insert("platform".into(), json!(platform));
  item.insert(
    "kind".into(),
    json!(if is_short { "short" } else { "video" }),
  );
  if let Some(u) = url {
    item.insert("url".into(), json!(u));
  }
  if let Some(t) = s("title") {
    item.insert("title".into(), json!(t));
  }
  item.insert("description".into(), json!(s("description").unwrap_or("")));
  if let Some(d) = n("duration") {
    item.insert("durationSec".into(), json!(d));
  }
  if let Some(p) = n("timestamp")
    .and_then(iso_from_ts)
    .or_else(|| s("upload_date").and_then(iso_from_date))
  {
    item.insert("publishedAt".into(), json!(p));
  }
  if let Some(v) = n("view_count") {
    item.insert("stats".into(), json!({ "views": v as u64 }));
  }
  let thumbs: Vec<Value> = e
    .get("thumbnails")
    .and_then(Value::as_array)
    .map(|a| {
      a.iter()
        .filter_map(|t| {
          let url = t.get("url")?.as_str()?;
          let mut m = Map::new();
          m.insert("url".into(), json!(url));
          for (k, out) in [("width", "width"), ("height", "height")] {
            if let Some(v) = t.get(k).and_then(Value::as_u64).filter(|v| *v > 0) {
              m.insert(out.into(), json!(v));
            }
          }
          Some(Value::Object(m))
        })
        .collect()
    })
    .unwrap_or_default();
  item.insert(
    "thumbnails".into(),
    Value::Array(thumbs.into_iter().rev().take(3).collect()),
  );
  item.insert(
    "flags".into(),
    json!({
      "live": live == Some("is_live"),
      "upcoming": live == Some("is_upcoming"),
      "premiere": live == Some("post_live") && tab == Some("streams"),
      "membersOnly": s("availability") == Some("subscriber_only"),
      "ageRestricted": e.get("age_limit").and_then(Value::as_u64).unwrap_or(0) >= 18,
    }),
  );
  item.insert(
    "source".into(),
    json!({ "via": "helper", "detail": s("ie_key").unwrap_or("yt-dlp") }),
  );
  Some(Value::Object(item))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Page {
  pub items: Vec<Value>,
  pub next: Option<String>,
  pub title: Option<String>,
  pub handle: Option<String>,
  pub total: Option<u64>,
}

/// Maps one window of `--dump-single-json` output and works out the next cursor.
/// `seen` carries ids already returned in this listing (Shorts that also appear under Videos).
pub fn map_window(
  doc: &Value,
  cursor: Cursor,
  tab_count: usize,
  tab: Option<&str>,
  url: &str,
  seen: &mut std::collections::HashSet<String>,
) -> Page {
  let fallback = platform_of(url, None);
  let entries = doc
    .get("entries")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default();
  let raw = entries.len() as u32;
  let items: Vec<Value> = entries
    .iter()
    .filter_map(|e| map_entry(e, tab, &fallback))
    .filter(|i| seen.insert(i["id"].as_str().unwrap_or_default().to_string()))
    .collect();
  let next = if raw >= PAGE {
    Some(
      Cursor {
        tab: cursor.tab,
        start: cursor.start + PAGE,
      }
      .encode(),
    )
  } else if cursor.tab + 1 < tab_count {
    Some(
      Cursor {
        tab: cursor.tab + 1,
        start: 1,
      }
      .encode(),
    )
  } else {
    None
  };
  let title = doc
    .get("channel")
    .or(doc.get("uploader"))
    .or(doc.get("title"))
    .and_then(Value::as_str)
    .map(|t| t.trim_end_matches(" - Videos").to_string());
  let handle = doc
    .get("uploader_id")
    .or(doc.get("channel_id"))
    .and_then(Value::as_str)
    .map(|h| h.trim_start_matches('@').to_string());
  let total = doc.get("playlist_count").and_then(Value::as_u64);
  Page {
    items,
    next,
    title,
    handle,
    total,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashSet;

  fn fixture() -> Value {
    json!({
      "_type": "playlist", "id": "UC123", "title": "Mara Vee - Videos", "channel": "Mara Vee", "uploader_id": "@maravee", "playlist_count": 2,
      "entries": [
        { "_type": "url", "ie_key": "Youtube", "id": "aaa", "url": "https://www.youtube.com/watch?v=aaa", "title": "Hello, 世界", "duration": 61.0, "view_count": 1200, "timestamp": 1730000000,
          "thumbnails": [{ "url": "https://i.ytimg.com/a/1.jpg", "width": 120, "height": 90 }, { "url": "https://i.ytimg.com/a/2.jpg", "width": 1280, "height": 720 }] },
        { "_type": "url", "ie_key": "Youtube", "id": "bbb", "url": "https://www.youtube.com/shorts/bbb", "title": "Short", "live_status": "is_upcoming" },
        { "_type": "url", "ie_key": "YoutubeTab", "id": "UCnested", "url": "https://www.youtube.com/@maravee/shorts" }
      ]
    })
  }

  #[test]
  fn catalog_channel_root_lists_tab_by_tab() {
    let t = tabs("https://www.youtube.com/@maravee/");
    assert_eq!(
      t.iter().map(|(u, _)| u.as_str()).collect::<Vec<_>>(),
      [
        "https://www.youtube.com/@maravee/videos",
        "https://www.youtube.com/@maravee/shorts",
        "https://www.youtube.com/@maravee/streams"
      ]
    );
    assert_eq!(tabs("https://www.youtube.com/@maravee/shorts").len(), 1);
    assert_eq!(tabs("https://vimeo.com/user1").len(), 1);
  }

  #[test]
  fn catalog_maps_flat_entries_and_skips_nested_tabs() {
    let mut seen = HashSet::new();
    let p = map_window(
      &fixture(),
      Cursor { tab: 0, start: 1 },
      3,
      Some("videos"),
      "https://www.youtube.com/@maravee/videos",
      &mut seen,
    );
    assert_eq!(p.items.len(), 2);
    let a = &p.items[0];
    assert_eq!(a["id"], "aaa");
    assert_eq!(a["platform"], "youtube");
    assert_eq!(a["kind"], "video");
    assert_eq!(a["title"], "Hello, 世界");
    assert_eq!(a["publishedAt"], "2024-10-27T03:33:20Z");
    assert_eq!(a["stats"]["views"], 1200);
    assert_eq!(a["thumbnails"][0]["width"], 1280);
    assert_eq!(a["source"]["via"], "helper");
    assert_eq!(p.items[1]["kind"], "short");
    assert_eq!(p.items[1]["flags"]["upcoming"], true);
    assert_eq!(p.title.as_deref(), Some("Mara Vee"));
    assert_eq!(p.handle.as_deref(), Some("maravee"));
    // short window, more tabs → next tab from the start
    assert_eq!(p.next.as_deref(), Some("1:1"));
  }

  #[test]
  fn catalog_full_window_pages_within_the_tab_and_dedupes_shorts() {
    let entries: Vec<Value> = (0..PAGE).map(|i| json!({ "id": format!("v{i}"), "url": format!("https://www.youtube.com/watch?v=v{i}") })).collect();
    let mut seen = HashSet::new();
    let p = map_window(
      &json!({ "entries": entries }),
      Cursor { tab: 0, start: 1 },
      3,
      Some("videos"),
      "https://www.youtube.com/@x/videos",
      &mut seen,
    );
    assert_eq!(p.next.as_deref(), Some("0:201"));
    let again = map_window(
      &json!({ "entries": [{ "id": "v3", "url": "https://www.youtube.com/shorts/v3" }] }),
      Cursor { tab: 2, start: 1 },
      3,
      Some("shorts"),
      "https://www.youtube.com/@x/shorts",
      &mut seen,
    );
    assert!(again.items.is_empty());
    assert_eq!(again.next, None);
  }

  #[test]
  fn catalog_cursor_round_trip() {
    assert_eq!(Cursor::parse(None), Cursor { tab: 0, start: 1 });
    assert_eq!(Cursor::parse(Some("2:401")), Cursor { tab: 2, start: 401 });
    assert_eq!(Cursor::parse(Some("junk")), Cursor { tab: 0, start: 1 });
    assert_eq!(Cursor { tab: 1, start: 201 }.encode(), "1:201");
  }

  #[test]
  fn catalog_platform_ids_match_the_registry_style() {
    assert_eq!(
      platform_of("https://m.youtube.com/watch?v=1", None),
      "youtube"
    );
    assert_eq!(
      platform_of("https://www.tiktok.com/@a/video/1", None),
      "tiktok"
    );
    assert_eq!(
      platform_of("https://example.org/v/1", Some("Generic")),
      "generic"
    );
  }
}

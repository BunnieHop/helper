//! Discord, through a channel webhook the creator made (Server settings → Integrations →
//! Webhooks). Posts the text and a link embed (title, thumbnail); images under 10 MB are attached.
//! Videos are linked, not uploaded (destination schema note). The webhook URL is the credential
//! and stays in the keychain.
//!
//! D11: webhooks can't search a channel, so the only guard against a second post is the hop's
//! own per-cell state; a post that was sent but not confirmed comes back `publishedUnverified`.

use super::{body_text, file_body, is_image, json_or_fail, mime_of, net, title_text};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader, With};
use serde_json::{json, Value};

const P: &str = "Discord";
const MAX_IMAGE: u64 = 10_000_000;

pub struct Discord {
  http: reqwest::Client,
  url: String,
}

/// `https://discord.com/api/webhooks/<id>/<token>` (also discordapp.com, ptb./canary.).
/// Loopback http is allowed for tests.
pub fn webhook_url(raw: &str) -> Result<String, Failure> {
  let t = raw.trim().trim_end_matches('/');
  let bad = || {
    Failure::new(
      "unknown",
      "That isn't a Discord webhook link. Copy it from Server settings → Integrations → Webhooks.",
    )
  };
  let (scheme, rest) = t.split_once("://").ok_or_else(bad)?;
  let (host, path) = rest.split_once('/').ok_or_else(bad)?;
  let discord = matches!(
    host,
    "discord.com" | "discordapp.com" | "ptb.discord.com" | "canary.discord.com"
  );
  let loopback = host.starts_with("127.0.0.1:");
  let parts: Vec<&str> = path.split('/').collect();
  let shape = parts.len() == 4
    && parts[0] == "api"
    && parts[1] == "webhooks"
    && parts[2].chars().all(|c| c.is_ascii_digit())
    && !parts[2].is_empty()
    && parts[3]
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    && !parts[3].is_empty();
  match (scheme, discord, loopback, shape) {
    ("https", true, _, true) | ("http", _, true, true) => Ok(format!("{scheme}://{host}/{path}")),
    _ => Err(bad()),
  }
}

/// Checks the webhook and returns a label ("#channel webhook name").
pub async fn connect(http: &reqwest::Client, raw: &str) -> Result<(String, String), Failure> {
  let url = webhook_url(raw)?;
  let w = json_or_fail(P, http.get(&url).send().await)
    .await
    .map_err(|f| {
      if f.code == "notFound404" || f.code == "tokenExpired" {
        Failure {
          code: "signInRequired",
          message: "Discord says that webhook doesn't exist any more. Make a new one.".into(),
          verbatim: f.verbatim,
        }
      } else {
        f
      }
    })?;
  let name = w["name"].as_str().unwrap_or("webhook");
  Ok((url, format!("{name} (Discord webhook)")))
}

impl Discord {
  pub fn new(http: reqwest::Client, secret: &Value) -> Option<Self> {
    Some(Self {
      http,
      url: secret["url"].as_str()?.to_string(),
    })
  }
}

/// Discord counts characters; keep under its 2,000 / 256 / 4,096 limits without splitting a char.
fn clip(s: &str, n: usize) -> String {
  if s.chars().count() <= n {
    return s.to_string();
  }
  let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
  out.push('…');
  out
}

pub fn payload(u: &Upload<'_>) -> Value {
  let link = u
    .post
    .and_then(|p| p.pointer("/fields/link"))
    .and_then(Value::as_str)
    .or_else(|| u.item.get("url").and_then(Value::as_str));
  let title = title_text(u.post, u.item);
  let mut content = body_text(u.post, u.item);
  if let Some(l) = link {
    if !content.contains(l) {
      content = format!("{content}\n{l}").trim().to_string();
    }
  }
  let mut embed = json!({ "title": clip(&title, 256) });
  if let Some(l) = link {
    embed["url"] = json!(l);
  }
  if let Some(t) = u
    .item
    .pointer("/thumbnails/0/url")
    .and_then(Value::as_str)
    .filter(|t| t.starts_with("https://"))
  {
    embed["image"] = json!({ "url": t });
  }
  if let Some(d) = u.item.get("publishedAt").and_then(Value::as_str) {
    embed["timestamp"] = json!(d);
  }
  json!({
    "content": clip(&content, 2000),
    "embeds": if link.is_some() { json!([embed]) } else { json!([]) },
    // the creator's own post never pings @everyone or roles
    "allowed_mentions": { "parse": [] },
  })
}

impl Uploader for Discord {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let body = payload(&u);
      let mut form = reqwest::multipart::Form::new();
      let mut n = 0;
      for p in u.media.iter().filter(|p| is_image(p)).take(10) {
        let len = tokio::fs::metadata(p).await.map(|m| m.len()).unwrap_or(0);
        if len == 0 || len > MAX_IMAGE {
          continue;
        }
        let (b, len) = file_body(p).await.map_err(|e| {
          Failure::new("unknown", "Couldn't read the image from the vault.").with(e)
        })?;
        let name = p
          .file_name()
          .and_then(|n| n.to_str())
          .unwrap_or("image")
          .to_string();
        let part = reqwest::multipart::Part::stream_with_length(b, len)
          .file_name(name)
          .mime_str(mime_of(p))
          .map_err(|e| net(P, e))?;
        form = form.part(format!("files[{n}]"), part);
        n += 1;
      }
      let url = format!("{}?wait=true", self.url);
      let r = if n > 0 {
        let form = form.text("payload_json", body.to_string());
        self.http.post(&url).multipart(form).send().await
      } else {
        self.http.post(&url).json(&body).send().await
      };
      let m = json_or_fail(P, r).await?;
      let id = m["id"].as_str().unwrap_or("").to_string();
      if id.is_empty() {
        return Ok(Published {
          note: None,
          dest_item_id: String::new(),
          dest_url: None,
          verified: false,
        });
      }
      let check = self
        .http
        .get(format!("{}/messages/{id}", self.url))
        .send()
        .await;
      let verified = matches!(check, Ok(r) if r.status().is_success());
      let dest_url = match (m["guild_id"].as_str(), m["channel_id"].as_str()) {
        (Some(g), Some(c)) => Some(format!("https://discord.com/channels/{g}/{c}/{id}")),
        _ => None,
      };
      Ok(Published {
        note: None,
        dest_item_id: id,
        dest_url,
        verified,
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Path, State};
  use axum::routing::get;
  use axum::{Json, Router};
  use std::sync::{Arc, Mutex};

  #[test]
  fn discord_accepts_only_webhook_links() {
    assert!(webhook_url("https://discord.com/api/webhooks/123/abc-DEF_9").is_ok());
    for bad in [
      "https://evil.example/api/webhooks/1/a",
      "http://discord.com/api/webhooks/1/a",
      "https://discord.com/api/webhooks/x/a",
      "https://discord.com/channels/1/2",
      "discord.com/api/webhooks/1/a",
    ] {
      assert!(webhook_url(bad).is_err(), "{bad}");
    }
  }

  #[tokio::test]
  async fn discord_posts_text_and_a_link_embed_without_pinging_anyone() {
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let app = Router::new()
      .route(
        "/api/webhooks/{id}/{tok}",
        get(|| async { Json(json!({ "name": "Uploads" })) }).post(
          |State(s): State<Arc<Mutex<Vec<Value>>>>, Json(b): Json<Value>| async move {
            s.lock().unwrap().push(b);
            Json(json!({ "id": "99", "channel_id": "2", "guild_id": "1" }))
          },
        ),
      )
      .route(
        "/api/webhooks/{id}/{tok}/messages/{m}",
        get(
          |Path((_, _, m)): Path<(String, String, String)>| async move { Json(json!({ "id": m })) },
        ),
      )
      .with_state(seen.clone());
    let base = serve(app).await;
    let http = reqwest::Client::new();
    let (url, label) = connect(&http, &format!("{base}/api/webhooks/1/tok"))
      .await
      .unwrap();
    assert_eq!(label, "Uploads (Discord webhook)");
    let d = Discord::new(http, &json!({ "url": url })).unwrap();
    let item = json!({ "id": "v1", "title": "My video", "description": "About it @everyone", "url": "https://www.youtube.com/watch?v=v1", "thumbnails": [{ "url": "https://i.ytimg.com/vi/v1/hq.jpg" }], "publishedAt": "2020-01-02T00:00:00Z" });
    let p = d
      .publish(Upload {
        item: &item,
        post: None,
        media: &[],
        idempotency_key: "h:v1:discord",
        options: &json!({}),
      })
      .await
      .unwrap();
    assert!(p.verified);
    assert_eq!(
      p.dest_url.as_deref(),
      Some("https://discord.com/channels/1/2/99")
    );
    let b = seen.lock().unwrap()[0].clone();
    assert!(b["content"]
      .as_str()
      .unwrap()
      .ends_with("https://www.youtube.com/watch?v=v1"));
    assert_eq!(b["embeds"][0]["title"], "My video");
    assert_eq!(b["embeds"][0]["timestamp"], "2020-01-02T00:00:00Z");
    assert_eq!(b["allowed_mentions"]["parse"], json!([]));
  }
}

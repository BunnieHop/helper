//! Telegram channel, through a bot the creator made with @BotFather and added as a channel admin
//! (Bot API). Videos, photos (albums of up to 10), audio and text. The public Bot API takes files
//! up to 50 MB; bigger files fail with that reason instead of being shrunk silently (D12).
//!
//! The bot token is part of every request path, so it is never logged: errors are reported with
//! `without_url()`. D11: the Bot API can't list a channel's messages, so the hop's own cell state
//! is the guard; the send answer is the message itself, which is our confirmation.

use super::{body_text, file_body, is_image, is_video, json_or_fail, mime_of, net, Endpoints};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader, With};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const P: &str = "Telegram";
pub const MAX_BYTES: u64 = 50_000_000;
const MAX_CAPTION: usize = 1024;
const MAX_TEXT: usize = 4096;

pub struct Telegram {
  http: reqwest::Client,
  api: String,
  chat: String,
}

fn valid_token(t: &str) -> bool {
  match t.split_once(':') {
    Some((id, rest)) => {
      !id.is_empty()
        && id.chars().all(|c| c.is_ascii_digit())
        && rest.len() >= 20
        && rest
          .chars()
          .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }
    None => false,
  }
}

/// "@mychannel", "t.me/mychannel", "https://t.me/mychannel" or a numeric id "-100…".
pub fn chat_id(raw: &str) -> Option<String> {
  let t = raw.trim().trim_end_matches('/');
  let t = t
    .strip_prefix("https://")
    .or_else(|| t.strip_prefix("http://"))
    .unwrap_or(t);
  let t = t.strip_prefix("t.me/").unwrap_or(t);
  let t = t.strip_prefix('@').unwrap_or(t);
  if t.starts_with('-') && t.len() > 1 && t[1..].chars().all(|c| c.is_ascii_digit()) {
    return Some(t.to_string());
  }
  let ok = (5..=32).contains(&t.len())
    && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
  ok.then(|| format!("@{t}"))
}

/// Checks the bot, the channel and that the bot may post there. Returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  ep: &Endpoints,
  token: &str,
  channel: &str,
) -> Result<(String, Value), Failure> {
  let token = token.trim();
  if !valid_token(token) {
    return Err(Failure::new(
      "signInRequired",
      "That doesn't look like a bot token. @BotFather shows it as 123456:ABC….",
    ));
  }
  let chat = chat_id(channel).ok_or_else(|| {
    Failure::new(
      "requiredChoiceMissing",
      "Type the channel as @name or its t.me link.",
    )
  })?;
  let api = format!("{}/bot{token}", ep.telegram);
  let me = call(http, &api, "getMe", &json!({}))
    .await
    .map_err(|f| match f.code {
      "tokenExpired" | "notFound404" => Failure {
        code: "signInRequired",
        message: "Telegram didn't accept that bot token.".into(),
        verbatim: f.verbatim,
      },
      _ => f,
    })?;
  let c = call(http, &api, "getChat", &json!({ "chat_id": chat }))
    .await
    .map_err(|f| match f.code {
      "uploadRejected" => Failure {
        code: "requiredChoiceMissing",
        message: "Telegram can't find that channel, or the bot hasn't been added to it yet.".into(),
        verbatim: f.verbatim,
      },
      _ => f,
    })?;
  let member = call(
    http,
    &api,
    "getChatMember",
    &json!({ "chat_id": chat, "user_id": me["id"] }),
  )
  .await?;
  let can_post = member["status"] == "creator"
    || (member["status"] == "administrator"
      && (c["type"] != "channel" || member["can_post_messages"] == true));
  if !can_post {
    return Err(Failure::new(
      "signInRequired",
      format!(
        "@{} isn't allowed to post in {}. Add it as an admin with “Post messages”.",
        me["username"].as_str().unwrap_or("the bot"),
        c["title"].as_str().unwrap_or("that channel")
      ),
    ));
  }
  let id = c["id"].as_i64().map(|i| i.to_string()).unwrap_or(chat);
  let label = c["title"].as_str().unwrap_or(&id).to_string();
  let secret = json!({
    "token": token,
    "chat": id,
    "username": c["username"],
  });
  Ok((label, secret))
}

/// Bot API answers `{ ok, result }` or `{ ok: false, description }`.
async fn call(
  http: &reqwest::Client,
  api: &str,
  method: &str,
  body: &Value,
) -> Result<Value, Failure> {
  let r = http.post(format!("{api}/{method}")).json(body).send().await;
  unwrap(json_or_fail(P, r.map_err(|e| e.without_url())).await)
}

fn unwrap(v: Result<Value, Failure>) -> Result<Value, Failure> {
  let v = v?;
  if v["ok"] == true {
    Ok(v["result"].clone())
  } else {
    Err(Failure {
      code: "uploadRejected",
      message: "Telegram refused the post.".into(),
      verbatim: v["description"].as_str().map(String::from),
    })
  }
}

fn clip_utf16(s: &str, max: usize) -> String {
  if s.encode_utf16().count() <= max {
    return s.to_string();
  }
  let mut n = 0;
  let mut out = String::new();
  for c in s.chars() {
    n += c.len_utf16();
    if n > max.saturating_sub(1) {
      out.push('…');
      return out;
    }
    out.push(c);
  }
  out
}

impl Telegram {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints) -> Option<Self> {
    Some(Self {
      http,
      api: format!("{}/bot{}", ep.telegram, secret["token"].as_str()?),
      chat: secret["chat"].as_str()?.to_string(),
    })
  }

  async fn part(path: &Path) -> Result<reqwest::multipart::Part, Failure> {
    let (b, len) = file_body(path)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the file from the vault.").with(e))?;
    let name = path
      .file_name()
      .and_then(|n| n.to_str())
      .unwrap_or("file")
      .to_string();
    reqwest::multipart::Part::stream_with_length(b, len)
      .file_name(name)
      .mime_str(mime_of(path))
      .map_err(|e| net(P, e))
  }

  async fn send_file(
    &self,
    method: &str,
    field: &str,
    path: &Path,
    caption: &str,
  ) -> Result<Value, Failure> {
    let mut form = reqwest::multipart::Form::new()
      .text("chat_id", self.chat.clone())
      .part(field.to_string(), Self::part(path).await?);
    if !caption.is_empty() {
      form = form.text("caption", caption.to_string());
    }
    if method == "sendVideo" {
      form = form.text("supports_streaming", "true");
    }
    let r = self
      .http
      .post(format!("{}/{method}", self.api))
      .multipart(form)
      .send()
      .await;
    unwrap(json_or_fail(P, r.map_err(|e| e.without_url())).await)
  }

  async fn album(&self, images: &[PathBuf], caption: &str) -> Result<Value, Failure> {
    let mut form = reqwest::multipart::Form::new().text("chat_id", self.chat.clone());
    let mut media = Vec::new();
    for (i, p) in images.iter().enumerate() {
      let mut m = json!({ "type": "photo", "media": format!("attach://f{i}") });
      if i == 0 && !caption.is_empty() {
        m["caption"] = json!(caption);
      }
      media.push(m);
      form = form.part(format!("f{i}"), Self::part(p).await?);
    }
    form = form.text("media", Value::Array(media).to_string());
    let r = self
      .http
      .post(format!("{}/sendMediaGroup", self.api))
      .multipart(form)
      .send()
      .await;
    let msgs = unwrap(json_or_fail(P, r.map_err(|e| e.without_url())).await)?;
    Ok(msgs.get(0).cloned().unwrap_or(Value::Null))
  }
}

async fn size(p: &Path) -> u64 {
  tokio::fs::metadata(p).await.map(|m| m.len()).unwrap_or(0)
}

impl Uploader for Telegram {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let text = body_text(u.post, u.item);
      let caption = clip_utf16(&text, MAX_CAPTION);
      let video = u.media.iter().find(|p| is_video(p));
      let audio = u.media.iter().find(|p| mime_of(p).starts_with("audio/"));
      let images: Vec<PathBuf> = u
        .media
        .iter()
        .filter(|p| is_image(p))
        .take(10)
        .cloned()
        .collect();
      for p in video.into_iter().chain(audio).chain(images.iter()) {
        let n = size(p).await;
        if n > MAX_BYTES {
          return Err(Failure::new(
            "itemTooLarge",
            format!(
              "Telegram bots can send files up to 50 MB; this one is {:.0} MB.",
              n as f64 / 1e6
            ),
          ));
        }
      }
      let msg = if let Some(v) = video {
        self.send_file("sendVideo", "video", v, &caption).await?
      } else if let Some(a) = audio {
        self.send_file("sendAudio", "audio", a, &caption).await?
      } else if images.len() == 1 {
        self
          .send_file("sendPhoto", "photo", &images[0], &caption)
          .await?
      } else if images.len() > 1 {
        self.album(&images, &caption).await?
      } else {
        call(
          &self.http,
          &self.api,
          "sendMessage",
          &json!({ "chat_id": self.chat, "text": clip_utf16(&text, MAX_TEXT) }),
        )
        .await?
      };
      let id = msg["message_id"].as_i64().unwrap_or(0);
      let username = msg.pointer("/chat/username").and_then(Value::as_str);
      Ok(Published {
        note: None,
        dest_item_id: id.to_string(),
        dest_url: username.map(|n| format!("https://t.me/{n}/{id}")),
        verified: id > 0,
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Path as AxPath, State};
  use axum::routing::post;
  use axum::{Json, Router};
  use std::sync::{Arc, Mutex};

  const TOKEN: &str = "123456:ABCdefGHIjklMNOpqrSTUvwxYZ_12345";

  #[test]
  fn telegram_channel_and_token_shapes() {
    assert_eq!(chat_id("@my_channel").as_deref(), Some("@my_channel"));
    assert_eq!(
      chat_id("https://t.me/my_channel/").as_deref(),
      Some("@my_channel")
    );
    assert_eq!(chat_id("-1001234").as_deref(), Some("-1001234"));
    assert!(chat_id("a b").is_none() && chat_id("@x").is_none());
    assert!(valid_token(TOKEN));
    assert!(!valid_token("123:short") && !valid_token("abc:ABCdefGHIjklMNOpqrSTUvwxYZ"));
    assert_eq!(clip_utf16("ab😀cd", 4), "ab…");
  }

  type Log = Arc<Mutex<Vec<String>>>;

  fn fake(log: Log, admin: bool) -> Router {
    Router::new()
      .route(
        "/{bot}/{method}",
        post(
          move |State(l): State<Log>, AxPath((bot, method)): AxPath<(String, String)>, body: axum::body::Bytes| async move {
            assert_eq!(bot, format!("bot{TOKEN}"));
            l.lock().unwrap().push(method.clone());
            let r = match method.as_str() {
              "getMe" => json!({ "id": 7, "username": "mara_bot" }),
              "getChat" => json!({ "id": -1001, "type": "channel", "title": "Mara Clips", "username": "maraclips" }),
              "getChatMember" => json!({ "status": if admin { "administrator" } else { "member" }, "can_post_messages": admin }),
              "sendVideo" => {
                let b = String::from_utf8_lossy(&body);
                assert!(b.contains("supports_streaming") && b.contains("Caption"));
                json!({ "message_id": 42, "chat": { "username": "maraclips" } })
              }
              "sendMessage" => json!({ "message_id": 43, "chat": { "username": "maraclips" } }),
              _ => return Json(json!({ "ok": false, "description": "Bad Request: method not found" })),
            };
            Json(json!({ "ok": true, "result": r }))
          },
        ),
      )
      .with_state(log)
  }

  #[tokio::test]
  async fn telegram_checks_the_bot_can_post_then_sends_the_video() {
    let log: Log = Arc::default();
    let base = serve(fake(log.clone(), true)).await;
    let ep = Endpoints {
      telegram: base,
      ..Endpoints::default()
    };
    let http = reqwest::Client::new();
    let (label, secret) = connect(&http, &ep, TOKEN, "t.me/maraclips").await.unwrap();
    assert_eq!(label, "Mara Clips");
    assert_eq!(secret["chat"], "-1001");
    let t = Telegram::new(http, &secret, &ep).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let v = dir.path().join("media.mp4");
    std::fs::write(&v, b"video").unwrap();
    let item = json!({ "id": "v1", "title": "Caption", "description": "" });
    let p = t
      .publish(Upload {
        item: &item,
        post: None,
        media: std::slice::from_ref(&v),
        idempotency_key: "h:v1:telegram",
        options: &json!({}),
      })
      .await
      .unwrap();
    assert_eq!(p.dest_url.as_deref(), Some("https://t.me/maraclips/42"));
    assert!(p.verified);
    let text = json!({ "id": "t1", "kind": "text", "description": "Just words" });
    let p = t
      .publish(Upload {
        item: &text,
        post: None,
        media: &[],
        idempotency_key: "h:t1:telegram",
        options: &json!({}),
      })
      .await
      .unwrap();
    assert_eq!(p.dest_item_id, "43");
  }

  #[tokio::test]
  async fn telegram_says_when_the_bot_isnt_an_admin() {
    let base = serve(fake(Arc::default(), false)).await;
    let ep = Endpoints {
      telegram: base,
      ..Endpoints::default()
    };
    let f = connect(&reqwest::Client::new(), &ep, TOKEN, "@maraclips")
      .await
      .unwrap_err();
    assert_eq!(f.code, "signInRequired");
    assert!(f.message.contains("@mara_bot") && f.message.contains("Post messages"));
  }

  #[tokio::test]
  async fn telegram_refuses_files_over_50_mb_honestly() {
    let ep = Endpoints::default();
    let t = Telegram::new(
      reqwest::Client::new(),
      &json!({ "token": TOKEN, "chat": "-1" }),
      &ep,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let v = dir.path().join("media.mp4");
    let f = std::fs::File::create(&v).unwrap();
    f.set_len(MAX_BYTES + 1).unwrap();
    let item = json!({ "id": "v1", "title": "Big" });
    let e = t
      .publish(Upload {
        item: &item,
        post: None,
        media: std::slice::from_ref(&v),
        idempotency_key: "k",
        options: &json!({}),
      })
      .await
      .unwrap_err();
    assert_eq!(e.code, "itemTooLarge");
  }
}

//! Telegram's user API. Authorization and media stay on this computer (O-012, D8).
use super::{body_text, is_image, is_video, mime_of};
use crate::hops::{BoxFut, Failure, PublishControl, Published, Upload, Uploader};
use crate::posted::UploadHandles;
use grammers_client::client::PasswordToken;
use grammers_client::{Client, SignInError};
use grammers_mtsender::{ConnectionParams, InvocationError, NoRetries, SenderPool};
use grammers_session::{storages::MemorySession, Session, SessionData};
use grammers_tl_types as tl;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
  path::PathBuf,
  sync::Arc,
  time::{Duration, Instant},
};
use tracing::instrument::WithSubscriber;

pub const SIGN_IN_TTL: Duration = Duration::from_secs(600);
/// Tries at one code or password before the sign-in stops.
const RETYPES: u8 = 3;
const MAX_BYTES: u64 = 2_000_000_000;

#[derive(Clone, Serialize, Deserialize)]
pub struct Channel {
  pub id: i64,
  pub hash: i64,
  pub title: String,
}
impl Channel {
  fn input(&self) -> tl::enums::InputChannel {
    tl::types::InputChannel {
      channel_id: self.id,
      access_hash: self.hash,
    }
    .into()
  }
  fn peer(&self) -> tl::enums::InputPeer {
    tl::types::InputPeerChannel {
      channel_id: self.id,
      access_hash: self.hash,
    }
    .into()
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
  pub id: i32,
  pub channel: i64,
  pub caption: String,
  pub media: String,
  pub media_id: i64,
}
fn verified_message(sent: &Receipt, got: &Receipt) -> bool {
  sent.id > 0
    && sent.id == got.id
    && sent.channel == got.channel
    && sent.caption == got.caption
    && sent.media == got.media
    && sent.media_id == got.media_id
}
fn can_post(broadcast: bool, creator: bool, post_rights: bool) -> bool {
  broadcast && (creator || post_rights)
}
fn random_id(key: &str) -> i64 {
  use sha2::{Digest, Sha256};
  let digest = Sha256::digest(format!("telegram|{key}").as_bytes());
  i64::from_le_bytes(digest[..8].try_into().expect("eight digest bytes")) | 1
}
fn rpc_refused(code: Option<i32>) -> bool {
  code
    .and_then(|n| u16::try_from(n).ok())
    .is_some_and(|n| super::NOTHING_POSTED.contains(&n))
}

/// Only known protocol names leave the transport. Never include a provider-supplied string
/// that could echo a phone, code, password, session or app credential.
fn rpc_failure(_code: i32, name: &str, value: Option<u32>) -> Failure {
  let (code, message, verbatim) = match name {
    "FLOOD_WAIT" | "FLOOD_PREMIUM_WAIT" | "SLOWMODE_WAIT" => (
      "rateLimited429",
      "Telegram asked you to wait. Try again after the wait shown below.",
      Some(format!("{name}_{}", value.unwrap_or(0))),
    ),
    "PHONE_CODE_EXPIRED"
    | "PHONE_CODE_INVALID"
    | "PHONE_NUMBER_INVALID"
    | "PASSWORD_HASH_INVALID" => (
      "signInRequired",
      "Telegram did not accept that. Check it and type it again, or start again if the code expired.",
      Some(name.into()),
    ),
    "PHONE_NUMBER_APP_SIGNUP_FORBIDDEN"
    | "PREMIUM_ACCOUNT_REQUIRED"
    | "ALLOW_PAYMENT_REQUIRED"
    | "STARS_PAYMENT_REQUIRED"
    | "PAYMENT_REQUIRED" => (
      "notSupported",
      "Telegram requires payment for this action. BunnieHop stopped without paying.",
      Some(name.into()),
    ),
    "AUTH_KEY_UNREGISTERED" | "SESSION_REVOKED" | "SESSION_EXPIRED" => (
      "tokenExpired",
      "Telegram signed this Helper out. Connect Telegram again.",
      Some(name.into()),
    ),
    "CHAT_WRITE_FORBIDDEN"
    | "CHAT_ADMIN_REQUIRED"
    | "CHANNEL_PRIVATE"
    | "USER_BANNED_IN_CHANNEL" => (
      "signInRequired",
      "Telegram did not allow posting to this channel. Choose a channel you run.",
      Some(name.into()),
    ),
    _ => (
      "uploadRejected",
      "Telegram refused the request. No automatic retry was made.",
      None,
    ),
  };
  Failure {
    code,
    message: message.into(),
    verbatim,
  }
}

pub struct RpcIssue {
  pub code: Option<i32>,
  pub failure: Failure,
}
fn issue(e: InvocationError) -> RpcIssue {
  match e {
    InvocationError::Rpc(e) => RpcIssue {
      code: Some(e.code),
      failure: rpc_failure(e.code, &e.name, e.value),
    },
    _ => RpcIssue {
      code: None,
      failure: Failure::new(
        "networkLost",
        "Couldn't read Telegram's answer. No automatic retry was made.",
      ),
    },
  }
}
fn retypable(stage: &str, e: &Failure) -> bool {
  matches!(
    (stage, e.verbatim.as_deref()),
    ("code", Some("PHONE_CODE_INVALID")) | ("password", Some("PASSWORD_HASH_INVALID"))
  )
}
fn expired() -> Failure {
  Failure::new(
    "signInRequired",
    "This Telegram sign-in expired. Start again in the Helper.",
  )
}
fn invalid_stage() -> Failure {
  Failure::new(
    "signInRequired",
    "Complete the current Telegram sign-in step first.",
  )
}
fn local_failure() -> Failure {
  Failure::new(
    "vaultUnavailable",
    "Couldn't save the Telegram result on this computer.",
  )
}

/// A narrow seam around real MTProto calls, used by the offline protocol tests.
pub trait TelegramApi: Send + Sync {
  fn auth<'a>(
    &'a mut self,
    stage: &'a str,
    value: &'a str,
  ) -> BoxFut<'a, Result<&'static str, Failure>>;
  fn channels(&mut self) -> BoxFut<'_, Result<Vec<Channel>, Failure>>;
  fn check_channel<'a>(&'a mut self, c: &'a Channel) -> BoxFut<'a, Result<(), Failure>>;
  fn session(&self) -> Result<Value, Failure>;
  fn upload<'a>(
    &'a mut self,
    files: &'a [PathBuf],
    item: &'a Value,
  ) -> BoxFut<'a, Result<Vec<Value>, Failure>>;
  fn send<'a>(
    &'a mut self,
    c: &'a Channel,
    media: &'a [Value],
    caption: &'a str,
    random: i64,
  ) -> BoxFut<'a, Result<Vec<Receipt>, RpcIssue>>;
  fn read<'a>(
    &'a mut self,
    c: &'a Channel,
    expected: &'a [Receipt],
  ) -> BoxFut<'a, Result<Vec<Receipt>, Failure>>;
}

pub struct SignIn {
  api: Box<dyn TelegramApi>,
  stage: &'static str,
  created: Instant,
  channels: Vec<Channel>,
  tries: u8,
}
impl SignIn {
  pub fn new(api: Box<dyn TelegramApi>) -> Self {
    Self {
      api,
      stage: "phone",
      created: Instant::now(),
      channels: Vec::new(),
      tries: 0,
    }
  }
  pub fn view(&self) -> Value {
    json!({"stage":self.stage,"channels":self.channels.iter().map(|c| json!({"id":c.id.to_string(),"title":c.title})).collect::<Vec<_>>()})
  }
  pub async fn advance(&mut self, stage: &str, value: &str) -> Result<Value, Failure> {
    if self.created.elapsed() >= SIGN_IN_TTL {
      return Err(expired());
    }
    if stage != self.stage || value.is_empty() || value.len() > 512 || stage == "channel" {
      return Err(invalid_stage());
    }
    // A code-request can happen only once per sign-in capability, even after a lost answer.
    self.stage = "stopped";
    match self.api.auth(stage, value).await {
      Ok(next) => {
        self.stage = next;
        self.tries = 0;
      }
      // A mistyped code or password can be typed again. No new code is requested.
      Err(e) if retypable(stage, &e) && self.tries + 1 < RETYPES => {
        self.tries += 1;
        self.stage = if stage == "code" { "code" } else { "password" };
        let mut view = self.view();
        view["error"] = json!([e.message, e.verbatim.unwrap_or_default()].join("\n"));
        return Ok(view);
      }
      Err(e) => return Err(e),
    }
    if self.stage == "channel" {
      self.channels = self.api.channels().await?;
      if self.channels.is_empty() {
        self.stage = "stopped";
        return Err(Failure::new("signInRequired", "Telegram found no channel you can post to. Create a channel or ask its owner for posting rights, then connect again."));
      }
    }
    Ok(self.view())
  }
  pub async fn finish(&mut self, id: &str) -> Result<(String, Value), Failure> {
    if self.created.elapsed() >= SIGN_IN_TTL {
      return Err(expired());
    }
    if self.stage != "channel" {
      return Err(invalid_stage());
    }
    let c = self
      .channels
      .iter()
      .find(|c| c.id.to_string() == id)
      .ok_or_else(invalid_stage)?
      .clone();
    self.api.check_channel(&c).await?;
    let session = self.api.session()?;
    self.stage = "done";
    Ok((
      c.title.clone(),
      json!({"channelId":c.id.to_string(),"channel":c,"session":session}),
    ))
  }
}

/// Uses only in-memory library storage. The existing Store writes this export to the OS
/// keychain; no SQLite/session file is created. No phone or password is included in the export.
pub struct Gram {
  client: Client,
  session: Arc<MemorySession>,
  stop: Option<tokio::sync::oneshot::Sender<()>>,
  api_hash: String,
  api_id: i32,
  login: Option<(String, String)>,
  password: Option<PasswordToken>,
}
impl Drop for Gram {
  fn drop(&mut self) {
    self.stop.take();
  }
}
impl Gram {
  pub fn configured(session: Option<&Value>) -> Result<Self, Failure> {
    let id = std::env::var("TELEGRAM_API_ID")
      .ok()
      .and_then(|s| s.parse::<i32>().ok())
      .filter(|n| *n > 0);
    let hash = std::env::var("TELEGRAM_API_HASH")
      .ok()
      .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let (Some(id), Some(hash)) = (id, hash) else {
      return Err(Failure::new("notSupported", "Telegram isn't ready in this Helper yet. BunnieHop still needs to configure its Telegram app."));
    };
    Self::new(id, hash, session)
  }
  fn new(id: i32, api_hash: String, saved: Option<&Value>) -> Result<Self, Failure> {
    let mut data = SessionData::default();
    if let Some(saved) = saved {
      data.home_dc = saved["home"]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| (1..=5).contains(n))
        .ok_or_else(expired)?;
      let dcs: Vec<grammers_session::types::DcOption> =
        serde_json::from_value(saved["dcs"].clone()).map_err(|_| expired())?;
      // Restore only keys onto built-in production endpoints. Stored addresses never decide
      // where this Helper sends session credentials.
      for dc in dcs {
        if let Some(known) = data.dc_options.get_mut(&dc.id) {
          known.auth_key = dc.auth_key;
        }
      }
      if data
        .dc_options
        .get(&data.home_dc)
        .is_none_or(|d| d.auth_key.is_none())
      {
        return Err(expired());
      }
    }
    let session = Arc::new(MemorySession::from(data));
    let pool = SenderPool::with_configuration(
      session.clone(),
      id,
      ConnectionParams {
        device_model: "BunnieHop Helper".into(),
        system_version: std::env::consts::OS.into(),
        app_version: crate::VERSION.into(),
        retry_policy: Box::new(NoRetries),
        ..Default::default()
      },
    );
    let client = Client::new(pool.handle);
    // The sender spawns its own tasks, which do not inherit a future's subscriber.
    // Keep it on a dedicated current-thread runtime with diagnostics disabled for the
    // whole thread, including every library task. Raw RPC errors cannot enter logs.
    let (stop, stopped) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
      .name("telegram-transport".into())
      .spawn(move || {
        let _quiet = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
          .enable_all()
          .build()
        {
          runtime.block_on(async move {
            tokio::select! {_ = pool.runner.run()=>{}, _ = stopped=>{}}
          });
        }
      })
      .map_err(|_| local_failure())?;
    Ok(Self {
      client,
      session,
      stop: Some(stop),
      api_hash,
      api_id: id,
      login: None,
      password: None,
    })
  }
  async fn invoke<R: tl::RemoteCall>(&self, call: &R) -> Result<R::Return, InvocationError> {
    self
      .client
      .invoke(call)
      .with_subscriber(tracing::subscriber::NoSubscriber::default())
      .await
  }
  fn authorized(
    &mut self,
    result: tl::enums::auth::Authorization,
  ) -> Result<&'static str, Failure> {
    match result {
      tl::enums::auth::Authorization::Authorization(_) => {
        self.login = None;
        Ok("channel")
      }
      _ => Err(Failure::new(
        "signInRequired",
        "Sign in to an existing Telegram account. BunnieHop does not create accounts.",
      )),
    }
  }
  async fn send_code(&mut self, phone: &str) -> Result<&'static str, Failure> {
    if !phone.starts_with('+')
      || !(8..=16).contains(&phone.len())
      || !phone[1..].bytes().all(|b| b.is_ascii_digit())
    {
      return Err(Failure::new(
        "signInRequired",
        "Type your phone number with its country code, starting with +.",
      ));
    }
    let request = tl::functions::auth::SendCode {
      phone_number: phone.into(),
      api_id: self.api_id,
      api_hash: self.api_hash.clone(),
      settings: tl::types::CodeSettings {
        allow_flashcall: false,
        current_number: false,
        allow_app_hash: false,
        allow_missed_call: false,
        allow_firebase: false,
        unknown_number: false,
        logout_tokens: None,
        token: None,
        app_sandbox: None,
      }
      .into(),
    };
    let answer = match self.invoke(&request).await {
      Err(InvocationError::Rpc(e)) if e.code == 303 => {
        let dc = e
          .value
          .and_then(|n| i32::try_from(n).ok())
          .filter(|n| (1..=5).contains(n))
          .ok_or_else(expired)?;
        self
          .session
          .set_home_dc_id(dc)
          .await
          .map_err(|_| local_failure())?;
        self.invoke(&request).await.map_err(|e| issue(e).failure)?
      }
      result => result.map_err(|e| issue(e).failure)?,
    };
    self.accept_sent_code(phone, answer)
  }
  fn accept_sent_code(
    &mut self,
    phone: &str,
    answer: tl::enums::auth::SentCode,
  ) -> Result<&'static str, Failure> {
    match answer {
      tl::enums::auth::SentCode::Code(code) => {
        // A paid Fragment code, email setup and Firebase-only delivery need other flows.
        // Stop without following links, resending or trying a different delivery method.
        if !matches!(
          code.r#type,
          tl::enums::auth::SentCodeType::App(_)
            | tl::enums::auth::SentCodeType::Sms(_)
            | tl::enums::auth::SentCodeType::Call(_)
            | tl::enums::auth::SentCodeType::SmsWord(_)
            | tl::enums::auth::SentCodeType::SmsPhrase(_)
        ) {
          return Err(Failure::new("notSupported", "Telegram requested a sign-in method this Helper cannot use. Open Telegram to check your account, then try again."));
        }
        self.login = Some((phone.into(), code.phone_code_hash));
        Ok("code")
      }
      tl::enums::auth::SentCode::PaymentRequired(_) => {
        Err(rpc_failure(403, "PAYMENT_REQUIRED", None))
      }
      tl::enums::auth::SentCode::Success(done) => self.authorized(done.authorization),
    }
  }
}

impl TelegramApi for Gram {
  fn auth<'a>(
    &'a mut self,
    stage: &'a str,
    value: &'a str,
  ) -> BoxFut<'a, Result<&'static str, Failure>> {
    Box::pin(async move {
      match stage {
        "phone" => self.send_code(value).await,
        "code" => {
          let (phone, hash) = self.login.take().ok_or_else(invalid_stage)?;
          let answer = self
            .invoke(&tl::functions::auth::SignIn {
              phone_number: phone.clone(),
              phone_code_hash: hash.clone(),
              phone_code: Some(value.into()),
              email_verification: None,
            })
            .await;
          match answer {
            Ok(done) => self.authorized(done),
            Err(InvocationError::Rpc(e)) if e.name == "SESSION_PASSWORD_NEEDED" => {
              let p = self
                .invoke(&tl::functions::account::GetPassword {})
                .await
                .map_err(|e| issue(e).failure)?;
              self.password = Some(PasswordToken::new(p.into()));
              Ok("password")
            }
            Err(InvocationError::Rpc(e)) if e.name == "PHONE_CODE_INVALID" => {
              self.login = Some((phone, hash));
              Err(rpc_failure(e.code, &e.name, e.value))
            }
            Err(e) => Err(issue(e).failure),
          }
        }
        "password" => {
          let p = self.password.take().ok_or_else(invalid_stage)?;
          match self
            .client
            .check_password(p, value.as_bytes())
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
          {
            Ok(_) => Ok("channel"),
            Err(SignInError::InvalidPassword(_)) => {
              // SRP parameters serve one attempt; fetch fresh ones for the next try.
              let p = self
                .invoke(&tl::functions::account::GetPassword {})
                .await
                .map_err(|e| issue(e).failure)?;
              self.password = Some(PasswordToken::new(p.into()));
              Err(rpc_failure(400, "PASSWORD_HASH_INVALID", None))
            }
            Err(SignInError::Other(e)) => Err(issue(e).failure),
            _ => Err(rpc_failure(400, "PASSWORD_HASH_INVALID", None)),
          }
        }
        _ => Err(invalid_stage()),
      }
    })
  }
  fn channels(&mut self) -> BoxFut<'_, Result<Vec<Channel>, Failure>> {
    Box::pin(async move {
      let mut dialogs = self.client.iter_dialogs();
      let mut found = Vec::new();
      while let Some(d) = dialogs
        .next()
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
        .map_err(|e| issue(e).failure)?
      {
        if let grammers_client::peer::Peer::Channel(c) = d.peer() {
          let c = &c.raw;
          if !c.min
            && !c.left
            && can_post(
              c.broadcast,
              c.creator,
              c.admin_rights.as_ref().is_some_and(
                |r| matches!(r, tl::enums::ChatAdminRights::Rights(v) if v.post_messages),
              ),
            )
          {
            if let Some(hash) = c.access_hash {
              found.push(Channel {
                id: c.id,
                hash,
                title: c.title.clone(),
              });
            }
          }
        }
      }
      Ok(found)
    })
  }
  fn check_channel<'a>(&'a mut self, c: &'a Channel) -> BoxFut<'a, Result<(), Failure>> {
    Box::pin(async move {
      let result = self
        .invoke(&tl::functions::channels::GetChannels {
          id: vec![c.input()],
        })
        .await
        .map_err(|e| issue(e).failure)?;
      let chats = match result {
        tl::enums::messages::Chats::Chats(v) => v.chats,
        tl::enums::messages::Chats::Slice(v) => v.chats,
      };
      if chats.iter().any(|v| matches!(v,tl::enums::Chat::Channel(v) if v.id==c.id && !v.min && !v.left && can_post(v.broadcast,v.creator,v.admin_rights.as_ref().is_some_and(|r| matches!(r, tl::enums::ChatAdminRights::Rights(v) if v.post_messages))))) {Ok(())}
      else {Err(rpc_failure(403,"CHAT_ADMIN_REQUIRED",None))}
    })
  }
  fn session(&self) -> Result<Value, Failure> {
    let home = self.session.home_dc_id().map_err(|_| local_failure())?;
    let dcs = (1..=5)
      .filter_map(|id| self.session.dc_option(id).ok().flatten())
      .collect::<Vec<_>>();
    Ok(json!({"home":home,"dcs":dcs}))
  }
  fn upload<'a>(
    &'a mut self,
    files: &'a [PathBuf],
    item: &'a Value,
  ) -> BoxFut<'a, Result<Vec<Value>, Failure>> {
    Box::pin(async move {
      let mut result = Vec::new();
      for path in files {
        let uploaded = self
          .client
          .upload_file(path)
          .with_subscriber(tracing::subscriber::NoSubscriber::default())
          .await
          .map_err(|e| {
            if let Some(InvocationError::Rpc(e)) = e
              .get_ref()
              .and_then(|e| e.downcast_ref::<InvocationError>())
            {
              rpc_failure(e.code, &e.name, e.value)
            } else {
              Failure::new(
                "networkLost",
                "Telegram did not finish receiving the file. Nothing was published.",
              )
            }
          })?;
        let media: tl::enums::InputMedia = if is_image(path) {
          tl::types::InputMediaUploadedPhoto {
            spoiler: false,
            live_photo: false,
            file: uploaded.raw,
            stickers: None,
            ttl_seconds: None,
            video: None,
          }
          .into()
        } else {
          let mut attributes = vec![tl::types::DocumentAttributeFilename {
            file_name: path
              .file_name()
              .and_then(|s| s.to_str())
              .unwrap_or("media")
              .into(),
          }
          .into()];
          if is_video(path) {
            attributes.push(
              tl::types::DocumentAttributeVideo {
                round_message: false,
                supports_streaming: false,
                nosound: false,
                duration: item["durationSec"].as_f64().unwrap_or(0.0),
                w: item["width"].as_i64().unwrap_or(0) as i32,
                h: item["height"].as_i64().unwrap_or(0) as i32,
                preload_prefix_size: None,
                video_start_ts: None,
                video_codec: None,
              }
              .into(),
            );
          } else {
            attributes.push(
              tl::types::DocumentAttributeAudio {
                voice: false,
                duration: item["durationSec"].as_i64().unwrap_or(0) as i32,
                title: None,
                performer: None,
                waveform: None,
              }
              .into(),
            );
          }
          tl::types::InputMediaUploadedDocument {
            nosound_video: false,
            force_file: false,
            spoiler: false,
            file: uploaded.raw,
            thumb: None,
            mime_type: mime_of(path).into(),
            attributes,
            stickers: None,
            video_cover: None,
            video_timestamp: None,
            ttl_seconds: None,
          }
          .into()
        };
        result.push(serde_json::to_value(media).map_err(|_| local_failure())?);
      }
      Ok(result)
    })
  }
  fn send<'a>(
    &'a mut self,
    c: &'a Channel,
    media: &'a [Value],
    caption: &'a str,
    random: i64,
  ) -> BoxFut<'a, Result<Vec<Receipt>, RpcIssue>> {
    Box::pin(async move {
      let unknown = || RpcIssue {
        code: None,
        failure: Failure::new(
          "publishedUnverified",
          "Telegram's publishing answer could not be read.",
        ),
      };
      let mut media = media
        .iter()
        .map(|v| serde_json::from_value::<tl::enums::InputMedia>(v.clone()).map_err(|_| unknown()))
        .collect::<Result<Vec<_>, _>>()?;
      let updates = if media.len() > 1 {
        let mut album = Vec::new();
        for (i, m) in media.drain(..).enumerate() {
          // Albums require reusable photo/document references. This call only uploads;
          // it does not publish. No paid options or suggested-post fields are supplied.
          let uploaded = self
            .invoke(&tl::functions::messages::UploadMedia {
              business_connection_id: None,
              peer: c.peer(),
              media: m,
            })
            .await
            .map_err(issue)?;
          let media = match grammers_client::media::Media::from_raw(uploaded)
            .and_then(|m| m.to_raw_input_media())
          {
            Some(m) => m,
            None => return Err(unknown()),
          };
          album.push(
            tl::types::InputSingleMedia {
              media,
              random_id: random.wrapping_add(i as i64),
              message: if i == 0 {
                caption.into()
              } else {
                String::new()
              },
              entities: None,
            }
            .into(),
          );
        }
        self
          .invoke(&tl::functions::messages::SendMultiMedia {
            silent: false,
            background: false,
            clear_draft: false,
            noforwards: false,
            update_stickersets_order: false,
            invert_media: false,
            allow_paid_floodskip: false,
            peer: c.peer(),
            reply_to: None,
            multi_media: album,
            schedule_date: None,
            send_as: None,
            quick_reply_shortcut: None,
            effect: None,
            allow_paid_stars: None,
          })
          .await
          .map_err(issue)?
      } else if let Some(media) = media.pop() {
        self
          .invoke(&tl::functions::messages::SendMedia {
            silent: false,
            background: false,
            clear_draft: false,
            noforwards: false,
            update_stickersets_order: false,
            invert_media: false,
            allow_paid_floodskip: false,
            peer: c.peer(),
            reply_to: None,
            media,
            message: caption.into(),
            random_id: random,
            reply_markup: None,
            entities: None,
            schedule_date: None,
            schedule_repeat_period: None,
            send_as: None,
            quick_reply_shortcut: None,
            effect: None,
            allow_paid_stars: None,
            suggested_post: None,
          })
          .await
          .map_err(issue)?
      } else {
        self
          .invoke(&tl::functions::messages::SendMessage {
            no_webpage: true,
            silent: false,
            background: false,
            clear_draft: false,
            noforwards: false,
            update_stickersets_order: false,
            invert_media: false,
            allow_paid_floodskip: false,
            peer: c.peer(),
            reply_to: None,
            message: caption.into(),
            random_id: random,
            reply_markup: None,
            entities: None,
            schedule_date: None,
            schedule_repeat_period: None,
            send_as: None,
            quick_reply_shortcut: None,
            effect: None,
            allow_paid_stars: None,
            suggested_post: None,
            rich_message: None,
          })
          .await
          .map_err(issue)?
      };
      let updates = match updates {
        tl::enums::Updates::Updates(v) => v.updates,
        tl::enums::Updates::Combined(v) => v.updates,
        _ => return Err(unknown()),
      };
      let mut result = updates
        .into_iter()
        .filter_map(|u| match u {
          tl::enums::Update::NewChannelMessage(v) => receipt(&v.message),
          _ => None,
        })
        .filter(|r| r.channel == c.id)
        .collect::<Vec<_>>();
      result.sort_by_key(|r| r.id);
      if result.is_empty() {
        Err(unknown())
      } else {
        Ok(result)
      }
    })
  }
  fn read<'a>(
    &'a mut self,
    c: &'a Channel,
    expected: &'a [Receipt],
  ) -> BoxFut<'a, Result<Vec<Receipt>, Failure>> {
    Box::pin(async move {
      let result = self
        .invoke(&tl::functions::channels::GetMessages {
          channel: c.input(),
          id: expected
            .iter()
            .map(|r| tl::types::InputMessageId { id: r.id }.into())
            .collect(),
        })
        .await
        .map_err(|e| issue(e).failure)?;
      let messages = match result {
        tl::enums::messages::Messages::Messages(v) => v.messages,
        tl::enums::messages::Messages::Slice(v) => v.messages,
        tl::enums::messages::Messages::ChannelMessages(v) => v.messages,
        _ => Vec::new(),
      };
      let mut found = messages.iter().filter_map(receipt).collect::<Vec<_>>();
      found.sort_by_key(|r| r.id);
      Ok(found)
    })
  }
}
fn receipt(message: &tl::enums::Message) -> Option<Receipt> {
  let tl::enums::Message::Message(m) = message else {
    return None;
  };
  if m.video_processing_pending || !m.post {
    return None;
  }
  let tl::enums::Peer::Channel(peer) = &m.peer_id else {
    return None;
  };
  let (kind, id) = match &m.media {
    Some(tl::enums::MessageMedia::Photo(p)) => match &p.photo {
      Some(tl::enums::Photo::Photo(p)) => ("photo", p.id),
      _ => return None,
    },
    Some(tl::enums::MessageMedia::Document(d)) => match &d.document {
      Some(tl::enums::Document::Document(d)) => {
        if d
          .attributes
          .iter()
          .any(|a| matches!(a, tl::enums::DocumentAttribute::Video(_)))
        {
          ("video", d.id)
        } else if d
          .attributes
          .iter()
          .any(|a| matches!(a, tl::enums::DocumentAttribute::Audio(_)))
        {
          ("audio", d.id)
        } else {
          return None;
        }
      }
      _ => return None,
    },
    None => ("text", 0),
    _ => return None,
  };
  Some(Receipt {
    id: m.id,
    channel: peer.channel_id,
    caption: m.message.clone(),
    media: kind.into(),
    media_id: id,
  })
}

pub struct Telegram {
  api: tokio::sync::Mutex<Option<Box<dyn TelegramApi>>>,
  secret: Value,
  channel: Channel,
  handles: UploadHandles,
}
impl Telegram {
  pub fn new(secret: &Value, handles: PathBuf) -> Option<Self> {
    let channel = serde_json::from_value(secret["channel"].clone()).ok()?;
    secret.get("session")?;
    Some(Self {
      api: tokio::sync::Mutex::new(None),
      secret: secret.clone(),
      channel,
      handles: UploadHandles::new(handles),
    })
  }
  #[cfg(test)]
  fn with_api(api: Box<dyn TelegramApi>, channel: Channel, handles: PathBuf) -> Self {
    Self {
      api: tokio::sync::Mutex::new(Some(api)),
      secret: Value::Null,
      channel,
      handles: UploadHandles::new(handles),
    }
  }
  fn unverified(&self, receipts: &[Receipt], note: &str) -> Published {
    Published {
      dest_item_id: receipts
        .first()
        .map(|r| r.id.to_string())
        .unwrap_or_default(),
      dest_url: receipts
        .first()
        .map(|r| format!("https://t.me/c/{}/{}", self.channel.id, r.id)),
      verified: false,
      note: Some(note.into()),
    }
  }
  async fn run(&self, u: Upload<'_>, control: PublishControl) -> Result<Published, Failure> {
    let caption = body_text(u.post, u.item);
    if caption.encode_utf16().count() > 1024 {
      return Err(Failure::new(
        "textOverLimit",
        "Telegram captions in this Helper allow 1,024 characters. Shorten the caption.",
      ));
    }
    if u.media.len() > 10 || (u.media.len() > 1 && u.media.iter().any(|p| !is_image(p))) {
      return Err(Failure::new(
        "notSupported",
        "Telegram accepts up to ten photos together in this Helper, or one video or audio file.",
      ));
    }
    for p in u.media {
      if !is_image(p) && !is_video(p) && !mime_of(p).starts_with("audio/") {
        return Err(Failure::new(
          "notSupported",
          "Telegram cannot post this file type from the Helper.",
        ));
      }
      let meta = tokio::fs::metadata(p).await.map_err(|_| {
        Failure::new(
          "notFound404",
          "The media file is no longer on this computer.",
        )
      })?;
      let limit = if is_image(p) { 10_000_000 } else { MAX_BYTES };
      if meta.len() > limit {
        return Err(Failure::new(
          "itemTooLarge",
          "This file exceeds the Telegram size limit offered by this Helper.",
        ));
      }
    }
    let saved = self.handles.load(u.idempotency_key);
    if !matches!(saved, Ok(None)) {
      // No receipt means an ambiguous/lost answer, including malformed state. A saved
      // receipt permits only read-back: never upload or send again on this path.
      let handle = saved.ok().flatten().unwrap_or(Value::Null);
      let matches_request = handle["matchesRequest"] == true;
      let receipts =
        serde_json::from_value::<Vec<Receipt>>(handle["receipts"].clone()).unwrap_or_default();
      let mut result = self.unverified(
        &receipts,
        "This item may already be on Telegram. Check the channel before choosing Post again.",
      );
      if matches_request && !receipts.is_empty() {
        let mut api = self.api.lock().await;
        if api.is_none() {
          if let Ok(client) = Gram::configured(Some(&self.secret["session"])) {
            *api = Some(Box::new(client));
          }
        }
        if let Some(api) = api.as_mut() {
          match api.read(&self.channel, &receipts).await {
            Ok(read)
              if read.len() == receipts.len()
                && receipts
                  .iter()
                  .zip(&read)
                  .all(|(s, r)| s.channel == self.channel.id && verified_message(s, r)) =>
            {
              result.verified = true;
              result.note = None;
            }
            Err(e) => result.note = Some(super::unknown_note("Telegram", &e, "posting")),
            _ => {}
          }
        }
      }
      return Ok(result);
    }
    let mut guard = self.api.lock().await;
    if guard.is_none() {
      *guard = Some(Box::new(Gram::configured(Some(&self.secret["session"]))?));
    }
    let api = guard.as_mut().expect("client initialized");
    api.check_channel(&self.channel).await?;
    let media = api.upload(u.media, u.item).await?;
    // Uploading file parts cannot publish. The durable marker precedes messages.sendMedia.
    if !self
      .handles
      .begin(u.idempotency_key, "telegram")
      .map_err(|_| local_failure())?
    {
      return Ok(self.unverified(
        &[],
        "This item may already be on Telegram. Check the channel.",
      ));
    }
    if let Err(e) = control.start_publish() {
      self.handles.release(u.idempotency_key);
      return Err(e);
    }
    let random = random_id(u.idempotency_key);
    self
      .handles
      .save(
        u.idempotency_key,
        &json!({"stage":"publishing","randomId":random}),
      )
      .map_err(|_| local_failure())?;
    let sent = match api.send(&self.channel, &media, &caption, random).await {
      Ok(sent) => sent,
      Err(e) if rpc_refused(e.code) => {
        self.handles.release(u.idempotency_key);
        return Err(e.failure);
      }
      Err(e) => {
        return Ok(self.unverified(&[], &super::unknown_note("Telegram", &e.failure, "posting")))
      }
    };
    let kinds = u
      .media
      .iter()
      .map(|p| {
        if is_image(p) {
          "photo"
        } else if is_video(p) {
          "video"
        } else {
          "audio"
        }
      })
      .collect::<Vec<_>>();
    let shape = sent.len() == u.media.len().max(1)
      && sent.iter().enumerate().all(|(i, r)| {
        r.channel == self.channel.id
          && r.caption == if i == 0 { caption.as_str() } else { "" }
          && r.media == kinds.get(i).copied().unwrap_or("text")
          && (r.media == "text" || r.media_id != 0)
      });
    if self
      .handles
      .save(
        u.idempotency_key,
        &json!({"stage":"sent","randomId":random,"receipts":sent,"matchesRequest":shape}),
      )
      .is_err()
    {
      return Ok(self.unverified(&sent,"Telegram may have posted this item. The Helper couldn't save its message ID. Check the channel."));
    }
    let (verified,note)=match api.read(&self.channel,&sent).await {
      Ok(read)=>(shape && read.len()==sent.len() && sent.iter().zip(&read).all(|(s,r)|verified_message(s,r)),"Telegram's channel read-back did not confirm the same message, caption and media. Check the channel before posting again.".into()),
      Err(e)=>(false,super::unknown_note("Telegram",&e,"posting")),
    };
    let mut result = self.unverified(&sent, &note);
    result.verified = verified;
    if verified {
      result.note = None;
    }
    Ok(result)
  }
}
impl Uploader for Telegram {
  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let (_tx, rx) = tokio::sync::watch::channel(false);
      self.run(u, PublishControl::new(rx)).await
    })
  }
  fn publish_controlled<'a>(
    &'a self,
    u: Upload<'a>,
    control: PublishControl,
  ) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(self.run(u, control))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn telegram_refusal_table_matches_d069() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      assert_eq!(rpc_refused(Some(code as i32)), freed, "{code}");
    }
    for code in [None, Some(420), Some(406), Some(303), Some(402)] {
      assert!(!rpc_refused(code));
    }
  }

  #[test]
  fn telegram_random_id_survives_restart_and_deduplicates() {
    let first = random_id("telegram|channel-1|source|item-1");
    assert_ne!(first, 0);
    assert_eq!(first, random_id("telegram|channel-1|source|item-1"));
    assert_ne!(first, random_id("telegram|channel-2|source|item-1"));
    let dir = tempfile::tempdir().unwrap();
    let key = "telegram|channel-1|source|item-1";
    let handles = UploadHandles::new(dir.path().join("handles"));
    assert!(handles.begin(key, "telegram").unwrap());
    handles
      .save(key, &json!({"stage":"publishing","randomId":first}))
      .unwrap();
    let restarted = UploadHandles::new(dir.path().join("handles"));
    assert_eq!(restarted.load(key).unwrap().unwrap()["randomId"], first);
    assert!(!restarted.begin(key, "telegram").unwrap());
    let ledger = crate::posted::Posted::open(dir.path().join("posted.json"));
    assert!(matches!(
      ledger.reserve(key, "t"),
      crate::posted::Seen::Clear
    ));
    ledger.finish(key, Some(json!({"state":"publishedUnverified"})));
    let ledger = crate::posted::Posted::open(dir.path().join("posted.json"));
    assert!(matches!(
      ledger.reserve(key, "t"),
      crate::posted::Seen::Posted(_)
    ));
  }

  #[test]
  fn telegram_errors_never_include_phone_code_or_password() {
    for secret in ["+15551234567", "123456", "two-factor-secret"] {
      let e = rpc_failure(400, &format!("PHONE_CODE_INVALID {secret}"), Some(123));
      assert!(!format!("{e:?}").contains(secret));
    }
    let e = rpc_failure(420, "FLOOD_WAIT", Some(120));
    assert_eq!(e.verbatim.as_deref(), Some("FLOOD_WAIT_120"));
    assert_eq!(e.code, "rateLimited429");
  }

  #[test]
  fn telegram_connect_requires_channel_posting_rights() {
    for (broadcast, creator, post_rights, allowed) in [
      (true, true, false, true),
      (true, false, true, true),
      (true, false, false, false),
      (false, true, true, false),
    ] {
      assert_eq!(can_post(broadcast, creator, post_rights), allowed);
    }
  }

  #[test]
  fn telegram_channel_readback_verifies_media() {
    let sent = Receipt {
      id: 42,
      channel: 7,
      caption: "Caption".into(),
      media: "photo".into(),
      media_id: 99,
    };
    assert!(verified_message(&sent, &sent));
    for wrong in [
      Receipt {
        id: 43,
        ..sent.clone()
      },
      Receipt {
        channel: 8,
        ..sent.clone()
      },
      Receipt {
        caption: "Different".into(),
        ..sent.clone()
      },
      Receipt {
        media: "video".into(),
        ..sent.clone()
      },
      Receipt {
        media_id: 100,
        ..sent.clone()
      },
    ] {
      assert!(!verified_message(&sent, &wrong));
    }
  }

  #[test]
  fn telegram_session_stays_out_of_connection_list_and_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::connections::Store::open(
      dir.path().join("connections.json"),
      Box::new(crate::connections::MemorySecrets::default()),
    );
    let secret = json!({"channelId":"7", "session":{"authKey":"session-only-key"}});
    let c = store
      .save(
        crate::connections::Connection {
          id: "telegram-test".into(),
          platform: "telegram".into(),
          label: "Channel".into(),
          path: "api".into(),
          checked_at: "t".into(),
          choices: Default::default(),
          account: String::new(),
        },
        &secret,
      )
      .unwrap();
    assert_eq!(store.secret(&c.id).unwrap(), secret);
    let disk = std::fs::read_to_string(dir.path().join("connections.json")).unwrap();
    assert!(!disk.contains("session-only-key"));
    assert!(!disk.contains("authKey"));
  }
}

#[cfg(test)]
pub(crate) mod flow_tests {
  use super::*;
  use crate::hops::Uploader;
  use std::sync::atomic::{AtomicUsize, Ordering};

  struct Fake {
    two_factor: bool,
    error: Option<i32>,
    read_wrong: bool,
    send_wrong: bool,
    sends: Arc<AtomicUsize>,
    steps: Arc<std::sync::Mutex<Vec<String>>>,
    auth_error: Option<(&'static str, &'static str)>,
    auth_fails: Arc<AtomicUsize>,
  }
  impl TelegramApi for Fake {
    fn auth<'a>(
      &'a mut self,
      stage: &'a str,
      _value: &'a str,
    ) -> BoxFut<'a, Result<&'static str, Failure>> {
      Box::pin(async move {
        self.steps.lock().unwrap().push(stage.into());
        if let Some((at, name)) = self.auth_error {
          if stage == at && self.auth_fails.load(Ordering::SeqCst) > 0 {
            self.auth_fails.fetch_sub(1, Ordering::SeqCst);
            return Err(rpc_failure(
              if name == "FLOOD_WAIT" { 420 } else { 400 },
              name,
              Some(120),
            ));
          }
        }
        Ok(match stage {
          "phone" => "code",
          "code" if self.two_factor => "password",
          _ => "channel",
        })
      })
    }
    fn channels(&mut self) -> BoxFut<'_, Result<Vec<Channel>, Failure>> {
      Box::pin(async {
        Ok(vec![Channel {
          id: 7,
          hash: 77,
          title: "Channel".into(),
        }])
      })
    }
    fn check_channel<'a>(&'a mut self, _c: &'a Channel) -> BoxFut<'a, Result<(), Failure>> {
      Box::pin(async { Ok(()) })
    }
    fn session(&self) -> Result<Value, Failure> {
      Ok(json!({"home":2,"dcs":[]}))
    }
    fn upload<'a>(
      &'a mut self,
      files: &'a [PathBuf],
      _item: &'a Value,
    ) -> BoxFut<'a, Result<Vec<Value>, Failure>> {
      Box::pin(async move {
        Ok(
          files
            .iter()
            .map(|p| json!({"file":p.extension().unwrap().to_str().unwrap()}))
            .collect(),
        )
      })
    }
    fn send<'a>(
      &'a mut self,
      c: &'a Channel,
      media: &'a [Value],
      caption: &'a str,
      _random: i64,
    ) -> BoxFut<'a, Result<Vec<Receipt>, RpcIssue>> {
      Box::pin(async move {
        self.sends.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = self.error {
          return Err(RpcIssue {
            code: Some(code),
            failure: rpc_failure(code, "TEST_ERROR", None),
          });
        }
        Ok(vec![Receipt {
          id: 42,
          channel: c.id,
          caption: if self.send_wrong {
            "Wrong caption".into()
          } else {
            caption.into()
          },
          media: if media.first().is_some_and(|v| v["file"] == "mp4") {
            "video"
          } else {
            "photo"
          }
          .into(),
          media_id: 99,
        }])
      })
    }
    fn read<'a>(
      &'a mut self,
      _c: &'a Channel,
      expected: &'a [Receipt],
    ) -> BoxFut<'a, Result<Vec<Receipt>, Failure>> {
      Box::pin(async move {
        let mut r = expected.to_vec();
        if self.read_wrong {
          r[0].media_id = 100;
        }
        Ok(r)
      })
    }
  }
  fn fake(two_factor: bool, error: Option<i32>, read_wrong: bool) -> Fake {
    Fake {
      two_factor,
      error,
      read_wrong,
      send_wrong: false,
      sends: Arc::default(),
      steps: Arc::default(),
      auth_error: None,
      auth_fails: Arc::new(AtomicUsize::new(usize::MAX)),
    }
  }

  pub(crate) fn local_test_api(two_factor: bool) -> Box<dyn TelegramApi> {
    Box::new(fake(two_factor, None, false))
  }

  #[tokio::test]
  async fn telegram_phone_code_and_two_factor_remain_on_device() {
    for two_factor in [false, true] {
      let api = fake(two_factor, None, false);
      let steps = api.steps.clone();
      let mut flow = SignIn::new(Box::new(api));
      assert_eq!(
        flow.advance("phone", "+15551234567").await.unwrap()["stage"],
        "code"
      );
      assert!(flow.advance("password", "early-secret").await.is_err());
      let next = flow.advance("code", "123456").await.unwrap();
      if two_factor {
        assert_eq!(next["stage"], "password");
        assert_eq!(
          flow.advance("password", "two-factor-secret").await.unwrap()["stage"],
          "channel"
        );
      } else {
        assert_eq!(next["stage"], "channel");
      }
      assert_eq!(
        *steps.lock().unwrap(),
        if two_factor {
          vec!["phone", "code", "password"]
        } else {
          vec!["phone", "code"]
        }
      );
      let (title, secret) = flow.finish("7").await.unwrap();
      assert_eq!(title, "Channel");
      assert_eq!(secret["channelId"], "7");
      for s in [
        "+15551234567",
        "123456",
        "early-secret",
        "two-factor-secret",
      ] {
        assert!(!secret.to_string().contains(s));
      }
    }
  }

  #[tokio::test]
  async fn telegram_expired_code_and_flood_wait_do_not_loop() {
    let mut flow = SignIn::new(Box::new(fake(false, None, false)));
    flow.created = std::time::Instant::now() - SIGN_IN_TTL;
    assert_eq!(
      flow
        .advance("phone", "+15551234567")
        .await
        .unwrap_err()
        .code,
      "signInRequired"
    );
    for (at, name) in [("code", "PHONE_CODE_EXPIRED"), ("phone", "FLOOD_WAIT")] {
      let mut api = fake(false, None, false);
      api.auth_error = Some((at, name));
      let steps = api.steps.clone();
      let mut flow = SignIn::new(Box::new(api));
      if at == "code" {
        flow.advance("phone", "+15551234567").await.unwrap();
      }
      assert!(flow.advance(at, "123456").await.is_err());
      let count = steps.lock().unwrap().len();
      assert!(flow.advance(at, "123456").await.is_err());
      assert_eq!(
        steps.lock().unwrap().len(),
        count,
        "no second provider call after a refusal"
      );
    }
    let expired = rpc_failure(400, "PHONE_CODE_EXPIRED", None);
    assert_eq!(expired.verbatim.as_deref(), Some("PHONE_CODE_EXPIRED"));
    let limited = rpc_failure(420, "FLOOD_WAIT", Some(120));
    assert_eq!(limited.verbatim.as_deref(), Some("FLOOD_WAIT_120"));
    assert_eq!(limited.code, "rateLimited429");
  }

  #[tokio::test]
  async fn telegram_mistyped_code_or_password_can_be_retyped_without_a_new_code() {
    for (two_factor, at, name) in [
      (false, "code", "PHONE_CODE_INVALID"),
      (true, "password", "PASSWORD_HASH_INVALID"),
    ] {
      let mut api = fake(two_factor, None, false);
      api.auth_error = Some((at, name));
      api.auth_fails.store(1, Ordering::SeqCst);
      let steps = api.steps.clone();
      let mut flow = SignIn::new(Box::new(api));
      flow.advance("phone", "+15551234567").await.unwrap();
      if two_factor {
        flow.advance("code", "123456").await.unwrap();
      }
      let retry = flow.advance(at, "wrong-entry").await.unwrap();
      assert_eq!(retry["stage"], at);
      assert!(retry["error"].as_str().unwrap().contains(name));
      assert!(!retry.to_string().contains("wrong-entry"));
      assert_eq!(
        flow.advance(at, "right-entry").await.unwrap()["stage"],
        "channel"
      );
      let calls = steps.lock().unwrap().clone();
      assert_eq!(
        calls.iter().filter(|s| *s == "phone").count(),
        1,
        "no second code request"
      );
    }
    let mut api = fake(false, None, false);
    api.auth_error = Some(("code", "PHONE_CODE_INVALID"));
    let steps = api.steps.clone();
    let mut flow = SignIn::new(Box::new(api));
    flow.advance("phone", "+15551234567").await.unwrap();
    for _ in 0..2 {
      assert_eq!(
        flow.advance("code", "000000").await.unwrap()["stage"],
        "code"
      );
    }
    assert_eq!(
      flow.advance("code", "000000").await.unwrap_err().code,
      "signInRequired"
    );
    let count = steps.lock().unwrap().len();
    assert!(flow.advance("code", "000000").await.is_err());
    assert_eq!(
      steps.lock().unwrap().len(),
      count,
      "stopped after three tries"
    );
  }

  #[test]
  fn telegram_payment_required_stops_without_payment() {
    for name in [
      "PHONE_NUMBER_APP_SIGNUP_FORBIDDEN",
      "PREMIUM_ACCOUNT_REQUIRED",
      "ALLOW_PAYMENT_REQUIRED",
      "STARS_PAYMENT_REQUIRED",
    ] {
      assert_eq!(rpc_failure(403, name, None).code, "notSupported");
    }
  }

  #[tokio::test]
  async fn telegram_photo_and_video_use_user_media_upload() {
    for ext in ["jpg", "mp4"] {
      let dir = tempfile::tempdir().unwrap();
      let file = dir.path().join(format!("media.{ext}"));
      std::fs::write(&file, b"media").unwrap();
      let api = fake(false, None, false);
      let sends = api.sends.clone();
      let u = Telegram::with_api(
        Box::new(api),
        Channel {
          id: 7,
          hash: 77,
          title: "Channel".into(),
        },
        dir.path().join("handles"),
      );
      let item = json!({"id":"item-1","title":"Caption"});
      let files = vec![file];
      let result = u
        .publish(Upload {
          item: &item,
          post: None,
          media: &files,
          idempotency_key: "key",
          options: &Value::Null,
        })
        .await
        .unwrap();
      assert!(result.verified);
      assert_eq!(result.dest_item_id, "42");
      assert_eq!(sends.load(Ordering::SeqCst), 1);
      assert!(!u.safe_to_retry());
    }
  }

  #[tokio::test]
  async fn telegram_publish_refusal_table_and_lost_answer_never_reposts() {
    for (code, freed) in crate::uploaders::testkit::REFUSAL_TABLE {
      let dir = tempfile::tempdir().unwrap();
      let file = dir.path().join("media.jpg");
      std::fs::write(&file, b"photo").unwrap();
      let api = fake(false, Some(i32::from(code)), false);
      let sends = api.sends.clone();
      let u = Telegram::with_api(
        Box::new(api),
        Channel {
          id: 7,
          hash: 77,
          title: "Channel".into(),
        },
        dir.path().join("handles"),
      );
      let item = json!({"id":"one","title":"Caption"});
      let files = vec![file];
      let result = u
        .publish(Upload {
          item: &item,
          post: None,
          media: &files,
          idempotency_key: "key",
          options: &Value::Null,
        })
        .await;
      if freed {
        assert!(result.is_err(), "{code}");
        assert!(u.handles.load("key").unwrap().is_none());
      } else {
        assert!(!result.unwrap().verified, "{code}");
        let again = u
          .publish(Upload {
            item: &item,
            post: None,
            media: &files,
            idempotency_key: "key",
            options: &Value::Null,
          })
          .await
          .unwrap();
        assert!(!again.verified);
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        let restart = Telegram::with_api(
          Box::new(fake(false, None, false)),
          Channel {
            id: 7,
            hash: 77,
            title: "Channel".into(),
          },
          dir.path().join("handles"),
        );
        assert!(
          !restart
            .publish(Upload {
              item: &item,
              post: None,
              media: &files,
              idempotency_key: "key",
              options: &Value::Null
            })
            .await
            .unwrap()
            .verified
        );
      }
    }
  }

  #[tokio::test]
  async fn telegram_stop_before_publish_sends_nothing_and_releases_marker() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("media.jpg");
    std::fs::write(&file, b"photo").unwrap();
    let api = fake(false, None, false);
    let sends = api.sends.clone();
    let uploader = Telegram::with_api(
      Box::new(api),
      Channel {
        id: 7,
        hash: 77,
        title: "Channel".into(),
      },
      dir.path().join("handles"),
    );
    let item = json!({"id":"one","title":"Caption"});
    let files = vec![file];
    let (_stop, rx) = tokio::sync::watch::channel(true);
    let result = uploader
      .publish_controlled(
        Upload {
          item: &item,
          post: None,
          media: &files,
          idempotency_key: "key",
          options: &Value::Null,
        },
        PublishControl::new(rx),
      )
      .await
      .unwrap_err();
    assert_eq!(result.code, "stopped");
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert!(uploader.handles.load("key").unwrap().is_none());
  }

  #[test]
  fn telegram_default_daily_cap_spreads_later_posts() {
    // The schema lives in `packages/schemas` in the monorepo and is copied to
    // `fixtures/schemas` in the published Helper source (scripts/publish-helper.sh).
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mono = root.join("../../packages/schemas/destinations/telegram.json");
    let path = if mono.is_file() {
      mono
    } else {
      root.join("fixtures/schemas/telegram.json")
    };
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(schema["dailyCapDefault"], 30);
    let pace = crate::pacing::Pace::from_plan(
      &json!({"pace":{"dailyCap":schema["dailyCapDefault"]}}),
      None,
    );
    let usage = crate::pacing::Usage {
      day: 0,
      count: 30,
      last: 60_000,
    };
    assert!(crate::pacing::next_slot(&pace, Some(&usage), 60_000, 0) >= 24 * 60 * 60 * 1000);
  }

  #[tokio::test]
  async fn telegram_mismatched_send_answer_cannot_become_verified_on_repeat() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("media.jpg");
    std::fs::write(&file, b"photo").unwrap();
    let mut api = fake(false, None, false);
    api.send_wrong = true;
    let sends = api.sends.clone();
    let uploader = Telegram::with_api(
      Box::new(api),
      Channel {
        id: 7,
        hash: 77,
        title: "Channel".into(),
      },
      dir.path().join("handles"),
    );
    let item = json!({"id":"one","title":"Caption"});
    let files = vec![file];
    for _ in 0..2 {
      let published = uploader
        .publish(Upload {
          item: &item,
          post: None,
          media: &files,
          idempotency_key: "key",
          options: &Value::Null,
        })
        .await
        .unwrap();
      assert!(
        !published.verified,
        "a mismatched send response must stay unverified"
      );
    }
    assert_eq!(sends.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn telegram_readback_mismatch_is_unverified_without_repost() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("media.jpg");
    std::fs::write(&file, b"photo").unwrap();
    let api = fake(false, None, true);
    let sends = api.sends.clone();
    let u = Telegram::with_api(
      Box::new(api),
      Channel {
        id: 7,
        hash: 77,
        title: "Channel".into(),
      },
      dir.path().join("handles"),
    );
    let item = json!({"id":"one","title":"Caption"});
    let files = vec![file];
    for _ in 0..2 {
      assert!(
        !u.publish(Upload {
          item: &item,
          post: None,
          media: &files,
          idempotency_key: "key",
          options: &Value::Null
        })
        .await
        .unwrap()
        .verified
      );
    }
    assert_eq!(sends.load(Ordering::SeqCst), 1);
  }
}

#[cfg(test)]
mod transport_tests {
  use super::*;

  #[tokio::test]
  async fn telegram_paid_code_response_stops_without_a_session_or_resend() {
    let mut gram = Gram::new(1, "0".repeat(32), None).unwrap();
    let response = tl::types::auth::SentCodePaymentRequired {
      store_product: "unavailable".into(),
      phone_code_hash: "ephemeral-code-hash".into(),
      support_email_address: "unavailable@example.invalid".into(),
      support_email_subject: "unavailable".into(),
      premium_days: 1,
      currency: "USD".into(),
      amount: 1,
    };
    let result = gram
      .accept_sent_code("+15551234567", response.into())
      .unwrap_err();
    assert_eq!(result.code, "notSupported");
    assert!(gram.login.is_none());
    assert!(gram.password.is_none());
    let observable = format!("{result:?}{}", gram.session().unwrap());
    assert!(!observable.contains("+15551234567") && !observable.contains("ephemeral-code-hash"));
  }

  #[test]
  fn telegram_configured_retry_policy_never_sleeps_or_retries() {
    use grammers_mtsender::{RetryContext, RetryPolicy, RpcError};
    for name in ["FLOOD_WAIT", "FLOOD_PREMIUM_WAIT", "SLOWMODE_WAIT"] {
      let context = RetryContext {
        fail_count: std::num::NonZeroU32::new(1).unwrap(),
        slept_so_far: Duration::ZERO,
        error: InvocationError::Rpc(RpcError {
          code: 420,
          name: name.into(),
          value: Some(120),
          caused_by: None,
        }),
      };
      assert!(matches!(
        NoRetries.should_retry(&context),
        std::ops::ControlFlow::Break(())
      ));
    }
  }

  #[tokio::test]
  async fn telegram_session_round_trips_only_dc_keys_in_memory() {
    let gram = Gram::new(1, "0".repeat(32), None).unwrap();
    let home = gram.session.home_dc_id().unwrap();
    let mut option = gram.session.dc_option(home).unwrap().unwrap();
    option.auth_key = Some([17; 256]);
    gram.session.set_dc_option(&option).await.unwrap();
    let exported = gram.session().unwrap();
    let restored = Gram::new(1, "0".repeat(32), Some(&exported)).unwrap();
    assert_eq!(restored.session().unwrap(), exported);
    for field in ["phone", "password", "code", "api_hash"] {
      assert!(!exported.to_string().contains(field));
    }
  }
}

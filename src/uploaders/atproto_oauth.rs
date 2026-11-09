//! Bluesky / AT Protocol OAuth: the creator types their handle and approves BunnieHop on their
//! own server's sign-in page. No app password.
//!
//! BunnieHop is a confidential client: api.bunniehop.party publishes the client metadata and
//! signs 60-second client assertions (apps/worker/src/atproto.ts). Everything else happens
//! here: handle → DID → PDS → authorization server, PAR with PKCE, the code exchange, refresh,
//! and a DPoP proof (a P-256 key made for this connection, kept in the keychain) on every call.
//! Tokens never reach BunnieHop's servers (D8).

use super::{json_or_fail, net, status_failure, Endpoints};
use crate::hops::Failure;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const P: &str = "Bluesky";
pub const SCOPE: &str = "atproto transition:generic";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub fn client_id(ep: &Endpoints) -> String {
  format!("{}/oauth/bluesky/client-metadata.json", ep.worker)
}

pub fn redirect_uri(ep: &Endpoints) -> String {
  format!("{}/oauth/bluesky/callback", ep.worker)
}

fn b64(b: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(b)
}

fn now_s() -> i64 {
  crate::pacing::now_ms() / 1000
}

/// The connection's DPoP key: tokens only work together with proofs signed by it.
pub struct Dpop(SigningKey);

impl Dpop {
  pub fn generate() -> Self {
    loop {
      if let Ok(k) = SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
        return Self(k);
      }
    }
  }

  pub fn from_secret(s: &str) -> Option<Self> {
    SigningKey::from_slice(&hex::decode(s).ok()?).ok().map(Self)
  }

  pub fn secret(&self) -> String {
    hex::encode(self.0.to_bytes())
  }

  fn jwk(&self) -> Value {
    let pt = self.0.verifying_key().to_sec1_point(false);
    json!({
      "kty": "EC", "crv": "P-256",
      "x": b64(pt.x().map(|x| x.as_slice()).unwrap_or_default()),
      "y": b64(pt.y().map(|y| y.as_slice()).unwrap_or_default()),
    })
  }

  /// RFC 9449 proof for one request (`ath` binds it to the access token at the PDS).
  pub fn proof(&self, htm: &str, url: &str, nonce: Option<&str>, access: Option<&str>) -> String {
    let htu = url.split(['?', '#']).next().unwrap_or(url);
    let h = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk() });
    let mut c = json!({ "jti": uuid::Uuid::new_v4().simple().to_string(), "htm": htm, "htu": htu, "iat": now_s() });
    if let Some(n) = nonce {
      c["nonce"] = json!(n);
    }
    if let Some(a) = access {
      c["ath"] = json!(b64(&Sha256::digest(a.as_bytes())));
    }
    let input = format!(
      "{}.{}",
      b64(h.to_string().as_bytes()),
      b64(c.to_string().as_bytes())
    );
    let sig: Signature = self.0.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
  }
}

/// https only, except loopback (tests and local servers).
fn safe_url(u: &str) -> Result<String, Failure> {
  let t = u.trim().trim_end_matches('/');
  let ok = t.starts_with("https://") || t.starts_with("http://127.0.0.1:");
  ok.then(|| t.to_string()).ok_or_else(|| {
    Failure::new(
      "signInRequired",
      "That Bluesky server's address isn't secure (https).",
    )
  })
}

/// `@mara.bsky.social` / `did:plc:…` → (did, pds).
pub async fn resolve(
  http: &reqwest::Client,
  ep: &Endpoints,
  handle: &str,
) -> Result<(String, String), Failure> {
  let h = handle.trim().trim_start_matches('@').to_ascii_lowercase();
  let did = if h.starts_with("did:") {
    h.clone()
  } else {
    let v = json_or_fail(
      P,
      http
        .get(format!(
          "{}/xrpc/com.atproto.identity.resolveHandle",
          ep.bsky_public
        ))
        .query(&[("handle", h.as_str())])
        .send()
        .await,
    )
    .await
    .map_err(|f| Failure {
      code: "signInRequired",
      message: format!("Bluesky doesn't know the handle @{h}. Check the spelling."),
      verbatim: f.verbatim,
    })?;
    v["did"].as_str().unwrap_or("").to_string()
  };
  let doc_url = if let Some(rest) = did.strip_prefix("did:web:") {
    format!("https://{}/.well-known/did.json", rest.replace("%3A", ":"))
  } else if did.starts_with("did:plc:") {
    format!("{}/{did}", ep.plc)
  } else {
    return Err(Failure::new(
      "signInRequired",
      "That isn't a Bluesky account.",
    ));
  };
  let doc = json_or_fail(P, http.get(doc_url).send().await).await?;
  let pds = doc["service"]
    .as_array()
    .into_iter()
    .flatten()
    .find(|s| {
      s["id"]
        .as_str()
        .is_some_and(|i| i.ends_with("#atproto_pds"))
    })
    .and_then(|s| s["serviceEndpoint"].as_str())
    .ok_or_else(|| Failure::new("signInRequired", "That account has no Bluesky server."))?;
  Ok((did, safe_url(pds)?))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthServer {
  pub issuer: String,
  pub par: String,
  pub authorize: String,
  pub token: String,
}

pub async fn auth_server(http: &reqwest::Client, pds: &str) -> Result<AuthServer, Failure> {
  let pr = json_or_fail(
    P,
    http
      .get(format!("{pds}/.well-known/oauth-protected-resource"))
      .send()
      .await,
  )
  .await?;
  let issuer = safe_url(pr["authorization_servers"][0].as_str().unwrap_or(""))?;
  let m = json_or_fail(
    P,
    http
      .get(format!("{issuer}/.well-known/oauth-authorization-server"))
      .send()
      .await,
  )
  .await?;
  let field = |k: &str| safe_url(m[k].as_str().unwrap_or(""));
  if m["issuer"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer.as_str()) {
    return Err(Failure::new(
      "signInRequired",
      "That Bluesky server's sign-in doesn't match.",
    ));
  }
  Ok(AuthServer {
    issuer,
    par: field("pushed_authorization_request_endpoint")?,
    authorize: field("authorization_endpoint")?,
    token: field("token_endpoint")?,
  })
}

async fn assertion(http: &reqwest::Client, ep: &Endpoints, aud: &str) -> Result<String, Failure> {
  let v = json_or_fail(
    "BunnieHop",
    http
      .post(format!("{}/v1/oauth/bluesky/assertion", ep.worker))
      .json(&json!({ "aud": aud }))
      .send()
      .await,
  )
  .await?;
  v["assertion"]
    .as_str()
    .map(str::to_string)
    .ok_or_else(|| Failure::new("server5xx", "BunnieHop's sign-in service didn't answer."))
}

/// A form POST to the auth server with DPoP (one retry with the server's nonce) and a fresh
/// client assertion each attempt (assertions are single-use).
async fn post_as(
  http: &reqwest::Client,
  ep: &Endpoints,
  dpop: &Dpop,
  srv: &AuthServer,
  url: &str,
  form: &[(&str, String)],
  nonce: &Mutex<Option<String>>,
) -> Result<Value, Failure> {
  for attempt in 0..2 {
    let a = assertion(http, ep, &srv.issuer).await?;
    let mut f: Vec<(&str, String)> = form.to_vec();
    f.push(("client_id", client_id(ep)));
    f.push(("client_assertion_type", ASSERTION_TYPE.into()));
    f.push(("client_assertion", a));
    let n = nonce.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let r = http
      .post(url)
      .header("DPoP", dpop.proof("POST", url, n.as_deref(), None))
      .form(&f)
      .send()
      .await
      .map_err(|e| net(P, e))?;
    if let Some(n) = r.headers().get("dpop-nonce").and_then(|v| v.to_str().ok()) {
      *nonce.lock().unwrap_or_else(|e| e.into_inner()) = Some(n.to_string());
    }
    let status = r.status();
    let text = r.text().await.map_err(|e| net(P, e))?;
    if status.is_success() {
      return serde_json::from_str(&text).map_err(|_| status_failure(P, status, &text));
    }
    if attempt == 0 && text.contains("use_dpop_nonce") {
      continue;
    }
    return Err(status_failure(P, status, &text));
  }
  Err(Failure::new(
    "signInRequired",
    "Bluesky's server kept refusing the sign-in.",
  ))
}

/// A sign-in waiting for the creator to approve on their server's page.
pub struct Pending {
  pub dpop: Dpop,
  pub srv: AuthServer,
  pub verifier: String,
  pub did: String,
  pub pds: String,
  pub nonce: Mutex<Option<String>>,
}

/// Resolves the account, pushes the request (PAR) and returns the page to open.
pub async fn begin(
  http: &reqwest::Client,
  ep: &Endpoints,
  handle: &str,
  state: &str,
) -> Result<(String, Pending), Failure> {
  let (did, pds) = resolve(http, ep, handle).await?;
  let srv = auth_server(http, &pds).await?;
  let dpop = Dpop::generate();
  let verifier = b64(&rand::random::<[u8; 32]>());
  let challenge = b64(&Sha256::digest(verifier.as_bytes()));
  let nonce = Mutex::new(None);
  let mut form = vec![
    ("response_type", "code".to_string()),
    ("redirect_uri", redirect_uri(ep)),
    ("scope", SCOPE.into()),
    ("state", state.into()),
    ("code_challenge", challenge),
    ("code_challenge_method", "S256".into()),
  ];
  let h = handle.trim().trim_start_matches('@').to_ascii_lowercase();
  if !h.starts_with("did:") {
    form.push(("login_hint", h));
  }
  let par = post_as(http, ep, &dpop, &srv, &srv.par, &form, &nonce).await?;
  let req = par["request_uri"].as_str().ok_or_else(|| {
    Failure::new(
      "signInRequired",
      "Bluesky's server didn't start the sign-in.",
    )
  })?;
  let url = format!(
    "{}?client_id={}&request_uri={}",
    srv.authorize,
    super::ghost::urlencode(&client_id(ep)),
    super::ghost::urlencode(req)
  );
  Ok((
    url,
    Pending {
      dpop,
      srv,
      verifier,
      did,
      pds,
      nonce,
    },
  ))
}

/// Trades the code for DPoP-bound tokens; returns the secret to keep.
pub async fn finish(
  http: &reqwest::Client,
  ep: &Endpoints,
  p: Pending,
  code: &str,
  iss: Option<&str>,
) -> Result<Value, Failure> {
  if iss.map(|i| i.trim_end_matches('/')) != Some(p.srv.issuer.as_str()) {
    return Err(Failure::new(
      "signInRequired",
      "The sign-in came back from a different server. Try again.",
    ));
  }
  let form = [
    ("grant_type", "authorization_code".to_string()),
    ("code", code.to_string()),
    ("redirect_uri", redirect_uri(ep)),
    ("code_verifier", p.verifier.clone()),
  ];
  let t = post_as(http, ep, &p.dpop, &p.srv, &p.srv.token, &form, &p.nonce).await?;
  if t["sub"].as_str() != Some(p.did.as_str())
    || !t["scope"]
      .as_str()
      .unwrap_or("")
      .split(' ')
      .any(|s| s == "atproto")
  {
    return Err(Failure::new(
      "signInRequired",
      "Bluesky signed in a different account. Try again.",
    ));
  }
  Ok(json!({
    "oauth": true,
    "did": p.did,
    "pds": p.pds,
    "server": p.srv,
    "dpopKey": p.dpop.secret(),
    "accessToken": t["access_token"],
    "refreshToken": t["refresh_token"],
    "expiresAt": now_s() + t["expires_in"].as_i64().unwrap_or(300),
  }))
}

/// Body of a PDS call; kept in memory so a nonce retry can resend it (images are ≤1 MB).
pub enum Body {
  None,
  Json(Value),
  Bytes(Vec<u8>, &'static str),
}

/// A signed-in connection: DPoP on every PDS call, refresh when the access token runs out, the
/// rotated refresh token saved back to the keychain.
pub struct Session {
  http: reqwest::Client,
  ep: Endpoints,
  store: Arc<crate::connections::Store>,
  conn_id: String,
  dpop: Dpop,
  srv: AuthServer,
  secret: Mutex<Value>,
  pds_nonce: Mutex<Option<String>>,
  as_nonce: Mutex<Option<String>>,
  refreshing: tokio::sync::Mutex<()>,
  pub did: String,
  pub pds: String,
}

impl Session {
  pub fn new(
    http: reqwest::Client,
    ep: &Endpoints,
    store: Arc<crate::connections::Store>,
    conn_id: String,
    secret: &Value,
  ) -> Option<Self> {
    Some(Self {
      dpop: Dpop::from_secret(secret["dpopKey"].as_str()?)?,
      srv: serde_json::from_value(secret["server"].clone()).ok()?,
      did: secret["did"].as_str()?.to_string(),
      pds: secret["pds"].as_str()?.to_string(),
      secret: Mutex::new(secret.clone()),
      http,
      ep: ep.clone(),
      store,
      conn_id,
      pds_nonce: Mutex::new(None),
      as_nonce: Mutex::new(None),
      refreshing: tokio::sync::Mutex::new(()),
    })
  }

  fn current(&self) -> Value {
    self
      .secret
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .clone()
  }

  async fn refresh(&self, seen: &str) -> Result<(), Failure> {
    let _g = self.refreshing.lock().await;
    let s = self.current();
    if s["accessToken"].as_str() != Some(seen) {
      return Ok(()); // another call already refreshed
    }
    let form = [
      ("grant_type", "refresh_token".to_string()),
      (
        "refresh_token",
        s["refreshToken"].as_str().unwrap_or("").to_string(),
      ),
    ];
    let t = post_as(
      &self.http,
      &self.ep,
      &self.dpop,
      &self.srv,
      &self.srv.token,
      &form,
      &self.as_nonce,
    )
    .await
    .map_err(|f| {
      if f.code == "networkLost" || f.code == "server5xx" {
        f
      } else {
        Failure {
          code: "tokenExpired",
          message: "Bluesky signed BunnieHop out. Connect Bluesky again.".into(),
          verbatim: f.verbatim,
        }
      }
    })?;
    let mut next = s;
    next["accessToken"] = t["access_token"].clone();
    if t["refresh_token"].is_string() {
      next["refreshToken"] = t["refresh_token"].clone();
    }
    next["expiresAt"] = json!(now_s() + t["expires_in"].as_i64().unwrap_or(300));
    let _ = self.store.set_secret(&self.conn_id, &next);
    *self.secret.lock().unwrap_or_else(|e| e.into_inner()) = next;
    Ok(())
  }

  async fn access(&self) -> Result<String, Failure> {
    let s = self.current();
    let tok = s["accessToken"].as_str().unwrap_or("").to_string();
    if s["expiresAt"].as_i64().unwrap_or(0) - 30 <= now_s() {
      self.refresh(&tok).await?;
      return Ok(
        self.current()["accessToken"]
          .as_str()
          .unwrap_or("")
          .to_string(),
      );
    }
    Ok(tok)
  }

  /// One XRPC call to the creator's PDS.
  pub async fn send(
    &self,
    method: reqwest::Method,
    url: &str,
    query: &[(&str, &str)],
    body: &Body,
  ) -> Result<reqwest::Response, Failure> {
    let mut refreshed = false;
    for _ in 0..3 {
      let tok = self.access().await?;
      let n = self
        .pds_nonce
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
      let mut rb = self
        .http
        .request(method.clone(), url)
        .query(query)
        .header("Authorization", format!("DPoP {tok}"))
        .header(
          "DPoP",
          self
            .dpop
            .proof(method.as_str(), url, n.as_deref(), Some(&tok)),
        );
      rb = match body {
        Body::None => rb,
        Body::Json(v) => rb.json(v),
        Body::Bytes(b, ct) => rb.header("content-type", *ct).body(b.clone()),
      };
      let r = rb.send().await.map_err(|e| net(P, e))?;
      if let Some(n) = r.headers().get("dpop-nonce").and_then(|v| v.to_str().ok()) {
        *self.pds_nonce.lock().unwrap_or_else(|e| e.into_inner()) = Some(n.to_string());
      }
      if r.status().as_u16() != 401 {
        return Ok(r);
      }
      let www = r
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
      if www.contains("use_dpop_nonce") {
        continue;
      }
      if refreshed {
        return Ok(r);
      }
      refreshed = true;
      self.refresh(&tok).await?;
    }
    Err(Failure::new(
      "tokenExpired",
      "Bluesky signed BunnieHop out. Connect Bluesky again.",
    ))
  }
}

#[cfg(test)]
pub mod tests {
  use super::*;
  use p256::ecdsa::{signature::Verifier, VerifyingKey};

  /// Checks a DPoP proof's signature against its own `jwk` and returns its claims.
  pub fn check_proof(proof: &str) -> Value {
    let parts: Vec<&str> = proof.split('.').collect();
    let dec = |s: &str| URL_SAFE_NO_PAD.decode(s).unwrap();
    let h: Value = serde_json::from_slice(&dec(parts[0])).unwrap();
    assert_eq!(h["typ"], "dpop+jwt");
    let mut sec1 = vec![4u8];
    sec1.extend(dec(h["jwk"]["x"].as_str().unwrap()));
    sec1.extend(dec(h["jwk"]["y"].as_str().unwrap()));
    let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = Signature::from_slice(&dec(parts[2])).unwrap();
    vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
      .expect("DPoP proof signature");
    serde_json::from_slice(&dec(parts[1])).unwrap()
  }

  #[test]
  fn dpop_proofs_are_signed_and_bound_to_the_request_and_token() {
    let k = Dpop::generate();
    let again = Dpop::from_secret(&k.secret()).unwrap();
    let p = again.proof(
      "POST",
      "https://pds.example/xrpc/x?y=1",
      Some("n1"),
      Some("tok"),
    );
    let c = check_proof(&p);
    assert_eq!(c["htm"], "POST");
    assert_eq!(c["htu"], "https://pds.example/xrpc/x");
    assert_eq!(c["nonce"], "n1");
    assert_eq!(c["ath"], b64(&Sha256::digest(b"tok")));
  }
}

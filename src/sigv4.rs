//! AWS Signature Version 4 for S3-compatible storage (the advanced vault, O-004). Built on the
//! `sha2` and `hmac` crates (both already in the Helper's dependency tree).

use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
  hex::encode(Sha256::digest(data))
}

/// RFC 2104 HMAC with SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
  use hmac::{KeyInit, Mac};
  let mut m = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
  m.update(data);
  m.finalize().into_bytes().into()
}

/// SigV4 URI encoding: unreserved characters stay, everything else is %XX (uppercase).
/// `keep_slash` leaves `/` alone, for object keys in the path.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
  let mut out = String::with_capacity(s.len());
  for b in s.bytes() {
    match b {
      b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
      b'/' if keep_slash => out.push('/'),
      _ => out.push_str(&format!("%{b:02X}")),
    }
  }
  out
}

pub struct Signer {
  pub access: String,
  pub secret: String,
  pub region: String,
}

pub struct Request<'a> {
  pub method: &'a str,
  /// Already URI-encoded path, starting with `/`.
  pub path: &'a str,
  /// Unencoded query pairs; encoded and sorted here.
  pub query: &'a [(String, String)],
  /// Headers to sign (must include `host`, `x-amz-date`, `x-amz-content-sha256`).
  pub headers: &'a [(String, String)],
  pub payload_hash: &'a str,
  /// `YYYYMMDDTHHMMSSZ`.
  pub amz_date: &'a str,
}

impl Signer {
  /// The `Authorization` header value for `req`.
  pub fn authorization(&self, req: &Request) -> String {
    let mut q: Vec<(String, String)> = req
      .query
      .iter()
      .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
      .collect();
    q.sort();
    let query = q
      .iter()
      .map(|(k, v)| format!("{k}={v}"))
      .collect::<Vec<_>>()
      .join("&");
    let mut h: Vec<(String, String)> = req
      .headers
      .iter()
      .map(|(k, v)| {
        (
          k.to_ascii_lowercase(),
          v.split_whitespace().collect::<Vec<_>>().join(" "),
        )
      })
      .collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed = h
      .iter()
      .map(|(k, _)| k.as_str())
      .collect::<Vec<_>>()
      .join(";");
    let canonical = format!(
      "{}\n{}\n{}\n{}\n{}\n{}",
      req.method, req.path, query, canonical_headers, signed, req.payload_hash
    );
    let date = &req.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", self.region);
    let to_sign = format!(
      "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
      req.amz_date,
      sha256_hex(canonical.as_bytes())
    );
    let k_date = hmac_sha256(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, self.region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let sig = hex::encode(hmac_sha256(&k_signing, to_sign.as_bytes()));
    format!(
      "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
      self.access
    )
  }
}

/// `YYYYMMDDTHHMMSSZ` for now.
pub fn amz_now() -> String {
  let f = time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
  time::OffsetDateTime::now_utc()
    .format(&f)
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hmac_matches_rfc_4231() {
    // test case 2
    assert_eq!(
      hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // test case 6: key longer than the block size
    assert_eq!(
      hex::encode(hmac_sha256(
        &[0xaa; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First"
      )),
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
  }

  #[test]
  fn sigv4_matches_the_aws_get_object_example() {
    // "Example: GET Object" in the S3 API reference, Signature Version 4 header auth.
    let empty = sha256_hex(b"");
    let s = Signer {
      access: "AKIAIOSFODNN7EXAMPLE".into(),
      secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
      region: "us-east-1".into(),
    };
    let headers = vec![
      ("Host".into(), "examplebucket.s3.amazonaws.com".into()),
      ("Range".into(), "bytes=0-9".into()),
      ("x-amz-content-sha256".into(), empty.clone()),
      ("x-amz-date".into(), "20130524T000000Z".into()),
    ];
    let auth = s.authorization(&Request {
      method: "GET",
      path: "/test.txt",
      query: &[],
      headers: &headers,
      payload_hash: &empty,
      amz_date: "20130524T000000Z",
    });
    assert_eq!(
      auth,
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
       SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
       Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
  }

  #[test]
  fn uri_encoding_keeps_unreserved_and_slashes_only_when_asked() {
    assert_eq!(uri_encode("a b/c~d.e_f-g", true), "a%20b/c~d.e_f-g");
    assert_eq!(uri_encode("a/b", false), "a%2Fb");
    assert_eq!(uri_encode("é", true), "%C3%A9");
  }
}

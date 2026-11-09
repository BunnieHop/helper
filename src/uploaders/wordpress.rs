//! WordPress through the REST API: self-hosted sites (5.6+) with an Application Password the
//! creator approves on their own `authorize-application.php` page, and WordPress.com sites with a
//! token from WordPress.com's sign-in page (same `/wp/v2` API under `public-api.wordpress.com`).
//! Posts keep their original date (`date_gmt`), tags and
//! HTML; the featured image and any video go to the media library first.
//!
//! D11: before creating a post, the site is searched for one with the same title and original
//! date, and that post is returned instead.

use super::{
  article_html, created_at, escape_html, file_body, is_image, is_video, json_or_fail, mime_of,
  site_url, tags, thumbnail_of, title_text, utc_iso, Endpoints,
};
use crate::hops::{BoxFut, Failure, Published, Upload, Uploader, With};
use serde_json::{json, Value};
use std::path::Path;

const P: &str = "WordPress";

enum Auth {
  Basic(String, String),
  Bearer(String),
}

pub struct WordPress {
  http: reqwest::Client,
  /// `…/wp-json/wp/v2` or `https://public-api.wordpress.com/wp/v2/sites/<id>`
  root: String,
  auth: Auth,
}

/// The signed-in user must be able to publish.
async fn check_can_publish(w: &WordPress, rejected: &str) -> Result<(), Failure> {
  let me = w
    .get("users/me?context=edit")
    .await
    .map_err(|f| match f.code {
      "tokenExpired" | "uploadRejected" => Failure {
        code: "signInRequired",
        message: rejected.into(),
        verbatim: f.verbatim,
      },
      "notFound404" => Failure {
        code: "notSupported",
        message: "That site doesn't answer the WordPress REST API at /wp-json.".into(),
        verbatim: f.verbatim,
      },
      _ => f,
    })?;
  if me.pointer("/capabilities/publish_posts") != Some(&json!(true)) {
    return Err(Failure::new(
      "signInRequired",
      "That WordPress user can't publish posts. Use an Author, Editor or Administrator.",
    ));
  }
  Ok(())
}

/// Checks the application password. Returns (label, secret).
pub async fn connect(
  http: &reqwest::Client,
  url: &str,
  user: &str,
  app_password: &str,
) -> Result<(String, Value), Failure> {
  let base = site_url(url)?;
  let (user, pass) = (user.trim().to_string(), app_password.trim().to_string());
  let w = WordPress {
    http: http.clone(),
    root: format!("{base}/wp-json/wp/v2"),
    auth: Auth::Basic(user.clone(), pass.clone()),
  };
  check_can_publish(
    &w,
    "WordPress didn't accept that username and application password.",
  )
  .await?;
  let site = json_or_fail(P, http.get(format!("{base}/wp-json/")).send().await)
    .await
    .unwrap_or(Value::Null);
  let label = site["name"]
    .as_str()
    .filter(|n| !n.is_empty())
    .map(String::from)
    .unwrap_or_else(|| base.trim_start_matches("https://").to_string());
  Ok((
    label,
    json!({ "url": base, "user": user, "appPassword": pass }),
  ))
}

fn host_of(site: &str) -> String {
  site
    .split("://")
    .nth(1)
    .unwrap_or(site)
    .split(['/', '?', '#'])
    .next()
    .unwrap_or("")
    .trim_start_matches("www.")
    .to_ascii_lowercase()
}

/// Is this site hosted on WordPress.com (not a self-hosted site with Jetpack)? Unknown → false,
/// so the site's own approve page is tried.
pub async fn is_wpcom(http: &reqwest::Client, ep: &Endpoints, site: &str) -> bool {
  let host = host_of(site);
  if host.ends_with(".wordpress.com") {
    return true;
  }
  if host.is_empty() {
    return false;
  }
  let Ok(r) = http
    .get(format!("{}/rest/v1.1/sites/{host}", ep.wpcom_api))
    .query(&[("fields", "ID,jetpack")])
    .send()
    .await
  else {
    return false;
  };
  match r.status().as_u16() {
    200 => r
      .json::<Value>()
      .await
      .is_ok_and(|v| v["jetpack"] == json!(false)),
    // A private WordPress.com site answers "User cannot access this restricted blog". Sites that
    // turned the API off ("API calls to this blog have been disabled", e.g. VIP or self-hosted
    // Jetpack) are not signed in through WordPress.com: their own approve page is used.
    403 => r.json::<Value>().await.is_ok_and(|v| {
      v["message"]
        .as_str()
        .is_some_and(|m| m.contains("restricted blog"))
    }),
    _ => false,
  }
}

/// After WordPress.com's sign-in page (Worker relay `wpcom`): the token is for the one site the
/// creator picked there. Returns (label, secret).
pub async fn connect_wpcom(
  http: &reqwest::Client,
  ep: &Endpoints,
  tokens: &Value,
) -> Result<(String, Value), Failure> {
  let blog = tokens["blog_id"]
    .as_i64()
    .map(|i| i.to_string())
    .or_else(|| tokens["blog_id"].as_str().map(String::from));
  let (Some(tok), Some(blog)) = (tokens["access_token"].as_str(), blog) else {
    return Err(Failure::new(
      "signInRequired",
      "WordPress.com didn't finish the sign-in. Try again and pick your site.",
    ));
  };
  let w = WordPress {
    http: http.clone(),
    root: format!("{}/wp/v2/sites/{blog}", ep.wpcom_api),
    auth: Auth::Bearer(tok.to_string()),
  };
  check_can_publish(&w, "WordPress.com signed BunnieHop out. Connect again.").await?;
  let url = tokens["blog_url"].as_str().unwrap_or("").to_string();
  let info = json_or_fail(
    P,
    w.auth(
      http
        .get(format!("{}/rest/v1.1/sites/{blog}", ep.wpcom_api))
        .query(&[("fields", "name,URL")]),
    )
    .send()
    .await,
  )
  .await
  .unwrap_or(Value::Null);
  let label = info["name"]
    .as_str()
    .filter(|n| !n.is_empty())
    .map(String::from)
    .unwrap_or_else(|| host_of(&url));
  Ok((
    label,
    json!({ "wpcom": true, "blogId": blog, "url": url, "accessToken": tok }),
  ))
}

/// WordPress wants `date_gmt` without a zone suffix.
fn wp_gmt(iso: &str) -> Option<String> {
  utc_iso(iso).map(|s| s.trim_end_matches('Z').to_string())
}

impl WordPress {
  pub fn new(http: reqwest::Client, secret: &Value, ep: &Endpoints) -> Option<Self> {
    if secret["wpcom"] == json!(true) {
      let blog = secret["blogId"].as_str()?;
      return Some(Self {
        http,
        root: format!("{}/wp/v2/sites/{blog}", ep.wpcom_api),
        auth: Auth::Bearer(secret["accessToken"].as_str()?.to_string()),
      });
    }
    Some(Self {
      http,
      root: format!("{}/wp-json/wp/v2", secret["url"].as_str()?),
      auth: Auth::Basic(
        secret["user"].as_str()?.to_string(),
        secret["appPassword"].as_str()?.to_string(),
      ),
    })
  }

  fn api(&self, path: &str) -> String {
    format!("{}/{path}", self.root)
  }

  fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match &self.auth {
      Auth::Basic(u, p) => r.basic_auth(u, Some(p)),
      Auth::Bearer(t) => r.bearer_auth(t),
    }
  }

  async fn get(&self, path: &str) -> Result<Value, Failure> {
    json_or_fail(P, self.auth(self.http.get(self.api(path))).send().await).await
  }

  async fn media(&self, path: &Path) -> Result<Value, Failure> {
    let (b, len) = file_body(path)
      .await
      .map_err(|e| Failure::new("unknown", "Couldn't read the file from the vault.").with(e))?;
    let name: String = path
      .file_name()
      .and_then(|n| n.to_str())
      .unwrap_or("file")
      .chars()
      .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
      .collect();
    json_or_fail(
      P,
      self
        .auth(self.http.post(self.api("media")))
        .header("Content-Type", mime_of(path))
        .header("Content-Length", len)
        .header(
          "Content-Disposition",
          format!("attachment; filename=\"{name}\""),
        )
        .body(b)
        .send()
        .await,
    )
    .await
  }

  async fn tag_ids(&self, names: &[String]) -> Result<Vec<i64>, Failure> {
    let mut ids = Vec::new();
    for n in names
      .iter()
      .map(|n| n.trim())
      .filter(|n| !n.is_empty())
      .take(30)
    {
      let found = self
        .get(&format!(
          "tags?per_page=100&search={}",
          super::ghost::urlencode(n)
        ))
        .await?;
      let hit = found.as_array().into_iter().flatten().find(|t| {
        t["name"]
          .as_str()
          .is_some_and(|x| x.eq_ignore_ascii_case(n) || x == escape_html(n))
      });
      let id = match hit {
        Some(t) => t["id"].as_i64(),
        None => {
          let r = self
            .auth(self.http.post(self.api("tags")))
            .json(&json!({ "name": n }))
            .send()
            .await;
          match json_or_fail(P, r).await {
            Ok(t) => t["id"].as_i64(),
            // made by a parallel request: WordPress answers term_exists with the id
            Err(f) => f
              .verbatim
              .as_deref()
              .and_then(|v| serde_json::from_str::<Value>(v).ok())
              .and_then(|v| v.pointer("/data/term_id").and_then(Value::as_i64)),
          }
        }
      };
      ids.extend(id);
    }
    Ok(ids)
  }

  async fn existing(&self, title: &str, gmt: Option<&str>) -> Result<Option<Value>, Failure> {
    let v = self
      .get(&format!(
        "posts?context=edit&per_page=20&status=publish,future,draft,pending,private&search={}",
        super::ghost::urlencode(title)
      ))
      .await?;
    Ok(
      v.as_array()
        .into_iter()
        .flatten()
        .find(|p| {
          p.pointer("/title/raw").and_then(Value::as_str) == Some(title)
            && match (gmt, p["date_gmt"].as_str()) {
              (Some(a), Some(b)) => a.get(..16) == b.get(..16),
              (None, _) => true,
              _ => false,
            }
        })
        .cloned(),
    )
  }
}

impl Uploader for WordPress {
  fn safe_to_retry(&self) -> bool {
    true
  }

  fn publish<'a>(&'a self, u: Upload<'a>) -> BoxFut<'a, Result<Published, Failure>> {
    Box::pin(async move {
      let title = title_text(u.post, u.item);
      let gmt = created_at(u.post, u.item).as_deref().and_then(wp_gmt);
      if let Some(p) = self.existing(&title, gmt.as_deref()).await? {
        return Ok(Published {
          note: None,
          dest_item_id: p["id"].as_i64().unwrap_or(0).to_string(),
          dest_url: p["link"].as_str().map(String::from),
          verified: true,
        });
      }
      let featured =
        match thumbnail_of(u.media).or_else(|| u.media.iter().find(|p| is_image(p)).cloned()) {
          Some(t) => self.media(&t).await?["id"].as_i64(),
          None => None,
        };
      let mut html = String::new();
      if let Some(v) = u.media.iter().find(|p| is_video(p)) {
        let m = self.media(v).await?;
        if let Some(src) = m["source_url"].as_str() {
          html.push_str(&format!(
            "<!-- wp:video -->\n<figure class=\"wp-block-video\"><video controls src=\"{}\"></video></figure>\n<!-- /wp:video -->\n",
            escape_html(src)
          ));
        }
      }
      html.push_str(&article_html(u.post, u.item));
      let mut post = json!({
        "title": title,
        "content": html,
        "status": "publish",
        "tags": self.tag_ids(&tags(u.post, u.item)).await?,
      });
      if let Some(d) = &gmt {
        post["date_gmt"] = json!(d);
      }
      if let Some(f) = featured {
        post["featured_media"] = json!(f);
      }
      let r = self
        .auth(self.http.post(self.api("posts")))
        .json(&post)
        .send()
        .await;
      let v = json_or_fail(P, r).await?;
      let id = v["id"].as_i64().unwrap_or(0);
      let check = self.get(&format!("posts/{id}?context=edit")).await;
      Ok(Published {
        note: None,
        dest_item_id: id.to_string(),
        dest_url: v["link"].as_str().map(String::from),
        verified: id > 0
          && check.is_ok_and(|c| c["status"] == "publish" || c["status"] == "future"),
      })
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::uploaders::testkit::serve;
  use axum::extract::{Path as AxPath, Query, State};
  use axum::http::HeaderMap;
  use axum::routing::{get, post};
  use axum::{Json, Router};
  use std::collections::HashMap;
  use std::sync::{Arc, Mutex};

  #[derive(Default)]
  struct Site {
    posts: Vec<Value>,
    tags: Vec<String>,
    media: usize,
  }
  type S = Arc<Mutex<Site>>;

  fn authed(h: &HeaderMap) -> bool {
    // "mara:abcd efgh ijkl mnop qrst uvwx"
    h.get("authorization").and_then(|v| v.to_str().ok())
      == Some("Basic bWFyYTphYmNkIGVmZ2ggaWprbCBtbm9wIHFyc3QgdXZ3eA==")
  }

  fn fake(s: S, can_publish: bool) -> Router {
    Router::new()
      .route("/wp-json/", get(|| async { Json(json!({ "name": "Mara's Blog" })) }))
      .route(
        "/wp-json/wp/v2/users/me",
        get(move |h: HeaderMap| async move {
          if !authed(&h) {
            return (axum::http::StatusCode::UNAUTHORIZED, Json(json!({ "code": "rest_not_logged_in" })));
          }
          (axum::http::StatusCode::OK, Json(json!({ "name": "Mara", "capabilities": { "publish_posts": can_publish } })))
        }),
      )
      .route(
        "/wp-json/wp/v2/tags",
        get(|State(s): State<S>, Query(q): Query<HashMap<String, String>>| async move {
          let s = s.lock().unwrap();
          let hits: Vec<Value> = s.tags.iter().enumerate().filter(|(_, t)| Some(*t) == q.get("search")).map(|(i, t)| json!({ "id": i + 1, "name": t })).collect();
          Json(json!(hits))
        })
        .post(|State(s): State<S>, Json(b): Json<Value>| async move {
          let mut s = s.lock().unwrap();
          s.tags.push(b["name"].as_str().unwrap().to_string());
          Json(json!({ "id": s.tags.len() }))
        }),
      )
      .route(
        "/wp-json/wp/v2/media",
        post(|State(s): State<S>, h: HeaderMap, _b: axum::body::Bytes| async move {
          assert!(authed(&h));
          assert!(h["content-disposition"].to_str().unwrap().contains("thumbnail.jpg"));
          s.lock().unwrap().media += 1;
          Json(json!({ "id": 77, "source_url": "https://blog.example/wp-content/uploads/thumbnail.jpg" }))
        }),
      )
      .route(
        "/wp-json/wp/v2/posts",
        get(|State(s): State<S>| async move { Json(json!(s.lock().unwrap().posts.clone())) }).post(
          |State(s): State<S>, Json(b): Json<Value>| async move {
            let mut s = s.lock().unwrap();
            let id = s.posts.len() + 10;
            let p = json!({ "id": id, "link": format!("https://blog.example/?p={id}"), "status": "publish", "title": { "raw": b["title"] }, "date_gmt": b["date_gmt"], "content": { "raw": b["content"] }, "tags": b["tags"], "featured_media": b["featured_media"] });
            s.posts.push(p.clone());
            Json(p)
          },
        ),
      )
      .route(
        "/wp-json/wp/v2/posts/{id}",
        get(|State(s): State<S>, AxPath(id): AxPath<i64>| async move {
          Json(s.lock().unwrap().posts.iter().find(|p| p["id"] == id).cloned().unwrap_or(Value::Null))
        }),
      )
      .with_state(s)
  }

  #[tokio::test]
  async fn wordpress_publishes_with_the_original_date_and_never_twice() {
    let site: S = Arc::default();
    site.lock().unwrap().tags.push("news".into());
    let base = serve(fake(site.clone(), true)).await;
    let http = reqwest::Client::new();
    let (label, secret) = connect(&http, &base, "mara", "abcd efgh ijkl mnop qrst uvwx")
      .await
      .unwrap();
    assert_eq!(label, "Mara's Blog");
    let w = WordPress::new(http, &secret, &Endpoints::default()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("thumbnail.jpg"), b"jpg").unwrap();
    let media = [dir.path().join("media.none")];
    let item = json!({ "id": "s1", "kind": "article", "title": "Hello", "description": "Words\n\nhttps://x.example", "tags": ["news", "new one"], "publishedAt": "2021-03-04T05:06:07-05:00" });
    let up = |k: &'static str| Upload {
      item: &item,
      post: None,
      media: &media,
      idempotency_key: k,
      options: &Value::Null,
    };
    let p = w.publish(up("h:s1:wordpress")).await.unwrap();
    assert!(p.verified);
    assert_eq!(p.dest_url.as_deref(), Some("https://blog.example/?p=10"));
    {
      let s = site.lock().unwrap();
      let post = &s.posts[0];
      assert_eq!(post["date_gmt"], "2021-03-04T10:06:07");
      assert_eq!(
        post["tags"],
        json!([1, 2]),
        "existing tag reused, new one made"
      );
      assert_eq!(post["featured_media"], 77);
      assert!(post["content"]["raw"]
        .as_str()
        .unwrap()
        .contains("<a href=\"https://x.example\">"));
    }
    let again = w.publish(up("h2:s1:wordpress")).await.unwrap();
    assert_eq!(again.dest_item_id, "10");
    let s = site.lock().unwrap();
    assert_eq!((s.posts.len(), s.media), (1, 1));
  }

  #[tokio::test]
  async fn wordpress_com_sites_use_the_public_api_with_the_sign_in_token() {
    use axum::http::StatusCode as S;
    let app = Router::new()
      .route(
        "/wp/v2/sites/4242/posts",
        get(|h: HeaderMap| async move {
          assert_eq!(h["authorization"], "Bearer wpcom-tok");
          Json(json!([{ "id": 9, "link": "https://mara.blog/hello", "title": { "raw": "Hello" }, "date_gmt": null }]))
        }),
      )
      // answers seen live from public-api.wordpress.com (2026-11-08)
      .route(
        "/rest/v1.1/sites/{host}",
        get(|AxPath(host): AxPath<String>| async move {
          match host.as_str() {
            "hosted.blog" => (S::OK, Json(json!({ "ID": 1, "jetpack": false }))),
            "jetpack.org" => (S::OK, Json(json!({ "ID": 2, "jetpack": true }))),
            "private.blog" => (S::FORBIDDEN, Json(json!({ "error": "unauthorized", "message": "User cannot access this restricted blog" }))),
            "vip.com" => (S::FORBIDDEN, Json(json!({ "error": "unauthorized", "message": "API calls to this blog have been disabled." }))),
            _ => (S::NOT_FOUND, Json(json!({ "error": "unknown_blog" }))),
          }
        }),
      );
    let base = serve(app).await;
    let ep = Endpoints {
      wpcom_api: base,
      ..Endpoints::default()
    };
    let secret = json!({ "wpcom": true, "blogId": "4242", "url": "https://mara.blog", "accessToken": "wpcom-tok" });
    let w = WordPress::new(reqwest::Client::new(), &secret, &ep).unwrap();
    let hit = w.existing("Hello", None).await.unwrap().unwrap();
    assert_eq!(hit["link"], "https://mara.blog/hello");
    let http = reqwest::Client::new();
    for (site, hosted) in [
      ("https://mara.wordpress.com/", true),
      ("hosted.blog", true),
      ("https://private.blog/about", true),
      ("jetpack.org", false),
      ("vip.com", false),
      ("selfhosted.net", false),
    ] {
      assert_eq!(is_wpcom(&http, &ep, site).await, hosted, "{site}");
    }
  }

  #[tokio::test]
  async fn wordpress_says_when_the_user_cant_publish_or_the_password_is_wrong() {
    let base = serve(fake(Arc::default(), false)).await;
    let http = reqwest::Client::new();
    let f = connect(&http, &base, "mara", "abcd efgh ijkl mnop qrst uvwx")
      .await
      .unwrap_err();
    assert!(f.message.contains("can't publish"));
    let f = connect(&http, &base, "mara", "wrong").await.unwrap_err();
    assert_eq!(f.code, "signInRequired");
    assert!(f.verbatim.unwrap().contains("rest_not_logged_in"));
  }
}

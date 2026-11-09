//! yt-dlp: argument builders, the process runner, progress parsing and error classification.
//!
//! The machine-readable progress template and `\r`-aware line splitting follow youtube-dl-gui's
//! runner; the argument builders are BunnieHop's own (paged catalog, retries, human pacing).
//! Nothing secret is ever put on argv, and argv is never logged.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

pub const PROGRESS_PREFIX: &str = "BHP|";
pub const FILE_PREFIX: &str = "BHF|";
const PROGRESS_TEMPLATE: &str = "download:BHP|%(progress.status)s|%(progress.downloaded_bytes)s|%(progress.total_bytes)s|%(progress.total_bytes_estimate)s|%(progress.fragment_index)s|%(progress.fragment_count)s";

/// Flags every run gets: no user config, stable output, a human request pace (PLAN §5).
fn base() -> Vec<String> {
  [
    "--ignore-config",
    "--no-color",
    "--encoding",
    "utf-8",
    "--sleep-requests",
    "1",
    "--socket-timeout",
    "30",
  ]
  .into_iter()
  .map(String::from)
  .collect()
}

/// Tool locations passed to yt-dlp so it uses the Helper's own copies.
#[derive(Debug, Clone, Default)]
pub struct Tools {
  pub ffmpeg: Option<PathBuf>,
  pub deno: Option<PathBuf>,
}

impl Tools {
  fn args(&self) -> Vec<String> {
    let mut a = Vec::new();
    if let Some(f) = &self.ffmpeg {
      a.push("--ffmpeg-location".into());
      a.push(f.display().to_string());
    }
    if let Some(d) = &self.deno {
      a.push("--js-runtimes".into());
      a.push(format!("deno:{}", d.display()));
    }
    a
  }
}

/// Only http(s) URLs reach yt-dlp, and always after `--` so they can't be read as options.
pub fn checked_url(url: &str) -> Option<&str> {
  let u = url.trim();
  (u.starts_with("https://") || u.starts_with("http://")).then_some(u)
}

/// One catalog window: flat listing (no per-video requests), items `start..=end` (1-based).
pub fn catalog_args(url: &str, start: u32, end: u32, tools: &Tools) -> Vec<String> {
  let mut a = base();
  a.extend(tools.args());
  a.extend(
    [
      "--flat-playlist",
      "--dump-single-json",
      "--playlist-items",
      &format!("{start}:{end}"),
      "--extractor-args",
      "youtubetab:approximate_date",
      "--",
      url,
    ]
    .into_iter()
    .map(String::from),
  );
  a
}

/// Download one item into `folder` as `media.<ext>` plus thumbnail, captions and info JSON.
/// Format: best up to 1080p, preferring H.264/AAC in MP4 (every Phase 1 destination accepts it).
pub fn download_args(url: &str, folder: &Path, tools: &Tools) -> Vec<String> {
  let f = |name: &str| folder.join(name).display().to_string();
  let has_ffmpeg = tools.ffmpeg.is_some();
  let mut a = base();
  a.extend(tools.args());
  a.extend(
    [
      "--no-playlist",
      "--newline",
      "--progress",
      "--progress-template",
      PROGRESS_TEMPLATE,
      "--progress-delta",
      "0.5",
      "--print",
      "after_move:BHF|%(filepath)s",
      "--retries",
      "10",
      "--fragment-retries",
      "10",
      "--retry-sleep",
      "linear=1::5",
      "--continue",
      "--no-overwrites",
      "--max-filesize",
      "10G",
      "--write-info-json",
      "--write-thumbnail",
      "--write-subs",
      "--sub-langs",
      "all,-live_chat",
    ]
    .into_iter()
    .map(String::from),
  );
  if has_ffmpeg {
    a.extend(
      [
        "-f",
        "bv*[height<=1080]+ba/b[height<=1080]/bv*+ba/b",
        "-S",
        "vcodec:avc1,acodec:aac,ext:mp4:m4a",
        "--merge-output-format",
        "mp4",
        "--convert-thumbnails",
        "jpg",
      ]
      .into_iter()
      .map(String::from),
    );
  } else {
    // Without ffmpeg only single-file formats work; quality is lower and the status says so.
    a.extend(["-f", "b[ext=mp4]/b"].into_iter().map(String::from));
  }
  a.extend([
    "-o".into(),
    f("media.%(ext)s"),
    "-o".into(),
    format!("thumbnail:{}", f("thumbnail.%(ext)s")),
    "-o".into(),
    format!("subtitle:{}", f("captions.%(ext)s")),
    "-o".into(),
    format!("infojson:{}", f("info")),
    "--".into(),
    url.into(),
  ]);
  a
}

#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
  pub status: String,
  pub downloaded: Option<u64>,
  pub total: Option<u64>,
  /// 0..=1, from bytes or fragments.
  pub fraction: Option<f64>,
}

pub fn parse_progress(line: &str) -> Option<Progress> {
  let rest = line.strip_prefix(PROGRESS_PREFIX)?;
  let f: Vec<&str> = rest.split('|').collect();
  let num = |i: usize| {
    f.get(i)
      .and_then(|v| v.trim().parse::<f64>().ok())
      .filter(|n| n.is_finite() && *n >= 0.0)
  };
  let downloaded = num(1).map(|n| n as u64);
  let total = num(2).or(num(3)).map(|n| n as u64).filter(|t| *t > 0);
  let fraction = match (downloaded, total) {
    (Some(d), Some(t)) => Some((d as f64 / t as f64).min(1.0)),
    _ => match (num(4), num(5)) {
      (Some(i), Some(c)) if c > 0.0 => Some((i / c).min(1.0)),
      _ => None,
    },
  };
  Some(Progress {
    status: f.first().unwrap_or(&"").to_string(),
    downloaded,
    total,
    fraction,
  })
}

/// Maps yt-dlp's words to the shared error codes (packages/protocol errors.ts). First match wins.
pub fn classify(stderr: &str) -> &'static str {
  let s = stderr.to_ascii_lowercase();
  let has = |needles: &[&str]| needles.iter().any(|n| s.contains(n));
  if has(&["not a bot", "confirm you\u{2019}re not a bot", "captcha"]) {
    "botCheck"
  } else if has(&[
    "confirm your age",
    "age-restricted",
    "age restricted",
    "inappropriate for some users",
  ]) {
    "ageRestricted"
  } else if has(&["members-only", "members only", "join this channel"]) {
    "membersOnly"
  } else if has(&[
    "available in your country",
    "geo restriction",
    "geo-restricted",
    "blocked it in your country",
  ]) {
    "geoBlocked"
  } else if has(&["http error 429", "too many requests"]) {
    "rateLimited429"
  } else if has(&["no space left on device", "disk full"]) {
    "diskFull"
  } else if has(&["larger than max-filesize", "file is larger than"]) {
    "itemTooLarge"
  } else if has(&[
    "http error 404",
    "video unavailable",
    "has been removed",
    "private video",
    "does not exist",
  ]) {
    "notFound404"
  } else if has(&[
    "http error 500",
    "http error 502",
    "http error 503",
    "http error 504",
  ]) {
    "server5xx"
  } else if has(&["sign in", "login required", "log in", "cookies"]) {
    "signInRequired"
  } else if has(&[
    "unable to download webpage",
    "getaddrinfo",
    "timed out",
    "connection reset",
    "network is unreachable",
    "name or service not known",
  ]) {
    "networkLost"
  } else {
    "unknown"
  }
}

/// The lines worth showing verbatim: yt-dlp's `ERROR:` lines, else the tail of stderr.
pub fn verbatim(stderr: &str) -> String {
  let errors: Vec<&str> = stderr.lines().filter(|l| l.starts_with("ERROR:")).collect();
  let text = if errors.is_empty() {
    stderr
      .lines()
      .rev()
      .take(5)
      .collect::<Vec<_>>()
      .into_iter()
      .rev()
      .collect::<Vec<_>>()
      .join("\n")
  } else {
    errors.join("\n")
  };
  tail_chars(&text, 2000)
}

/// Last `max` bytes, cut on a char boundary (upstream issue #2: byte slicing panicked mid-char).
pub fn tail_chars(s: &str, max: usize) -> String {
  if s.len() <= max {
    return s.to_string();
  }
  let mut i = s.len() - max;
  while !s.is_char_boundary(i) {
    i += 1;
  }
  s[i..].to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunError {
  Cancelled,
  Spawn(String),
  Failed {
    code: &'static str,
    verbatim: String,
  },
}

pub struct RunOutput {
  pub stdout: String,
  /// Files yt-dlp reported after moving them into place.
  pub files: Vec<PathBuf>,
}

/// Runs yt-dlp; progress lines go to `on_progress`. Cancelling sends SIGTERM to the process
/// group, then SIGKILL after five seconds.
pub async fn run(
  exe: &Path,
  args: &[String],
  mut cancel: watch::Receiver<bool>,
  mut on_progress: impl FnMut(Progress),
) -> Result<RunOutput, RunError> {
  let mut cmd = Command::new(exe);
  cmd
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
  #[cfg(unix)]
  cmd.process_group(0);
  let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.to_string()))?;
  let pid = child.id();
  let stdout = child.stdout.take().expect("piped stdout");
  let mut stderr = child.stderr.take().expect("piped stderr");
  let err_task = tokio::spawn(async move {
    let mut buf = Vec::new();
    let _ = stderr.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
  });
  let mut lines = BufReader::new(stdout).lines();
  let mut out = String::new();
  let mut files = Vec::new();
  loop {
    tokio::select! {
      line = lines.next_line() => match line {
        Ok(Some(l)) => {
          // yt-dlp may join progress updates with \r on one line.
          for part in l.split('\r') {
            if let Some(p) = parse_progress(part) {
              on_progress(p);
            } else if let Some(f) = part.strip_prefix(FILE_PREFIX) {
              files.push(PathBuf::from(f.trim()));
            } else if !part.is_empty() {
              out.push_str(part);
              out.push('\n');
            }
          }
        }
        _ => break,
      },
      changed = cancel.changed() => {
        if changed.is_err() || *cancel.borrow() {
          terminate(&mut child, pid).await;
          return Err(RunError::Cancelled);
        }
      }
    }
  }
  let status = child
    .wait()
    .await
    .map_err(|e| RunError::Spawn(e.to_string()))?;
  let stderr = err_task.await.unwrap_or_default();
  if status.success() {
    Ok(RunOutput { stdout: out, files })
  } else {
    Err(RunError::Failed {
      code: classify(&stderr),
      verbatim: verbatim(&stderr),
    })
  }
}

async fn terminate(child: &mut tokio::process::Child, pid: Option<u32>) {
  #[cfg(unix)]
  if let Some(pid) = pid {
    // SAFETY: signalling our own child's process group.
    unsafe {
      libc::kill(-(pid as i32), libc::SIGTERM);
    }
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
      .await
      .is_ok()
    {
      return;
    }
    unsafe {
      libc::kill(-(pid as i32), libc::SIGKILL);
    }
  }
  #[cfg(not(unix))]
  let _ = pid;
  let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ytdlp_url_goes_after_double_dash_and_must_be_http() {
    let a = catalog_args(
      "https://www.youtube.com/@x/videos",
      1,
      200,
      &Tools::default(),
    );
    let n = a.len();
    assert_eq!(&a[n - 2..], ["--", "https://www.youtube.com/@x/videos"]);
    assert!(a.windows(2).any(|w| w == ["--playlist-items", "1:200"]));
    assert!(a.contains(&"--flat-playlist".to_string()));
    assert!(checked_url("-x").is_none());
    assert!(checked_url("file:///etc/passwd").is_none());
    assert_eq!(checked_url(" https://a.b/c "), Some("https://a.b/c"));
  }

  #[test]
  fn ytdlp_download_args_pace_retry_and_never_carry_secrets() {
    let tools = Tools {
      ffmpeg: Some("/opt/ff/ffmpeg".into()),
      deno: Some("/opt/deno".into()),
    };
    let a = download_args("https://youtu.be/abc", Path::new("/v/item"), &tools);
    for flag in [
      "--ignore-config",
      "--continue",
      "--no-overwrites",
      "--write-info-json",
      "--write-subs",
      "--write-thumbnail",
    ] {
      assert!(a.contains(&flag.to_string()), "{flag}");
    }
    let pair = |k: &str, v: &str| a.windows(2).any(|w| w[0] == k && w[1] == v);
    assert!(pair("--sleep-requests", "1"));
    assert!(pair("--retries", "10"));
    assert!(pair("--fragment-retries", "10"));
    assert!(pair("--max-filesize", "10G"));
    assert!(pair("--merge-output-format", "mp4"));
    assert!(pair("--ffmpeg-location", "/opt/ff/ffmpeg"));
    assert!(pair("--js-runtimes", "deno:/opt/deno"));
    let out = Path::new("/v/item")
      .join("media.%(ext)s")
      .display()
      .to_string();
    assert!(pair("-o", &out));
    assert_eq!(a.last().unwrap(), "https://youtu.be/abc");
    assert_eq!(a[a.len() - 2], "--");
    assert!(!a
      .iter()
      .any(|x| x.contains("password") || x.contains("cookies") || x.starts_with("--add-header")));
    let plain = download_args(
      "https://youtu.be/abc",
      Path::new("/v/item"),
      &Tools::default(),
    );
    assert!(plain
      .windows(2)
      .any(|w| w[0] == "-f" && w[1] == "b[ext=mp4]/b"));
  }

  #[test]
  fn ytdlp_progress_template_parses_bytes_then_fragments() {
    let p = parse_progress("BHP|downloading|500|1000|NA|NA|NA").unwrap();
    assert_eq!(p.fraction, Some(0.5));
    let p = parse_progress("BHP|downloading|500|NA|2000|NA|NA").unwrap();
    assert_eq!(p.fraction, Some(0.25));
    let p = parse_progress("BHP|downloading|NA|NA|NA|3|4").unwrap();
    assert_eq!(p.fraction, Some(0.75));
    assert!(parse_progress("RAW something").is_none());
    assert!(parse_progress("BHPX|").is_none());
  }

  #[test]
  fn ytdlp_errors_map_to_shared_codes_with_verbatim_text() {
    let cases = [
      ("ERROR: [youtube] abc: Sign in to confirm you\u{2019}re not a bot. Use --cookies-from-browser", "botCheck"),
      ("ERROR: [youtube] abc: Sign in to confirm your age.", "ageRestricted"),
      ("ERROR: [youtube] abc: Join this channel to get access to members-only content", "membersOnly"),
      ("ERROR: The uploader has not made this video available in your country", "geoBlocked"),
      ("ERROR: Unable to download webpage: HTTP Error 429: Too Many Requests", "rateLimited429"),
      ("ERROR: [youtube] abc: Video unavailable", "notFound404"),
      ("ERROR: unable to write data: [Errno 28] No space left on device", "diskFull"),
      ("ERROR: Unable to download webpage: <urlopen error [Errno 8] nodename nor servname provided> (caused by getaddrinfo)", "networkLost"),
      ("ERROR: something new", "unknown"),
    ];
    for (line, code) in cases {
      assert_eq!(classify(line), code, "{line}");
    }
    let stderr = "WARNING: x\nERROR: [youtube] abc: Video unavailable\n";
    assert_eq!(verbatim(stderr), "ERROR: [youtube] abc: Video unavailable");
  }

  #[test]
  fn ytdlp_tail_never_splits_a_character() {
    let s = "é".repeat(10);
    let t = tail_chars(&s, 5);
    assert!(t.len() <= 5 && t.chars().all(|c| c == 'é'));
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn ytdlp_runner_reports_progress_files_and_classified_failures() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-ytdlp");
    std::fs::write(&script, "#!/bin/sh\nprintf 'BHP|downloading|1|4|NA|NA|NA\\rBHP|downloading|4|4|NA|NA|NA\\n'\necho 'BHF|/v/item/media.mp4'\nif [ \"$1\" = fail ]; then echo 'ERROR: [youtube] x: Video unavailable' >&2; exit 1; fi\n").unwrap();
    crate::config::restrict(&script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (_tx, rx) = watch::channel(false);
    let mut seen = Vec::new();
    let out = run(&script, &["ok".into()], rx.clone(), |p| {
      seen.push(p.fraction)
    })
    .await
    .ok()
    .unwrap();
    assert_eq!(seen, vec![Some(0.25), Some(1.0)]);
    assert_eq!(out.files, vec![PathBuf::from("/v/item/media.mp4")]);
    let err = run(&script, &["fail".into()], rx, |_| {})
      .await
      .err()
      .unwrap();
    assert_eq!(
      err,
      RunError::Failed {
        code: "notFound404",
        verbatim: "ERROR: [youtube] x: Video unavailable".into()
      }
    );
  }

  #[cfg(unix)]
  #[tokio::test]
  async fn ytdlp_cancel_stops_the_process() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("slow");
    std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (tx, rx) = watch::channel(false);
    let t0 = std::time::Instant::now();
    let h = tokio::spawn(async move { run(&script, &[], rx, |_| {}).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(true).unwrap();
    assert_eq!(h.await.unwrap().err(), Some(RunError::Cancelled));
    assert!(t0.elapsed() < Duration::from_secs(5));
  }
}

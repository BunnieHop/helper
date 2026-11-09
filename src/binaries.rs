//! The tools a hop needs on the creator's machine: yt-dlp, ffmpeg/ffprobe, and Deno (yt-dlp's
//! JavaScript runtime for YouTube). Found in the Helper's own `bin/` first, then on PATH.
//! Installs come from each project's official releases and are refused unless the published
//! SHA-256 matches.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
  YtDlp,
  Ffmpeg,
  Ffprobe,
  Deno,
}

impl Tool {
  pub const ALL: [Tool; 4] = [Tool::YtDlp, Tool::Ffmpeg, Tool::Ffprobe, Tool::Deno];

  pub fn exe(self) -> &'static str {
    let win = cfg!(windows);
    match (self, win) {
      (Tool::YtDlp, false) => "yt-dlp",
      (Tool::YtDlp, true) => "yt-dlp.exe",
      (Tool::Ffmpeg, false) => "ffmpeg",
      (Tool::Ffmpeg, true) => "ffmpeg.exe",
      (Tool::Ffprobe, false) => "ffprobe",
      (Tool::Ffprobe, true) => "ffprobe.exe",
      (Tool::Deno, false) => "deno",
      (Tool::Deno, true) => "deno.exe",
    }
  }
}

/// Where a tool comes from, and how its checksum is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
  pub url: String,
  pub checksum: Checksum,
  /// The file inside a zip to extract; `None` when the download is the binary itself.
  pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
  /// A `SHA2-256SUMS`-style list; the entry named `name`.
  List { url: String, name: String },
  /// `<download url>.sha256` (or a fixed sibling) holding one digest. Resolved after redirects.
  Sibling { suffix: String },
}

/// Official release assets per OS/arch (data, not logic). `None`: use the system's own copy.
pub fn source(tool: Tool, os: &str, arch: &str) -> Option<Source> {
  let gh =
    |repo: &str, asset: &str| format!("https://github.com/{repo}/releases/latest/download/{asset}");
  match tool {
    Tool::YtDlp => {
      let asset = match (os, arch) {
        ("macos", _) => "yt-dlp_macos",
        ("windows", "x86_64") => "yt-dlp.exe",
        ("windows", "aarch64") => "yt-dlp_arm64.exe",
        ("linux", "x86_64") => "yt-dlp_linux",
        ("linux", "aarch64") => "yt-dlp_linux_aarch64",
        _ => return None,
      };
      Some(Source {
        url: gh("yt-dlp/yt-dlp", asset),
        checksum: Checksum::List {
          url: gh("yt-dlp/yt-dlp", "SHA2-256SUMS"),
          name: asset.into(),
        },
        member: None,
      })
    }
    Tool::Ffmpeg | Tool::Ffprobe => {
      let name = if tool == Tool::Ffmpeg {
        "ffmpeg"
      } else {
        "ffprobe"
      };
      match (os, arch) {
        ("macos", "aarch64" | "x86_64") => {
          let a = if arch == "aarch64" { "arm64" } else { "amd64" };
          Some(Source {
            url: format!(
              "https://ffmpeg.martin-riedl.de/redirect/latest/macos/{a}/release/{name}.zip"
            ),
            checksum: Checksum::Sibling {
              suffix: ".sha256".into(),
            },
            member: Some(name.into()),
          })
        }
        ("windows", "x86_64") => {
          let asset = "ffmpeg-master-latest-win64-gpl.zip";
          Some(Source {
            url: gh("BtbN/FFmpeg-Builds", asset).replace("/latest/download/", "/download/latest/"),
            checksum: Checksum::List {
              url: gh("BtbN/FFmpeg-Builds", "checksums.sha256")
                .replace("/latest/download/", "/download/latest/"),
              name: asset.into(),
            },
            member: Some(format!("ffmpeg-master-latest-win64-gpl/bin/{name}.exe")),
          })
        }
        // Linux: the distribution's ffmpeg is the right one (backlog: static build).
        _ => None,
      }
    }
    Tool::Deno => {
      let triple = match (os, arch) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => return None,
      };
      let asset = format!("deno-{triple}.zip");
      Some(Source {
        url: gh("denoland/deno", &asset),
        checksum: Checksum::Sibling {
          suffix: ".sha256sum".into(),
        },
        member: Some(Tool::Deno.exe().into()),
      })
    }
  }
}

/// Finds `name`'s digest in a `sha256sum`-format list (`<hex>  <name>` or `<hex> *<name>`).
pub fn digest_from_list(list: &str, name: &str) -> Option<String> {
  list.lines().find_map(|l| {
    let mut parts = l.split_whitespace();
    let hex = parts.next()?;
    let file = parts.next()?.trim_start_matches('*');
    (file == name && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
      .then(|| hex.to_ascii_lowercase())
  })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
  hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
  #[error("{0} isn't available for this computer; install it yourself and the Helper will find it on PATH.")]
  Unsupported(&'static str),
  #[error("Download failed: {0}")]
  Network(String),
  #[error("The download didn't match its published checksum (expected {expected}, got {actual}). Nothing was installed.")]
  Checksum { expected: String, actual: String },
  #[error("No published checksum was found for {0}. Nothing was installed.")]
  NoChecksum(String),
  #[error("Couldn't unpack the download: {0}")]
  Archive(String),
  #[error("Couldn't write to the Helper folder: {0}")]
  Io(#[from] std::io::Error),
}

pub struct Binaries {
  pub dir: PathBuf,
}

impl Binaries {
  pub fn new(dir: PathBuf) -> Self {
    Self { dir }
  }

  /// The Helper's own copy, else the first match on PATH.
  pub fn find(&self, tool: Tool) -> Option<PathBuf> {
    let own = self.dir.join(tool.exe());
    if own.is_file() {
      return Some(own);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
      .map(|d| d.join(tool.exe()))
      .find(|p| p.is_file())
  }

  /// Checks the bytes against `expected` and installs them (or the zip member) atomically.
  pub fn install_bytes(
    &self,
    tool: Tool,
    bytes: &[u8],
    expected: &str,
    member: Option<&str>,
  ) -> Result<PathBuf, InstallError> {
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected) {
      return Err(InstallError::Checksum {
        expected: expected.to_string(),
        actual,
      });
    }
    let payload = match member {
      None => bytes.to_vec(),
      Some(m) => extract(bytes, m)?,
    };
    std::fs::create_dir_all(&self.dir)?;
    let dest = self.dir.join(tool.exe());
    let tmp = self.dir.join(format!(".{}.part", tool.exe()));
    std::fs::write(&tmp, &payload)?;
    make_executable(&tmp)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
  }

  /// Downloads `tool` from its official source and installs it after checksum verification.
  pub async fn install(
    &self,
    client: &reqwest::Client,
    tool: Tool,
  ) -> Result<PathBuf, InstallError> {
    let src = source(tool, std::env::consts::OS, std::env::consts::ARCH)
      .ok_or(InstallError::Unsupported(tool.exe()))?;
    let net = |e: reqwest::Error| InstallError::Network(e.without_url().to_string());
    let res = client
      .get(&src.url)
      .send()
      .await
      .map_err(net)?
      .error_for_status()
      .map_err(net)?;
    let final_url = res.url().clone();
    let bytes = res.bytes().await.map_err(net)?;
    let expected = match &src.checksum {
      Checksum::List { url, name } => {
        let list = client
          .get(url)
          .send()
          .await
          .map_err(net)?
          .error_for_status()
          .map_err(net)?
          .text()
          .await
          .map_err(net)?;
        digest_from_list(&list, name).ok_or_else(|| InstallError::NoChecksum(name.clone()))?
      }
      Checksum::Sibling { suffix } => {
        let url = format!("{final_url}{suffix}");
        let text = client
          .get(&url)
          .send()
          .await
          .map_err(net)?
          .error_for_status()
          .map_err(net)?
          .text()
          .await
          .map_err(net)?;
        text
          .split_whitespace()
          .next()
          .filter(|h| h.len() == 64)
          .map(str::to_ascii_lowercase)
          .ok_or_else(|| InstallError::NoChecksum(tool.exe().into()))?
      }
    };
    self.install_bytes(tool, &bytes, &expected, src.member.as_deref())
  }

  /// `--version` of a found tool, for the status screen.
  pub async fn version(&self, tool: Tool) -> Option<String> {
    let exe = self.find(tool)?;
    let arg = if matches!(tool, Tool::Ffmpeg | Tool::Ffprobe) {
      "-version"
    } else {
      "--version"
    };
    let out = tokio::process::Command::new(exe)
      .arg(arg)
      .kill_on_drop(true)
      .output()
      .await
      .ok()?;
    String::from_utf8_lossy(&out.stdout)
      .lines()
      .next()
      .map(|l| l.trim().to_string())
  }
}

fn extract(zip_bytes: &[u8], member: &str) -> Result<Vec<u8>, InstallError> {
  let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
    .map_err(|e| InstallError::Archive(e.to_string()))?;
  // Exact path first, else the same file name anywhere (archives nest a version folder).
  let idx = (0..z.len())
    .find(|&i| z.name_for_index(i) == Some(member))
    .or_else(|| {
      let base = Path::new(member).file_name()?.to_str()?.to_string();
      (0..z.len()).find(|&i| {
        z.name_for_index(i)
          .and_then(|n| Path::new(n).file_name()?.to_str().map(|s| s == base))
          .unwrap_or(false)
      })
    })
    .ok_or_else(|| InstallError::Archive(format!("{member} not in archive")))?;
  let mut f = z
    .by_index(idx)
    .map_err(|e| InstallError::Archive(e.to_string()))?;
  let mut out = Vec::new();
  f.read_to_end(&mut out)?;
  Ok(out)
}

fn make_executable(p: &Path) -> std::io::Result<()> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
  }
  #[cfg(not(unix))]
  let _ = p;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Write;

  #[test]
  fn binaries_checksum_list_parsing() {
    let list = "e51e69e89489f199530f13d32a4342da3ddb2cf34842f364603a066db05afbf3  yt-dlp\nF5389D3698ECDE4EF06F4E6B1CE0294FE9AC1396228C899000000000000000AA *yt-dlp_macos\n";
    assert_eq!(
      digest_from_list(list, "yt-dlp_macos").unwrap(),
      "f5389d3698ecde4ef06f4e6b1ce0294fe9ac1396228c899000000000000000aa"
    );
    assert!(digest_from_list(list, "yt-dlp_linux").is_none());
    assert!(digest_from_list("short  yt-dlp", "yt-dlp").is_none());
  }

  #[test]
  fn binaries_refuse_a_download_whose_checksum_differs() {
    let dir = tempfile::tempdir().unwrap();
    let b = Binaries::new(dir.path().join("bin"));
    let err = b
      .install_bytes(Tool::YtDlp, b"evil", &sha256_hex(b"good"), None)
      .unwrap_err();
    assert!(matches!(err, InstallError::Checksum { .. }));
    assert!(!dir.path().join("bin").join(Tool::YtDlp.exe()).exists());
    let p = b
      .install_bytes(Tool::YtDlp, b"good", &sha256_hex(b"good"), None)
      .unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"good");
    assert_eq!(b.find(Tool::YtDlp).unwrap(), p);
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o755
      );
    }
  }

  #[test]
  fn binaries_extract_the_named_member_from_a_nested_zip() {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
      let mut w = zip::ZipWriter::new(&mut buf);
      let o = zip::write::SimpleFileOptions::default();
      w.start_file("README.txt", o).unwrap();
      w.write_all(b"hi").unwrap();
      w.start_file("ffmpeg-7.1/bin/ffmpeg", o).unwrap();
      w.write_all(b"FFMPEG").unwrap();
      w.finish().unwrap();
    }
    let bytes = buf.into_inner();
    let dir = tempfile::tempdir().unwrap();
    let b = Binaries::new(dir.path().to_path_buf());
    let p = b
      .install_bytes(Tool::Ffmpeg, &bytes, &sha256_hex(&bytes), Some("ffmpeg"))
      .unwrap();
    assert_eq!(std::fs::read(p).unwrap(), b"FFMPEG");
  }

  #[test]
  fn binaries_official_sources_per_platform() {
    let y = source(Tool::YtDlp, "macos", "aarch64").unwrap();
    assert_eq!(
      y.url,
      "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_macos"
    );
    assert_eq!(
      y.checksum,
      Checksum::List {
        url: "https://github.com/yt-dlp/yt-dlp/releases/latest/download/SHA2-256SUMS".into(),
        name: "yt-dlp_macos".into()
      }
    );
    let f = source(Tool::Ffmpeg, "macos", "aarch64").unwrap();
    assert!(f.url.contains("/macos/arm64/release/ffmpeg.zip"));
    assert_eq!(
      f.checksum,
      Checksum::Sibling {
        suffix: ".sha256".into()
      }
    );
    let w = source(Tool::Ffprobe, "windows", "x86_64").unwrap();
    assert_eq!(w.url, "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip");
    assert_eq!(
      w.member.as_deref(),
      Some("ffmpeg-master-latest-win64-gpl/bin/ffprobe.exe")
    );
    assert!(source(Tool::Ffmpeg, "linux", "x86_64").is_none());
    assert!(source(Tool::Deno, "macos", "aarch64")
      .unwrap()
      .url
      .ends_with("deno-aarch64-apple-darwin.zip"));
  }
}

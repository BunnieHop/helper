use std::path::{Path, PathBuf};

/// Where the Helper keeps its own state, and the default vault the creator owns.
#[derive(Debug, Clone)]
pub struct Paths {
  /// App state: pairings, queue, logs. Never media.
  pub data_dir: PathBuf,
  /// Default Backup Vault folder (the creator's files; never deleted by the Helper).
  pub vault_dir: PathBuf,
  /// Scratch space for downloads in flight; emptied after each verified publish.
  pub temp_dir: PathBuf,
}

impl Paths {
  /// OS defaults; `BUNNIEHOP_DATA_DIR` / `BUNNIEHOP_VAULT_DIR` override them (tests, portable installs).
  pub fn system() -> Self {
    let data = std::env::var_os("BUNNIEHOP_DATA_DIR")
      .map(PathBuf::from)
      .unwrap_or_else(|| {
        dirs::data_dir()
          .unwrap_or_else(std::env::temp_dir)
          .join("BunnieHop")
      });
    let vault = std::env::var_os("BUNNIEHOP_VAULT_DIR")
      .map(PathBuf::from)
      .unwrap_or_else(|| {
        dirs::home_dir()
          .unwrap_or_else(std::env::temp_dir)
          .join("BunnieHop")
      });
    Self::under(&data, &vault)
  }

  pub fn under(data: &Path, vault: &Path) -> Self {
    Self {
      data_dir: data.to_path_buf(),
      vault_dir: vault.to_path_buf(),
      temp_dir: data.join("tmp"),
    }
  }

  pub fn ensure(&self) -> std::io::Result<()> {
    std::fs::create_dir_all(&self.data_dir)?;
    std::fs::create_dir_all(&self.temp_dir)?;
    restrict(&self.data_dir)
  }
}

/// Owner-only permissions for Helper state (pairing hashes, queue).
pub fn restrict(path: &Path) -> std::io::Result<()> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
  }
  #[cfg(not(unix))]
  let _ = path;
  Ok(())
}

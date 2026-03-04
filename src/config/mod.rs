pub mod types;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use types::{GlobalConfig, WorkspaceConfig};

const WORKSPACE_CONFIG_FILE: &str = ".ctf.toml";

pub fn find_workspace_root(from: &Path) -> Option<PathBuf> {
  let mut current = from.to_path_buf();
  loop {
    if current.join(WORKSPACE_CONFIG_FILE).exists() {
      return Some(current);
    }
    if !current.pop() {
      return None;
    }
  }
}

pub fn load_workspace_config(workspace_root: &Path) -> Result<WorkspaceConfig> {
  let config_path = workspace_root.join(WORKSPACE_CONFIG_FILE);
  let content = std::fs::read_to_string(&config_path).map_err(|e| {
    Error::Config(format!(
      "Failed to read {}: {e}",
      config_path.display()
    ))
  })?;
  let config: WorkspaceConfig = toml::from_str(&content)?;
  Ok(config)
}

pub fn load_global_config() -> Result<GlobalConfig> {
  let config_dir = dirs::config_dir()
    .ok_or_else(|| Error::Config("Could not determine config directory".into()))?;
  let config_path = config_dir.join("ctf").join("config.toml");

  if !config_path.exists() {
    return Ok(GlobalConfig::default());
  }

  let content = std::fs::read_to_string(&config_path).map_err(|e| {
    Error::Config(format!(
      "Failed to read {}: {e}",
      config_path.display()
    ))
  })?;
  let config: GlobalConfig = toml::from_str(&content)?;
  Ok(config)
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
  pub platform: PlatformConfig,
  pub workspace: WorkspaceSection,
  #[serde(default)]
  pub scaffold: ScaffoldConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
  #[serde(rename = "type")]
  pub platform_type: Option<String>,
  pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSection {
  pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldConfig {
  #[serde(default = "default_template")]
  pub template: String,
  #[serde(default = "default_true")]
  pub create_solve_file: bool,
  #[serde(default = "default_true")]
  pub create_notes_file: bool,
}

impl Default for ScaffoldConfig {
  fn default() -> Self {
    Self {
      template: default_template(),
      create_solve_file: true,
      create_notes_file: true,
    }
  }
}

fn default_template() -> String {
  "{category}/{name}".to_string()
}

fn default_true() -> bool {
  true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
  #[serde(default)]
  pub defaults: GlobalDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDefaults {
  #[serde(default = "default_output")]
  pub output: String,
}

impl Default for GlobalDefaults {
  fn default() -> Self {
    Self {
      output: default_output(),
    }
  }
}

fn default_output() -> String {
  "table".to_string()
}

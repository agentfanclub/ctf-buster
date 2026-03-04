use clap::Subcommand;
use colored::Colorize;
use dialoguer::{Input, Password};

use crate::config::types::PlatformConfig;
use crate::error::{Error, Result};
use crate::platform;

#[derive(Subcommand)]
pub enum AuthCommand {
  /// Log in to a CTF platform
  Login,
  /// Log out (clear stored credentials)
  Logout,
  /// Show current auth status
  Status,
}

fn keyring_key(workspace_name: &str) -> String {
  format!("ctf:{workspace_name}")
}

pub fn store_token(workspace_name: &str, token: &str) -> Result<()> {
  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .set_password(token)
    .map_err(|e| Error::Keyring(e.to_string()))?;
  Ok(())
}

pub fn get_token(workspace_name: &str) -> Result<String> {
  // Check env var first
  if let Ok(token) = std::env::var("CTF_TOKEN") {
    return Ok(token);
  }

  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .get_password()
    .map_err(|e| Error::Auth(format!("No token found. Run `ctf auth login` first. ({e})")))
}

pub fn delete_token(workspace_name: &str) -> Result<()> {
  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .delete_credential()
    .map_err(|e| Error::Keyring(e.to_string()))?;
  Ok(())
}

pub async fn handle_login(workspace_name: &str, platform_url: &str) -> Result<()> {
  let token: String = Password::new()
    .with_prompt("API token")
    .interact()
    .map_err(|e| Error::Auth(e.to_string()))?;

  // Verify the token works
  let config = PlatformConfig {
    platform_type: None,
    url: platform_url.to_string(),
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  store_token(workspace_name, &token)?;

  println!(
    "{} Logged in as {} (score: {})",
    "✓".green().bold(),
    info.name.bold(),
    info.score,
  );
  if let Some(rank) = info.rank {
    println!("  Rank: #{rank}");
  }

  Ok(())
}

pub async fn handle_login_interactive() -> Result<()> {
  let url: String = Input::new()
    .with_prompt("Platform URL")
    .interact_text()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let workspace_name: String = Input::new()
    .with_prompt("Workspace name")
    .interact_text()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let token: String = Password::new()
    .with_prompt("API token")
    .interact()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let config = PlatformConfig {
    platform_type: None,
    url: url.clone(),
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  store_token(&workspace_name, &token)?;

  println!(
    "{} Logged in as {} (score: {})",
    "✓".green().bold(),
    info.name.bold(),
    info.score,
  );
  if let Some(rank) = info.rank {
    println!("  Rank: #{rank}");
  }

  Ok(())
}

pub async fn handle_logout(workspace_name: &str) -> Result<()> {
  delete_token(workspace_name)?;
  println!("{} Logged out", "✓".green().bold());
  Ok(())
}

pub async fn handle_status(workspace_name: &str, platform_url: &str) -> Result<()> {
  let token = get_token(workspace_name)?;
  let config = PlatformConfig {
    platform_type: None,
    url: platform_url.to_string(),
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  println!("Workspace: {}", workspace_name.bold());
  println!("Platform:  {platform_url}");
  println!("Team:      {}", info.name.bold());
  println!("Score:     {}", info.score);
  if let Some(rank) = info.rank {
    println!("Rank:      #{rank}");
  }

  Ok(())
}

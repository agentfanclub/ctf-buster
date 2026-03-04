use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::platform::types::Challenge;

const STATE_FILE: &str = ".ctf-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceState {
  #[serde(default)]
  pub last_sync: Option<DateTime<Utc>>,
  #[serde(default)]
  pub challenges: HashMap<String, ChallengeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeState {
  pub id: String,
  pub name: String,
  pub category: String,
  pub status: ChallengeStatus,
  pub solved_at: Option<DateTime<Utc>>,
  pub points: Option<u32>,
  pub flag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
  Unsolved,
  InProgress,
  Solved,
}

pub fn init_state(workspace_root: &Path) -> Result<()> {
  let state = WorkspaceState::default();
  write_state(workspace_root, &state)
}

pub fn load_state(workspace_root: &Path) -> Result<WorkspaceState> {
  let path = workspace_root.join(STATE_FILE);
  if !path.exists() {
    return Ok(WorkspaceState::default());
  }
  let content = std::fs::read_to_string(&path)?;
  let state: WorkspaceState = serde_json::from_str(&content)?;
  Ok(state)
}

fn write_state(workspace_root: &Path, state: &WorkspaceState) -> Result<()> {
  let path = workspace_root.join(STATE_FILE);
  let content = serde_json::to_string_pretty(state)?;
  std::fs::write(path, content)?;
  Ok(())
}

pub fn update_sync(workspace_root: &Path, challenges: &[Challenge]) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.last_sync = Some(Utc::now());

  for c in challenges {
    let entry = state
      .challenges
      .entry(c.name.to_lowercase())
      .or_insert_with(|| ChallengeState {
        id: c.id.clone(),
        name: c.name.clone(),
        category: c.category.clone(),
        status: ChallengeStatus::Unsolved,
        solved_at: None,
        points: None,
        flag: None,
      });

    // Update from platform data
    entry.id = c.id.clone();
    entry.name = c.name.clone();
    entry.category = c.category.clone();

    if c.solved_by_me && entry.status != ChallengeStatus::Solved {
      entry.status = ChallengeStatus::Solved;
      entry.points = Some(c.value);
    }
  }

  write_state(workspace_root, &state)
}

pub fn mark_solved(
  workspace_root: &Path,
  challenge_id: &str,
  challenge_name: &str,
  points: u32,
  flag: &str,
) -> Result<()> {
  let mut state = load_state(workspace_root)?;

  let key = challenge_name.to_lowercase();
  let entry = state.challenges.entry(key).or_insert_with(|| ChallengeState {
    id: challenge_id.to_string(),
    name: challenge_name.to_string(),
    category: String::new(),
    status: ChallengeStatus::Unsolved,
    solved_at: None,
    points: None,
    flag: None,
  });

  entry.status = ChallengeStatus::Solved;
  entry.solved_at = Some(Utc::now());
  entry.points = Some(points);
  entry.flag = Some(flag.to_string());

  write_state(workspace_root, &state)
}

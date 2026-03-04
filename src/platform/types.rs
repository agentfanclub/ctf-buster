use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
  pub id: String,
  pub name: String,
  pub category: String,
  pub description: String,
  pub value: u32,
  pub solves: u32,
  pub solved_by_me: bool,
  pub files: Vec<ChallengeFile>,
  pub tags: Vec<String>,
  pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeFile {
  pub name: String,
  pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
  pub id: String,
  pub content: Option<String>,
  pub cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmitResult {
  Correct { challenge: String, points: u32 },
  Incorrect,
  AlreadySolved,
  RateLimited { retry_after: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardEntry {
  pub rank: u32,
  pub name: String,
  pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInfo {
  pub name: String,
  pub score: u32,
  pub rank: Option<u32>,
  pub solves: Vec<SolveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolveInfo {
  pub challenge_id: String,
  pub challenge_name: String,
  pub solved_at: DateTime<Utc>,
  pub points: u32,
}

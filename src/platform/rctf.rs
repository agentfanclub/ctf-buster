use std::path::Path;

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::types::*;
use super::Platform;
use crate::error::{Error, Result};

pub struct RctfPlatform {
  base_url: String,
  token: String,
  client: Client,
}

impl RctfPlatform {
  pub fn new(url: String, token: String) -> Self {
    Self { base_url: url.trim_end_matches('/').to_string(), token, client: Client::new() }
  }

  fn api_url(&self, path: &str) -> String {
    format!("{}/api/v1{path}", self.base_url)
  }

  async fn get(&self, path: &str) -> Result<serde_json::Value> {
    let resp = self
      .client
      .get(self.api_url(path))
      .header("Authorization", format!("Bearer {}", self.token))
      .send()
      .await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
      return Err(Error::Platform(format!(
        "rCTF API error ({}): {}",
        status,
        body.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error")
      )));
    }

    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    if kind.starts_with("bad") {
      return Err(Error::Platform(format!(
        "rCTF API error: {}",
        body.get("message").and_then(|m| m.as_str()).unwrap_or(kind)
      )));
    }

    Ok(body)
  }

  async fn post(&self, path: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let resp = self
      .client
      .post(self.api_url(path))
      .header("Authorization", format!("Bearer {}", self.token))
      .header("Content-Type", "application/json")
      .json(payload)
      .send()
      .await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    // rCTF uses various HTTP status codes (400 bad flag, 409 already solved, 429 rate limit)
    // but always includes a `kind` field. Only error on 5xx or missing kind.
    if status.is_server_error() {
      return Err(Error::Platform(format!(
        "rCTF API error ({}): {}",
        status,
        body.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error")
      )));
    }

    Ok(body)
  }
}

#[derive(Debug, Deserialize)]
struct RctfChallenge {
  id: String,
  name: String,
  category: String,
  description: String,
  points: u32,
  solves: u32,
  #[serde(default)]
  files: Vec<RctfFile>,
}

#[derive(Debug, Deserialize)]
struct RctfFile {
  name: String,
  url: String,
}

#[async_trait]
impl Platform for RctfPlatform {
  async fn whoami(&self) -> Result<TeamInfo> {
    let body = self.get("/users/me").await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let name = data.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
    let score = data.get("score").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
    let rank = data.get("globalPlace").and_then(|r| r.as_u64()).map(|r| r as u32);

    let solves = data
      .get("solves")
      .and_then(|s| s.as_array())
      .map(|arr| {
        arr
          .iter()
          .filter_map(|s| {
            let id = s.get("id").and_then(|v| v.as_str())?.to_string();
            let name = s.get("name").and_then(|v| v.as_str())?.to_string();
            let points = s.get("points").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let created_at = s.get("createdAt").and_then(|v| v.as_i64()).unwrap_or(0);
            let solved_at = chrono::DateTime::from_timestamp_millis(created_at).unwrap_or_default();
            Some(SolveInfo { challenge_id: id, challenge_name: name, solved_at, points })
          })
          .collect()
      })
      .unwrap_or_default();

    Ok(TeamInfo { name, score, rank, solves })
  }

  async fn challenges(&self) -> Result<Vec<Challenge>> {
    let body = self.get("/challs").await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let rctf_challs: Vec<RctfChallenge> = serde_json::from_value(data.clone())?;

    // Fetch solves from /users/me to determine solved_by_me
    let solved_ids: std::collections::HashSet<String> = self
      .whoami()
      .await
      .map(|info| info.solves.into_iter().map(|s| s.challenge_id).collect())
      .unwrap_or_default();

    Ok(
      rctf_challs
        .into_iter()
        .map(|c| {
          let solved = solved_ids.contains(&c.id);
          Challenge {
            id: c.id,
            name: c.name,
            category: c.category,
            description: c.description,
            value: c.points,
            solves: c.solves,
            solved_by_me: solved,
            files: c
              .files
              .into_iter()
              .map(|f| ChallengeFile { name: f.name, url: f.url })
              .collect(),
            tags: Vec::new(),
            hints: Vec::new(),
          }
        })
        .collect(),
    )
  }

  async fn challenge(&self, id: &str) -> Result<Challenge> {
    // rCTF doesn't support /challs/{id}, so find it from the full list
    let challenges = self.challenges().await?;
    challenges
      .into_iter()
      .find(|c| c.id == id || c.name == id)
      .ok_or_else(|| Error::Platform(format!("Challenge not found: {id}")))
  }

  async fn submit(&self, challenge_id: &str, flag: &str) -> Result<SubmitResult> {
    let payload = serde_json::json!({ "flag": flag });
    let body = self.post(&format!("/challs/{challenge_id}/submit"), &payload).await?;

    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");

    match kind {
      "goodFlag" => {
        let challenge = self.challenge(challenge_id).await.ok();
        let name =
          challenge.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| challenge_id.to_string());
        let points = challenge.as_ref().map(|c| c.value).unwrap_or(0);
        Ok(SubmitResult::Correct { challenge: name, points })
      }
      "badFlag" => Ok(SubmitResult::Incorrect),
      "badAlreadySolvedFlag" | "badAlreadySolvedChallenge" => Ok(SubmitResult::AlreadySolved),
      "badRateLimit" => {
        let retry_after = body.get("data").and_then(|d| d.get("timeLeft")).and_then(|t| t.as_u64());
        Ok(SubmitResult::RateLimited { retry_after })
      }
      _ => Err(Error::Platform(format!("Unknown rCTF response kind: {kind}"))),
    }
  }

  async fn scoreboard(&self, limit: Option<u32>) -> Result<Vec<ScoreboardEntry>> {
    let limit = limit.unwrap_or(10);
    let body = self.get(&format!("/leaderboard/now?limit={limit}&offset=0")).await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let leaderboard = data
      .get("leaderboard")
      .and_then(|l| l.as_array())
      .ok_or_else(|| Error::Platform("Missing leaderboard array".into()))?;

    let mut entries = Vec::new();
    for (i, entry) in leaderboard.iter().enumerate() {
      let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
      let score = entry.get("score").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
      entries.push(ScoreboardEntry { rank: (i + 1) as u32, name, score });
    }

    Ok(entries)
  }

  async fn download_file(&self, file: &ChallengeFile, dest: &Path) -> Result<()> {
    let url = if file.url.starts_with("http") {
      file.url.clone()
    } else {
      format!("{}{}", self.base_url, file.url)
    };

    let resp = self
      .client
      .get(&url)
      .header("Authorization", format!("Bearer {}", self.token))
      .send()
      .await?;

    let bytes = resp.bytes().await?;
    tokio::fs::write(dest, &bytes).await?;
    Ok(())
  }

  async fn unlock_hint(&self, _hint_id: &str) -> Result<Hint> {
    Err(Error::Platform("rCTF does not support hint unlocking".into()))
  }

  async fn notifications(&self) -> Result<Vec<Notification>> {
    Ok(vec![]) // rCTF does not have a notifications endpoint
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_rctf_challenge() {
    let json = serde_json::json!({
      "id": "abc123",
      "name": "Flag Store",
      "category": "web",
      "description": "Find the hidden flag in the store",
      "points": 250,
      "solves": 15,
      "files": [
        { "name": "app.py", "url": "/dl/app.py" }
      ]
    });

    let c: RctfChallenge = serde_json::from_value(json).unwrap();
    assert_eq!(c.id, "abc123");
    assert_eq!(c.name, "Flag Store");
    assert_eq!(c.category, "web");
    assert_eq!(c.description, "Find the hidden flag in the store");
    assert_eq!(c.points, 250);
    assert_eq!(c.solves, 15);
    assert_eq!(c.files.len(), 1);
    assert_eq!(c.files[0].name, "app.py");
  }

  #[test]
  fn parse_rctf_challenge_no_files() {
    let json = serde_json::json!({
      "id": "def456",
      "name": "Simple Math",
      "category": "misc",
      "description": "What is 2+2?",
      "points": 50,
      "solves": 100
    });

    let c: RctfChallenge = serde_json::from_value(json).unwrap();
    assert!(c.files.is_empty());
  }

  #[test]
  fn rctf_challenge_to_challenge_conversion() {
    let rctf = RctfChallenge {
      id: "abc".into(),
      name: "Test".into(),
      category: "pwn".into(),
      description: "Pwn it".into(),
      points: 400,
      solves: 3,
      files: vec![RctfFile { name: "binary".into(), url: "/dl/binary".into() }],
    };

    let challenge = Challenge {
      id: rctf.id.clone(),
      name: rctf.name.clone(),
      category: rctf.category.clone(),
      description: rctf.description.clone(),
      value: rctf.points,
      solves: rctf.solves,
      solved_by_me: false,
      files: rctf
        .files
        .iter()
        .map(|f| ChallengeFile { name: f.name.clone(), url: f.url.clone() })
        .collect(),
      tags: Vec::new(),
      hints: Vec::new(),
    };

    assert_eq!(challenge.id, "abc");
    assert_eq!(challenge.value, 400);
    assert!(!challenge.solved_by_me);
    assert_eq!(challenge.files.len(), 1);
    assert!(challenge.tags.is_empty());
    assert!(challenge.hints.is_empty());
  }

  #[test]
  fn parse_submit_good_flag() {
    let body = serde_json::json!({
      "kind": "goodFlag",
      "message": "correct"
    });
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap();
    assert_eq!(kind, "goodFlag");
  }

  #[test]
  fn parse_submit_bad_flag() {
    let body = serde_json::json!({
      "kind": "badFlag",
      "message": "incorrect"
    });
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap();
    assert_eq!(kind, "badFlag");
  }

  #[test]
  fn parse_submit_rate_limited() {
    let body = serde_json::json!({
      "kind": "badRateLimit",
      "data": { "timeLeft": 30000 }
    });
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap();
    assert_eq!(kind, "badRateLimit");

    let time_left = body.get("data").and_then(|d| d.get("timeLeft")).and_then(|t| t.as_u64());
    assert_eq!(time_left, Some(30000));
  }

  #[test]
  fn parse_submit_already_solved_flag() {
    let body = serde_json::json!({
      "kind": "badAlreadySolvedFlag",
      "message": "already solved"
    });
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap();
    assert!(kind == "badAlreadySolvedFlag" || kind == "badAlreadySolvedChallenge");
  }

  #[test]
  fn parse_submit_already_solved_challenge() {
    let body = serde_json::json!({
      "kind": "badAlreadySolvedChallenge",
      "message": "already solved"
    });
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap();
    assert!(kind == "badAlreadySolvedFlag" || kind == "badAlreadySolvedChallenge");
  }

  #[test]
  fn parse_leaderboard() {
    let body = serde_json::json!({
      "kind": "goodLeaderboard",
      "data": {
        "leaderboard": [
          { "name": "Team1", "score": 1000 },
          { "name": "Team2", "score": 800 },
          { "name": "Team3", "score": 500 }
        ]
      }
    });

    let leaderboard = body.get("data").unwrap().get("leaderboard").unwrap().as_array().unwrap();

    assert_eq!(leaderboard.len(), 3);
    assert_eq!(leaderboard[0].get("name").unwrap().as_str().unwrap(), "Team1");
    assert_eq!(leaderboard[0].get("score").unwrap().as_u64().unwrap(), 1000);
  }

  #[test]
  fn parse_whoami() {
    let body = serde_json::json!({
      "kind": "goodUserSelfData",
      "data": {
        "name": "MyTeam",
        "score": 1500,
        "globalPlace": 5,
        "solves": [
          {
            "category": "crypto",
            "name": "Easy RSA",
            "points": 100,
            "solves": 50,
            "id": "easy_rsa",
            "createdAt": 1772903886676_i64
          }
        ]
      }
    });

    let data = body.get("data").unwrap();
    let name = data.get("name").unwrap().as_str().unwrap();
    let score = data.get("score").unwrap().as_u64().unwrap();
    let rank = data.get("globalPlace").and_then(|r| r.as_u64());
    let solves = data.get("solves").unwrap().as_array().unwrap();

    assert_eq!(name, "MyTeam");
    assert_eq!(score, 1500);
    assert_eq!(rank, Some(5));
    assert_eq!(solves.len(), 1);
    assert_eq!(solves[0].get("id").unwrap().as_str().unwrap(), "easy_rsa");
  }

  #[test]
  fn api_url_construction() {
    let plat = RctfPlatform::new("https://ctf.example.com/".into(), "token".into());
    assert_eq!(plat.api_url("/challs"), "https://ctf.example.com/api/v1/challs");

    let plat2 = RctfPlatform::new("https://ctf.example.com".into(), "token".into());
    assert_eq!(plat2.api_url("/challs"), "https://ctf.example.com/api/v1/challs");
  }
}

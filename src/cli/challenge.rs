use colored::Colorize;

use crate::cli::OutputFormat;
use crate::error::Result;
use crate::output;
use crate::platform::types::Challenge;
use crate::platform::Platform;

pub async fn handle_list(
  platform: &dyn Platform,
  category: Option<&str>,
  unsolved: bool,
  solved: bool,
  format: &OutputFormat,
) -> Result<()> {
  let mut challenges = platform.challenges().await?;

  if let Some(cat) = category {
    let cat_lower = cat.to_lowercase();
    challenges.retain(|c| c.category.to_lowercase() == cat_lower);
  }

  if unsolved {
    challenges.retain(|c| !c.solved_by_me);
  }

  if solved {
    challenges.retain(|c| c.solved_by_me);
  }

  // Sort by category, then name
  challenges.sort_by(|a, b| {
    a.category
      .cmp(&b.category)
      .then(a.name.cmp(&b.name))
  });

  match format {
    OutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(&challenges)?);
    }
    _ => {
      output::table::print_challenges(&challenges);
    }
  }

  Ok(())
}

pub async fn handle_show(
  platform: &dyn Platform,
  id_or_name: &str,
  challenges: &[Challenge],
) -> Result<()> {
  let challenge = resolve_challenge(platform, id_or_name, challenges).await?;

  println!("{} {}", "Challenge:".bold(), challenge.name.bold().cyan());
  println!("{} {}", "Category: ".bold(), challenge.category);
  println!("{} {}", "Points:   ".bold(), challenge.value);
  println!("{} {}", "Solves:   ".bold(), challenge.solves);

  let status = if challenge.solved_by_me {
    "Solved".green().to_string()
  } else {
    "Unsolved".red().to_string()
  };
  println!("{} {status}", "Status:   ".bold());

  if !challenge.tags.is_empty() {
    println!("{} {}", "Tags:     ".bold(), challenge.tags.join(", "));
  }

  if !challenge.description.is_empty() {
    println!();
    println!("{}", "Description:".bold());
    println!("{}", challenge.description);
  }

  if !challenge.files.is_empty() {
    println!();
    println!("{}", "Files:".bold());
    for file in &challenge.files {
      println!("  - {}", file.name);
    }
  }

  if !challenge.hints.is_empty() {
    println!();
    println!("{}", "Hints:".bold());
    for hint in &challenge.hints {
      match &hint.content {
        Some(content) => println!("  - {content}"),
        None => println!("  - [Locked, cost: {}]", hint.cost),
      }
    }
  }

  Ok(())
}

pub async fn resolve_challenge(
  platform: &dyn Platform,
  id_or_name: &str,
  cached_challenges: &[Challenge],
) -> Result<Challenge> {
  // Try numeric ID first
  if id_or_name.parse::<u64>().is_ok() {
    return platform.challenge(id_or_name).await;
  }

  // Try exact name match
  let lower = id_or_name.to_lowercase();
  if let Some(c) = cached_challenges
    .iter()
    .find(|c| c.name.to_lowercase() == lower)
  {
    return platform.challenge(&c.id).await;
  }

  // Try fuzzy match (substring)
  let matches: Vec<_> = cached_challenges
    .iter()
    .filter(|c| c.name.to_lowercase().contains(&lower))
    .collect();

  match matches.len() {
    0 => Err(crate::error::Error::ChallengeNotFound(
      id_or_name.to_string(),
    )),
    1 => platform.challenge(&matches[0].id).await,
    _ => {
      let names: Vec<_> = matches.iter().map(|c| c.name.as_str()).collect();
      Err(crate::error::Error::ChallengeNotFound(format!(
        "Ambiguous name '{}'. Matches: {}",
        id_or_name,
        names.join(", ")
      )))
    }
  }
}

use std::path::{Path, PathBuf};

use crate::config::types::ScaffoldConfig;
use crate::error::Result;
use crate::platform::types::Challenge;

/// Returns the directory path for a challenge based on the scaffold template.
pub fn challenge_dir(
  workspace_root: &Path,
  challenge: &Challenge,
  config: &ScaffoldConfig,
) -> PathBuf {
  let path = config
    .template
    .replace("{category}", &sanitize_name(&challenge.category))
    .replace("{name}", &sanitize_name(&challenge.name));
  workspace_root.join(path)
}

/// Scaffold a challenge directory. Returns true if the directory was newly created.
pub fn scaffold_challenge(
  workspace_root: &Path,
  challenge: &Challenge,
  config: &ScaffoldConfig,
) -> Result<bool> {
  let dir = challenge_dir(workspace_root, challenge, config);

  if dir.exists() {
    return Ok(false);
  }

  std::fs::create_dir_all(&dir)?;

  if config.create_solve_file {
    let solve_path = dir.join("solve.py");
    if !solve_path.exists() {
      std::fs::write(&solve_path, generate_solve_template(challenge))?;
    }
  }

  if config.create_notes_file {
    let notes_path = dir.join("notes.md");
    if !notes_path.exists() {
      std::fs::write(&notes_path, generate_notes_template(challenge))?;
    }
  }

  Ok(true)
}

fn sanitize_name(name: &str) -> String {
  name
    .to_lowercase()
    .chars()
    .map(|c| {
      if c.is_alphanumeric() || c == '-' || c == '_' {
        c
      } else if c == ' ' {
        '-'
      } else {
        '_'
      }
    })
    .collect()
}

fn generate_solve_template(challenge: &Challenge) -> String {
  format!(
    r#"#!/usr/bin/env python3
"""
{name} ({category}, {value} pts)
"""

from pwn import *

# challenge files in ./dist/
"#,
    name = challenge.name,
    category = challenge.category,
    value = challenge.value,
  )
}

fn generate_notes_template(challenge: &Challenge) -> String {
  format!(
    r#"# {name}

**Category:** {category}
**Points:** {value}
**Solves:** {solves}

## Description

{description}

## Notes

"#,
    name = challenge.name,
    category = challenge.category,
    value = challenge.value,
    solves = challenge.solves,
    description = challenge.description,
  )
}

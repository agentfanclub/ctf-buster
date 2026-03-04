# CTF-Buster

AI-powered CTF competition toolkit. Rust CLI + 4 MCP servers (26 tools total).

## Architecture

```
ctf-buster (Rust)     — 9 tools: platform interaction (CTFd/rCTF)
ctf-crypto (Python)   — 6 tools: encoding chains, RSA attacks, constraint solving
ctf-binary (Python)   — 8 tools: triage, disassembly, ROP, pwntools, angr
ctf-forensics (Python) — 5 tools: file analysis, stego, extraction, entropy
```

All servers communicate over MCP stdio transport.

## CTF Competition Workflow

When working on a CTF competition, use this multi-agent orchestration strategy.

### 1. Initial Recon

```
ctf_sync(full=true)          # Fetch all challenges + descriptions + files
ctf_workspace_status()       # See score, progress, categories
ctf_challenges(unsolved=true) # List what's left to solve
```

### 2. Orchestration Loop

The main agent acts as an **orchestrator** — it does NOT solve challenges directly.
Instead it launches subagents and monitors progress:

```
while unsolved challenges remain:
  1. ctf_challenges(unsolved=true)         # Get current unsolved list
  2. Prioritize: easy/low-solve challenges first, then by category strength
  3. Launch subagents (Task tool) for batches of challenges
  4. Wait for results, collect flags
  5. ctf_workspace_status()                # Check updated score/progress
  6. Re-sync if needed: ctf_sync()         # Picks up newly solved status
```

Key orchestration rules:
- **Always check `ctf_challenges(unsolved=true)` before launching new agents** — avoids
  re-attempting challenges already solved by another subagent
- **State is shared** — `ctf_submit_flag` writes to `.ctf-state.json` which tracks every
  solve with timestamp, flag, and points. `ctf_workspace_status` reads this.
- **Re-sync periodically** — `ctf_sync()` updates local state from the platform, catching
  solves from other team members too
- **Batch by difficulty** — start with "easy" tagged challenges, then "medium", then "hard"
- **Time-box subagents** — if a challenge isn't progressing, move on and come back later

### 3. Subagent Structure

Each subagent receives a specific challenge (or small batch) to solve:

```
Subagent prompt pattern:
  "Solve CTF challenge '{name}' (category: {category}, {points} pts).
   Description: {description}
   Files: {file_list}
   Workspace: {workspace_path}

   Steps:
   1. Download files with ctf_download_files('{name}')
   2. Triage with {appropriate_triage_tool}
   3. Analyze and solve
   4. Submit flag with ctf_submit_flag('{name}', 'flag{...}')
   5. Report back: solved/unsolved/needs-help"
```

For parallel execution, launch multiple subagents in a single message using the Task tool.

### 4. Category-Specific Approaches

**Crypto challenges:**
- `crypto_identify` to detect encoding/cipher type
- `transform_chain` for multi-step decode pipelines
- `rsa_toolkit` for RSA challenges (auto-tries factordb, fermat, wiener, small-e)
- `math_solve` with z3 mode for constraint problems
- `frequency_analysis` for classical ciphers

**Binary/Pwn challenges:**
- `binary_triage` first — get checksec, imports, dangerous functions, architecture
- `disassemble` to read key functions
- `angr_analyze` for automatic solving of simple stack-based challenges:
  - `auto` mode: finds inputs producing flag-like output
  - `find_addr` mode: finds inputs reaching a specific address
  - `find_string` mode: finds inputs causing specific output
- `find_rop_gadgets` for ROP chains
- `pattern_offset` to find buffer overflow offsets
- `pwntools_template` to generate exploit scripts
- `shellcode_generate` for shellcode payloads
- Use bash + pwntools/gdb for interactive exploitation

**Forensics/Stego challenges:**
- `file_triage` first — get file type, metadata, embedded data, entropy
- `stego_analyze` systematically tries all stego tools for the file type
- `extract_embedded` for binwalk/foremost extraction
- `entropy_analysis` to find encrypted/compressed regions
- `image_analysis` for deep image inspection (LSB, channels, histograms)

**Web challenges:**
- Use bash directly: curl, sqlmap, ffuf, nuclei, nikto, etc.
- These tools work well from bash and don't need MCP wrapping

### 5. Progress Tracking & Flag Submission

- **Always submit via `ctf_submit_flag`** — this writes to `.ctf-state.json` with the flag,
  points, and timestamp. Never submit flags manually via curl/bash.
- **Check progress often** — `ctf_workspace_status()` gives a live scoreboard-style view
  of solved/unsolved per category
- **`ctf_challenges(solved=true)`** — review what's been solved to avoid duplicating work
- **Flags are stored** — `.ctf-state.json` keeps every flag for later reference. The
  `mark_solved` function records challenge ID, name, points, flag, and solve timestamp.
- **Platform sync** — `ctf_sync()` also detects solves made outside ctf-buster (e.g. by
  teammates) via the `solved_by_me` field from the API

## Development

### Build & Test

```bash
nix develop                                    # Enter devShell
cargo build --release                          # Build Rust CLI
cargo test                                     # Run Rust tests (56 tests)
cargo clippy -- -W clippy::all                 # Lint Rust
python3 -m pytest tools/tests/                 # Run Python tests (151 tests)
python3 -m pytest tools/tests/ --cov=tools     # Python coverage
cargo tarpaulin                                # Rust coverage
```

### Project Structure

```
src/                    Rust CLI + MCP server
  cli/                  CLI command handlers
  config/               Workspace config (.ctf.toml)
  mcp/                  MCP server (rmcp)
  platform/             CTFd + rCTF API clients
  workspace/            Scaffolding + state management
tools/                  Python MCP servers
  ctf_crypto.py         Crypto & encoding server
  ctf_binary.py         Binary analysis server
  ctf_forensics.py      Forensics & stego server
  lib/                  Shared subprocess utilities
  tests/                Python test suite
```

### MCP Server Registration

```bash
claude mcp add -s user ctf-buster -- /path/to/target/release/ctf mcp --workspace /path/to/workspace
claude mcp add -s user ctf-crypto -- python3 /path/to/tools/ctf_crypto.py
claude mcp add -s user ctf-binary -- python3 /path/to/tools/ctf_binary.py
claude mcp add -s user ctf-forensics -- python3 /path/to/tools/ctf_forensics.py
```

The Rust server needs `CTF_TOKEN` env var set for platform authentication.

## Conventions

- Rust: stable toolchain, `cargo clippy -- -W clippy::all` clean
- Python: no external deps beyond what's in flake.nix pythonEnv
- All Python MCP servers use fastmcp with stdio transport
- Tools return JSON strings for structured data
- Security tools are for authorized CTF competitions only

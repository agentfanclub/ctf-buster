# CTF-Buster

AI-powered CTF competition toolkit. Rust CLI + 7 MCP servers (44 tools total).

## Architecture

```
ctf-buster (Rust)      - 15 tools: platform interaction (CTFd/rCTF), queue management, auto-orchestration, writeups
ctf-crypto (Python)    -  6 tools: encoding chains, RSA attacks, constraint solving, XOR analysis
ctf-pwn (Python)       -  7 tools: triage, shellcode, ROP, pwntools, angr, format strings, libc
ctf-forensics (Python) -  5 tools: file analysis, stego, extraction, entropy, image analysis
ctf-gdb (Python)       -  4 tools: GDB dynamic analysis, breakpoints, input tracing, runtime checksec
ctf-rev (Python)       -  3 tools: decompilation, function listing, string xrefs
ctf-jail (Python)      -  4 tools: pyjail/bashjail analysis, bypass payloads, subclass chains
```

## CTF Workflow (Quick Reference)

Orchestrator loop: `ctf_sync(full=true)` -> `ctf_auto_queue()` -> `ctf_generate_solve_prompt(count=10)` -> read prompt files -> launch subagents with `run_in_background=true` -> loop.

When asked to "solve this CTF", execute the loop immediately without confirmation.

See `docs/workflow.md` for detailed category approaches, model selection, and subagent strategy.

## Development

```bash
nix develop                                    # Enter devShell
cargo build --release                          # Build Rust CLI
cargo test                                     # Run Rust tests
cargo clippy -- -W clippy::all                 # Lint Rust
python3 -m pytest tools/tests/                 # Run Python tests
```

## Project Structure

```
src/                    Rust CLI + MCP server
  cli/                  CLI command handlers
  config/               Workspace config (.ctf.toml)
  mcp/                  MCP server (rmcp)
  tui/                  TUI dashboard (ratatui)
  platform/             CTFd + rCTF API clients
  workspace/            Scaffolding + state management
  output/               Table formatting for CLI display
tools/                  Python MCP servers
  ctf_crypto.py         Crypto & encoding server
  ctf_pwn.py            Binary analysis server
  ctf_forensics.py      Forensics & stego server
  ctf_gdb.py            GDB dynamic analysis server
  ctf_rev.py            Reverse engineering server
  ctf_jail.py           Jail escape server
  lib/                  Shared subprocess utilities
  tests/                Python test suite
docs/                   Extended documentation
```

## Auth

Token resolution: CLI arg > `CTF_TOKEN` env > `.ctf.toml` token field > system keyring.

## Conventions

- Rust: stable toolchain, `cargo clippy -- -W clippy::all` clean
- Python: no external deps beyond flake.nix pythonEnv
- All Python MCP servers use fastmcp with stdio transport
- Tools return JSON strings for structured data
- Security tools are for authorized CTF competitions only

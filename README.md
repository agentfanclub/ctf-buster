# CTF-Buster

An AI-powered CTF (Capture The Flag) toolkit combining a Rust CLI with seven MCP
(Model Context Protocol) servers. Designed to let AI agents, particularly
Claude Code, interact with CTFd and rCTF platforms, perform cryptographic
attacks, analyze binaries, and run forensic investigations, all from a unified
workspace.

## Features

- **Platform integration** - authenticate, sync challenges, submit flags, and
  track scores on CTFd and rCTF with automatic platform detection.
- **Workspace management** - initialize per-competition workspaces with
  scaffolded directories, solve templates, and notes files.
- **7 MCP servers / 44 tools** - expose every capability over MCP so AI agents
  can call them directly.
- **TUI dashboard** - run `ctf dashboard` in a separate terminal to monitor
  progress in real-time while the AI orchestrator works.
- **90+ security tools** - the Nix dev shell bundles a curated set of
  security CLI tools (radare2, Ghidra, binwalk, hashcat, pwntools, angr, z3,
  and many more).
- **Multi-agent orchestration** - priority queue, model selection, and
  parallel subagent coordination for solving challenges at scale.

## Architecture

```
                        Claude Code / AI Agent
                                |
    +--------+--------+---------+---------+---------+--------+--------+
    |        |        |                   |         |        |        |
ctf-buster ctf-crypto ctf-pwn    ctf-forensics  ctf-gdb  ctf-rev  ctf-jail
  (Rust)   (Python)   (Python)     (Python)     (Python) (Python) (Python)
 15 tools  6 tools    7 tools      5 tools      4 tools  3 tools  4 tools
    |          |          |            |            |        |        |
 CTFd/rCTF  sympy,z3  radare2,pwn  binwalk,    GDB      radare2  pyjail
 platforms  crypto    ROPgadget    zsteg,PIL   batch     r2ghidra bashjail
```

All seven servers communicate over **stdio** using the Model Context Protocol.
The Rust server (`ctf-buster`) handles platform interaction, workspace
management, and orchestration queuing. The six Python servers handle
domain-specific analysis, built on the
[FastMCP](https://github.com/jlowin/fastmcp) framework.

## Quick Start

```bash
# Enter the dev shell (includes Rust toolchain, Python env, 90+ security tools)
nix develop

# Build the CLI
cargo build --release

# Initialize a workspace for a competition
ctf init my-ctf --url https://ctf.example.com

# Authenticate (token stored in system keyring)
ctf auth login

# Sync challenges, scaffold directories, download files
ctf sync --full

# List unsolved challenges
ctf challenges --unsolved

# Submit a flag
ctf submit "challenge-name" "flag{...}"
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, module structure, platform abstraction |
| [CLI Reference](docs/cli-reference.md) | All CLI commands with examples |
| [MCP Tools](docs/mcp-tools.md) | All 44 tools across 7 MCP servers |
| [Configuration](docs/configuration.md) | `.ctf.toml`, authentication, scaffold templates |
| [Integration](docs/integration.md) | Claude Code setup and `.mcp.json` |
| [Security Tools](docs/security-tools.md) | 90+ tools available in the Nix dev shell |
| [Workflow](docs/workflow.md) | Orchestration loop, category approaches, subagent strategy |

## Development

```bash
nix develop                        # Enter dev shell
cargo build --release              # Build Rust CLI
cargo test                         # Run Rust tests (165 tests)
cargo clippy -- -W clippy::all     # Lint Rust
python3 -m pytest tools/tests/     # Run Python tests (396 tests)
```

## Platform Support

| Platform | Status | Auth method |
|----------|--------|-------------|
| [CTFd](https://ctfd.io/) | Supported | API token or session cookie |
| [rCTF](https://rctf.redpwn.net/) | Supported | API token (JWT) |

## License

See [LICENSE](LICENSE) for details.

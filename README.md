# CTF-Buster

An AI-powered CTF (Capture The Flag) toolkit combining a Rust CLI with four MCP
(Model Context Protocol) servers. Designed to let AI agents -- particularly
Claude Code -- interact with CTFd and rCTF platforms, perform cryptographic
attacks, analyze binaries, and run forensic investigations, all from a unified
workspace.

## Features

- **Platform integration** -- authenticate, sync challenges, submit flags, and
  track scores on CTFd and rCTF with automatic platform detection.
- **Workspace management** -- initialize per-competition workspaces with
  scaffolded directories, solve templates, and notes files.
- **4 MCP servers / 26 tools** -- expose every capability over MCP so AI agents
  can call them directly.
- **160+ security tools** -- the Nix dev shell bundles a curated set of
  security CLI tools (radare2, Ghidra, binwalk, hashcat, pwntools, angr, z3,
  and many more).
- **Multi-format output** -- CLI supports `--output table|json|plain` for
  scripting and human consumption.

## Architecture

```
                        Claude Code / AI Agent
                                |
          +-----------+---------+---------+-----------+
          |           |                   |           |
   ctf-buster     ctf-crypto      ctf-binary    ctf-forensics
    (Rust)        (Python)         (Python)       (Python)
    9 tools       6 tools          6 tools        5 tools
      |               |               |               |
   CTFd/rCTF     sympy, z3       radare2, pwn    binwalk, zsteg
   platforms     cryptography    ROPgadget        steghide, PIL
```

All four servers communicate over **stdio** using the Model Context Protocol.
The Rust server (`ctf-buster`) handles platform interaction and workspace
management. The three Python servers (`ctf-crypto`, `ctf-binary`,
`ctf-forensics`) handle domain-specific analysis, built on the
[FastMCP](https://github.com/jlowin/fastmcp) framework.

## Quick Start

```bash
# Enter the dev shell (includes Rust toolchain, Python env, 160+ security tools)
nix develop

# Build the CLI
cargo build --release

# Initialize a workspace for a competition
ctf init my-ctf --url https://ctf.example.com

# Authenticate (token stored in system keyring)
ctf auth login

# Sync challenges, scaffold directories, download files
ctf sync --full

# List challenges
ctf challenges --unsolved

# Submit a flag
ctf submit "challenge-name" "flag{...}"
```

## CLI Reference

The binary is named `ctf`. All commands support `--output table|json|plain`.

| Command | Aliases | Description |
|---------|---------|-------------|
| `ctf init <name> --url <url>` | | Initialize a CTF workspace. Creates `.ctf.toml` and directory structure. Optionally pass `--type ctfd\|rctf` to skip auto-detection. |
| `ctf auth login` | | Authenticate with the platform. Stores the API token in the system keyring. |
| `ctf auth logout` | | Remove stored credentials. |
| `ctf auth status` | | Show current authentication state. |
| `ctf sync` | | Sync challenges from the platform, scaffold directories, download attached files. Pass `--full` to also cache descriptions and hints. |
| `ctf challenges` | `ls`, `chals` | List all challenges. Filter with `--category <cat>`, `--unsolved`, or `--solved`. |
| `ctf challenge <id_or_name>` | | Show full details of a challenge (description, hints, files, solve count). Pass `--download` to fetch attached files. |
| `ctf submit <flag>` | `sub` | Submit a flag. Accepts either `ctf submit <flag>` or `ctf submit <challenge> <flag>`. |
| `ctf files <id_or_name>` | `dl` | Download challenge files into the workspace `dist/` directory. |
| `ctf scoreboard` | `sb` | Show competition scoreboard. Use `--limit <n>` to control how many entries (default 10). |
| `ctf status` | | Dashboard showing team info, score, rank, and per-category solve progress. |
| `ctf mcp` | | Run as an MCP server over stdio. Optionally pass `--workspace <path>` or set `CTF_WORKSPACE`. |

## MCP Server Reference

### ctf-buster (Rust) -- 9 tools

Platform interaction and workspace management.

| Tool | Description |
|------|-------------|
| `ctf_whoami` | Get info about the authenticated team/user -- name, score, rank. |
| `ctf_challenges` | List challenges with optional filters (category, solved/unsolved). Returns cached descriptions when available. |
| `ctf_challenge_detail` | Get full details of a challenge by ID or name -- description, hints, files, solve count. |
| `ctf_submit_flag` | Submit a flag for a challenge. Returns correct, incorrect, already solved, or rate-limited. |
| `ctf_scoreboard` | Show competition scoreboard with team rankings. |
| `ctf_sync` | Sync challenges from the platform -- creates workspace directories, downloads files, updates local state. Use `full=true` to cache all descriptions and hints. |
| `ctf_download_files` | Download files attached to a challenge into the workspace. |
| `ctf_workspace_status` | Get workspace status -- team info, score, challenge counts per category, solve progress. |
| `ctf_unlock_hint` | Unlock a hint for a challenge (may cost points). |

### ctf-crypto (Python) -- 6 tools

Encoding pipelines, cryptographic attacks, and mathematical solving.

| Tool | Description |
|------|-------------|
| `transform_chain` | Apply a chain of encoding/decoding operations (base64, hex, rot(N), xor, vigenere, URL, binary, atbash, etc.) with intermediate results. |
| `crypto_identify` | Identify encoding or cipher type -- detects Base64, hex, hashes (MD5/SHA), JWT, binary, Caesar shifts, URL encoding. |
| `rsa_toolkit` | RSA attacks: auto, small_e, fermat, wiener, factordb, or given_pq. Accepts n, e, c, and optional p/q/dp/dq. |
| `math_solve` | Evaluate sympy expressions (`mode="eval"`) or solve Z3 constraints (`mode="z3"` with semicolon-separated constraints). |
| `hash_crack` | Identify hash type and attempt lightweight dictionary cracking. Supports MD5, SHA-1, SHA-256, SHA-512, bcrypt, crypt variants. |
| `frequency_analysis` | Character and bigram frequency analysis, chi-squared English scoring, and index of coincidence for classical cipher analysis. |

### ctf-binary (Python) -- 6 tools

Binary analysis and exploit development.

| Tool | Description |
|------|-------------|
| `binary_triage` | Comprehensive one-shot analysis -- file type, checksec mitigations, architecture, imports/exports, sections, dangerous functions, interesting strings. |
| `disassemble` | Disassemble a function or address range using radare2. |
| `find_rop_gadgets` | Search for ROP gadgets using ROPgadget with optional filters. |
| `pattern_offset` | Generate cyclic patterns or find crash offsets using pwntools. |
| `shellcode_generate` | Generate shellcode via pwntools shellcraft (sh, cat_flag, connect_back, execve) for amd64/i386/arm/aarch64/mips. |
| `pwntools_template` | Generate a complete pwntools exploit script skeleton (ret2win, ret2libc, format_string, shellcode) from binary analysis. |

### ctf-forensics (Python) -- 5 tools

File forensics and steganography.

| Tool | Description |
|------|-------------|
| `file_triage` | Comprehensive file analysis -- file type, EXIF metadata, binwalk signatures, interesting strings, entropy, trailing data detection. |
| `stego_analyze` | Systematic steganography analysis. Runs all applicable tools per file type: zsteg (PNG), steghide (JPEG/BMP/WAV), EXIF comments, trailing data, LSB. |
| `extract_embedded` | Extract embedded files using binwalk and foremost. Returns extracted file types, sizes, and content previews. |
| `entropy_analysis` | Block-level Shannon entropy calculation to detect encrypted/compressed regions and anomalous boundaries. |
| `image_analysis` | Deep image inspection -- channel statistics, LSB ratio analysis, palette examination, histogram anomaly detection. Optional LSB data extraction. |

## Claude Code Integration

Register all four MCP servers with Claude Code:

```bash
# Rust MCP server (platform interaction)
claude mcp add ctf-buster -- cargo run -q -- mcp --workspace /path/to/workspace

# Python MCP servers (domain tools)
claude mcp add ctf-crypto -- python tools/ctf_crypto.py
claude mcp add ctf-binary -- python tools/ctf_binary.py
claude mcp add ctf-forensics -- python tools/ctf_forensics.py
```

Once registered, Claude Code can call any of the 26 tools directly. A typical
workflow:

1. `ctf_workspace_status` -- understand the current competition state.
2. `ctf_challenges` -- browse available challenges.
3. `ctf_challenge_detail` -- read a specific challenge description.
4. `ctf_download_files` -- pull challenge attachments into the workspace.
5. Use domain tools (`binary_triage`, `file_triage`, `rsa_toolkit`, etc.) to
   analyze files and develop solutions.
6. `ctf_submit_flag` -- submit the flag.

## Configuration

Each workspace is defined by a `.ctf.toml` file at the workspace root.

### Minimal configuration

```toml
[platform]
url = "https://ctf.example.com"

[workspace]
name = "my-ctf"
```

### Full configuration

```toml
[platform]
type = "ctfd"                    # "ctfd" or "rctf" (auto-detected if omitted)
url = "https://ctf.example.com"

[workspace]
name = "heroctf"

[scaffold]
template = "{category}/{name}"   # Directory layout template (default)
create_solve_file = true         # Generate solve.py per challenge (default: true)
create_notes_file = true         # Generate notes.md per challenge (default: true)
```

### Scaffold template variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{category}` | Challenge category, lowercased and sanitized | `crypto` |
| `{name}` | Challenge name, lowercased and sanitized | `easy-rsa` |

### Workspace structure

After syncing, a workspace looks like this:

```
my-ctf/
  .ctf.toml
  crypto/
    easy-rsa/
      solve.py          # Auto-generated solve template
      notes.md          # Auto-generated notes with description
      dist/             # Downloaded challenge files
        output.txt
        rsa.pub
  web/
    login-bypass/
      solve.py
      notes.md
      dist/
        app.py
```

## Development

### Prerequisites

- [Nix](https://nixos.org/) with flakes enabled (provides the entire toolchain)

### Building

```bash
nix develop          # Enter dev shell
cargo build          # Debug build
cargo build --release
```

### Testing

```bash
# Rust tests
cargo test

# Python MCP server tests
pytest tools/
```

### Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out html
```

## Security Toolkit

The `nix develop` shell provides over **160 pre-configured security tools**,
including but not limited to:

| Category | Tools |
|----------|-------|
| Reverse engineering | radare2, Ghidra, cutter, iaito, rizin, dex2jar, jadx, apktool |
| Binary exploitation | gdb, lldb, pwntools, ROPgadget, ropper, one_gadget, patchelf, checksec |
| Forensics | binwalk, foremost, sleuthkit, autopsy, volatility3, bulk_extractor, exiftool, testdisk |
| Steganography | steghide, stegsolve, zsteg |
| Web | burpsuite, sqlmap, ffuf, feroxbuster, gobuster, nikto, whatweb, dalfox, commix |
| Crypto | hashcat, john, fcrackzip, SageMath |
| Networking | nmap, wireshark-cli, tcpdump, masscan, rustscan, scapy, mitmproxy |
| OSINT | amass, subfinder, theharvester, sherlock, recon-ng, gitleaks, trufflehog |
| Password attacks | hydra, medusa, hashcat, john, crowbar, kerbrute |

The Python environment includes angr, z3-solver, pwntools, pycryptodome,
cryptography, sympy, capstone, keystone-engine, unicorn, scapy, pillow, and
opencv.

## Platform Support

| Platform | Status | Auth method |
|----------|--------|-------------|
| [CTFd](https://ctfd.io/) | Supported | API token |
| [rCTF](https://rctf.redpwn.net/) | Supported | API token |

Platform type is **auto-detected** by probing the `/api/v1/` endpoints. You can
override detection by setting `type` in the `[platform]` section of `.ctf.toml`.

## License

See [LICENSE](LICENSE) for details.

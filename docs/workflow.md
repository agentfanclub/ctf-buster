# CTF Competition Workflow

Detailed orchestration workflow, category approaches, and subagent strategy.

## Initial Recon

```
ctf_sync(full=true)          # Fetch all challenges + descriptions + files + unlock free hints
ctf_workspace_status()       # See score, progress, categories
ctf_challenges(unsolved=true) # List what's left to solve
ctf_notifications()          # Check for announcements, errata, format changes
```

## Challenge Priority Queue

Call `ctf_auto_queue()` to auto-score and queue all unsolved challenges.

Scoring algorithm:
```
priority = category_score + difficulty_bonus + solve_bonus

category_score: crypto/forensics +10, web/jail +8, rev +6, misc +4, pwn +2
difficulty_bonus: >50 solves +20, 20-50 +10, <20 +0
solve_bonus: points/solves < 10 → +5
failure_penalty: previously failed → -10
```

Queue rules:
- Process in descending priority order
- Batch by category when launching parallel subagents
- Skip challenges already in-progress
- Re-queue failed challenges with -10 penalty
- Time-box: if no progress after agent's full turn, mark "needs-help"

## Orchestration Loop

The main agent acts as an **orchestrator** — it does NOT solve challenges directly.

```
while unsolved challenges remain:
  1. ctf_sync(full=true)                   # Fetch challenges + descriptions + files
  2. ctf_auto_queue()                      # Auto-score and queue all unsolved
  3. ctf_generate_solve_prompt(count=10)   # Get prompts for top 10
  4. For each prompt: Read the prompt_file, then launch a subagent:
     Task(
       description="Solve <challenge_name>",
       prompt=<content read from prompt_file>,
       model=<recommended_model>,
       subagent_type="general-purpose",
       run_in_background=true
     )
  5. Do NOT wait — loop back to step 1 immediately.
  6. When a batch completes, review results and continue launching.
```

**One-command start:** When asked to "solve this CTF" or "start solving", execute steps
1-4 immediately without asking for confirmation.

**Continuous throughput:** Launch 10 subagents per batch. The queue system handles dedup:
- `ctf_generate_solve_prompt` auto-marks challenges as in_progress
- `ctf_auto_queue` skips in_progress and solved challenges
- Subagents auto-submit flags and auto-mark queue state (complete/fail)

Key rules:
- Always re-sync before each batch
- `ctf_generate_solve_prompt` auto-marks in_progress (no manual start needed)
- State is shared via `.ctf-state.json`
- Use `ctf_queue_update(action='prioritize')` to bump a challenge
- Use `ctf_queue_update(action='retry')` to retry failures

## Model Selection

`ctf_generate_solve_prompt` auto-selects models:
- **opus**: retries, >300pts, hard crypto/pwn
- **sonnet**: most first attempts, web, forensics, easy crypto/pwn
- **haiku**: very easy challenges (priority >= 30)

## Subagent Prompt Structure

`ctf_generate_solve_prompt(count=N)` generates prompt files. Each contains:
1. Download files with ctf_download_files
2. Read solve.py (category template or prior work)
3. Triage with category-appropriate tools
4. Build solution in solve.py incrementally
5. AUTO-SUBMIT any flag-like strings immediately
6. On correct flag, call ctf_save_writeup
7. Report: solved/unsolved/needs-help

**Flag detection:** Submit immediately on seeing flag{...}, CTF{...}, etc.
Never hold a flag. `ctf_submit_flag` returns correct/incorrect safely.

## Category-Specific Approaches

**Crypto:** crypto_identify → crypto_transform_chain / crypto_rsa_toolkit / crypto_math_solve / crypto_xor_analyze. SageMath/hashcat from bash.

**Pwn:** pwn_triage → rev_decompile → gdb_trace_input / pwn_format_string / pwn_angr_analyze. ROPgadget/one_gadget from bash.

**Rev:** rev_functions → rev_decompile → rev_strings_xrefs → gdb_break_inspect. r2/radiff2 from bash.

**Forensics:** forensics_file_triage → forensics_stego_analyze / forensics_extract_embedded / forensics_entropy_analysis / forensics_image_analysis. volatility3 from bash.

**Web:** curl, sqlmap, ffuf, nuclei, nikto from bash.

**Jail:** Read source → jail_analyze_source → jail_find_subclass_chain / jail_construct_string / jail_build_payload. Test via pwntools.

## Incremental Work & Retries

- Read solve.py first — may contain prior work
- Edit incrementally, keep it runnable
- Even failed attempts should leave useful code
- Submit first, polish after

## Progress Tracking

- Auto-submit immediately via `ctf_submit_flag`
- `ctf_workspace_status()` for live progress
- `ctf_sync()` detects teammate solves
- `ctf_notifications()` for platform announcements

## Post-Solve Documentation

Call `ctf_save_writeup(challenge, methodology, tools_used)` after every correct flag.
Include: vulnerability/technique, key observations, dead ends, step-by-step process.

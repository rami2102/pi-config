---
name: multi-lang-bench
description: Run multi-language coding benchmarks across pi, codex, claude, and gemini agents. Executes N tests (default 12) in batches of 3, running pi+codex in parallel first, then claude+gemini. Produces detailed per-test and per-model summary tables.
---

# Multi-Language Benchmark Skill

Runs the Multi-SWE-bench_mini benchmark across 4 coding agents (pi, codex, claude, gemini) with controlled parallelism and produces comparative summary tables.

## Parameters

- **N** — Total number of tests to run (default: 12). User can override.
- **BATCH_SIZE** — Tests per batch per agent (fixed: 3).
- **TIMEOUT** — Base timeout per task in seconds (default: 600).
- **VALIDATE** — Whether to run test validation (default: true).

## Execution Plan

1. Ensure the dataset is cached and test lists are built.
2. Select N test instance IDs from the round-robin list.
3. Split them into batches of 3.
4. For each batch:
   - **Wave 1**: Run `pi` and `codex` in parallel (pi and claude share the same model, so they must NOT run together).
   - **Wave 2**: Run `claude` and `gemini` in parallel. Give gemini+claude a timeout of **5× base** timeout.
5. Collect all `result.json` files from each agent's task directories.
6. Generate 3 summary outputs:
   - **Table 1**: Per-test detail (test name, success, fix lines, test lines, benchmark resolved).
   - **Table 2**: Per-model totals.
   - **Table 3**: Best model conclusion.

## Instructions

Run the benchmark by executing:

```bash
bash /home/node/.pi/agent/skills/multi-lang-bench/run-bench.sh [N]
```

Where `[N]` is the optional total number of tests (default 12).

After it completes, read the generated summary file and present the 3 tables to the user formatted as markdown.

The summary file location is printed at the end of the script output.

If the script fails, check the log files in the results directory for debugging.

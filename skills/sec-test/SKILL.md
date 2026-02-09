---
name: sec-test
description: Run a 5-layer security scan on any skill folder (or prompt-provided code) to determine SAFE or DANGEROUS. Layers — (1) Code Security patterns, (2) LLM/agent-skill risks, (3) Dependency CVEs, (4) Compliance checks, (5) LLM validation via pi. Generates a timestamped report. Use when importing new skills, auditing existing ones, or asking "is this skill safe?".
---

# sec-test — 5-Layer Skill Security Scanner

Run a comprehensive security assessment on a skill folder (including all sub-folders) or on prompt-provided code. Returns a clear **SAFE** / **DANGEROUS** verdict with reasons, and saves a detailed Markdown report.

## Quick Start

```bash
# Scan a skill folder
bash scripts/sec-test.sh /path/to/skill-folder

# Scan with a specific LLM for Layer 5
bash scripts/sec-test.sh /path/to/skill-folder --llm gpt-4o

# Scan without LLM validation (layers 1-4 only)
bash scripts/sec-test.sh /path/to/skill-folder --no-pi-validate

# Scan with custom report directory
bash scripts/sec-test.sh /path/to/skill-folder /custom/report/dir
```

All paths in this skill are **relative to the skill directory**: `~/.pi/agent/skills/sec-test/`

## What It Scans (5 Layers)

| Layer | Scanner | What It Catches |
|-------|---------|-----------------|
| **1 — Code Security** | `senior-secops/security_scanner.py` | Hardcoded secrets, SQL injection, XSS, command injection, path traversal |
| **2 — LLM/Skill Security** | `scripts/llm-skill-scanner.py` | Prompt injection, excessive agency, data exfiltration, system prompt leakage, unsafe eval/exec, supply-chain risks, unbounded consumption |
| **3 — Dependency CVEs** | `senior-secops/vulnerability_assessor.py` | Known CVEs in npm, Python, Go dependencies |
| **4 — Compliance** | `senior-secops/compliance_checker.py` | SOC 2, PCI-DSS, HIPAA, GDPR control checks |
| **5 — LLM Validation** | `scripts/llm-validate-scanner.py` | AI-powered per-file analysis via pi — catches context-dependent threats, obfuscated attacks, subtle social engineering, novel patterns that regex misses |

## LLM Name — Config Cascade

Layer 5 spawns a pi agent per file. The LLM model used can be overridden. Resolution order (each overrides the previous):

| Priority | Source | Example |
|----------|--------|---------|
| 1 (lowest) | Built-in default | `default` (same model as pi) |
| 2 | Config file | `sec-test.conf.json` → `{"llm_name": "gpt-4o"}` |
| 3 (highest) | CLI flag / user prompt | `--llm claude-3-opus` or user says "scan with GPT-4" |

### Config file

Edit `sec-test.conf.json` to set persistent defaults:

```json
{
  "llm_name": "claude-3.5-sonnet",
  "pi_validate": false
}
```

Layer 5 (LLM validation) is **disabled by default**. Set `"pi_validate": true` or pass `--pi-validate` to enable it.

## Usage

### Scan a Folder

To scan a skill folder (recursively includes all sub-folders):

```bash
bash ~/.pi/agent/skills/sec-test/scripts/sec-test.sh /absolute/path/to/target/folder
```

The script will:
1. Run all 5 layers against the target
2. Print a **SAFE** or **DANGEROUS** verdict to the terminal
3. Save a detailed report to `$PWD/docs/security-test-scans/security-test-scan-YYYY-MM-DD-HHMMSS.md` (relative to pi's working directory)

**Exit codes:** `0` = SAFE, `1` = DANGEROUS

### CLI Flags

| Flag | Description |
|------|-------------|
| `--llm <model>` | Override the LLM model for Layer 5 (e.g., `--llm gpt-4o`) |
| `--no-pi-validate` | Skip Layer 5 (LLM validation) — runs layers 1-4 only |
| `--pi-validate` | Force-enable Layer 5 (overrides config `"pi_validate": false`) |

### Scan Prompt-Provided Content

When the user provides code or a skill definition as text (not a folder path):

1. Save the content to a temporary file/folder
2. Run the scanner on that folder
3. Return the verdict and clean up

```bash
# Example: save user-provided content, scan it
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/SKILL.md" << 'EOF'
<paste content here>
EOF
cd ~/.pi/agent/skills/sec-test
bash scripts/sec-test.sh "$TMPDIR"
rm -rf "$TMPDIR"
```

### Run Individual Layers

```bash
# Layer 1 — Code security only
python3 /home/node/git/pi-cool/alireza-claude-skills/engineering-team/senior-secops/scripts/security_scanner.py /path/to/target --json

# Layer 2 — LLM/skill security only
python3 scripts/llm-skill-scanner.py /path/to/target --json

# Layer 3 — Dependency vulnerabilities only
python3 /home/node/git/pi-cool/alireza-claude-skills/engineering-team/senior-secops/scripts/vulnerability_assessor.py /path/to/target --json

# Layer 4 — Compliance only
python3 /home/node/git/pi-cool/alireza-claude-skills/engineering-team/senior-secops/scripts/compliance_checker.py /path/to/target --framework all --json

# Layer 5 — LLM validation only
python3 scripts/llm-validate-scanner.py /path/to/target --json
python3 scripts/llm-validate-scanner.py /path/to/target --llm gpt-4o --json
```

## Layer 5 — How It Works

Layer 5 spawns a separate `pi` instance (non-interactive: `pi -p --no-tools --no-session`) **per file** in the target folder. Each pi call sends the file content to the LLM with a security-analysis system prompt. The LLM evaluates the file holistically and returns a structured JSON verdict with severity and findings.

This catches risks that pattern-matching cannot:
- Short destructive commands (`rm /tmp`, `drop table users`)
- Context-dependent threats (commands safe in isolation but dangerous for a tool-equipped agent)
- Subtle social engineering or obfuscated payloads
- Novel attack patterns not covered by static rules
- Encoded/indirect attacks (base64 payloads, variable-based injection)

**File types scanned:** `.md`, `.py`, `.js`, `.ts`, `.sh`, `.yaml`, `.json`, `.toml`, `.go`, `.rb`, `.php`, `.rs`, and more.
**Skipped:** `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `security-test-scans`, files > 100KB.

**Performance:** Layer 5 adds ~5-15 seconds per file (one LLM call each). Use `--no-pi-validate` to skip it when speed matters.

## Verdict Logic

- **DANGEROUS** if ANY layer finds **critical** or **high** severity issues, OR compliance score < 50%
- **SAFE** if ALL layers pass with no critical/high issues and compliance ≥ 50%

The verdict line always follows this format:
```
SAFE
```
or
```
DANGEROUS — [reason1]; [reason2]; ...
```

## Report Location

Reports are saved to the **current working directory** (where the pi agent is running):
```
./docs/security-test-scans/security-test-scan-YYYY-MM-DD-HHMMSS.md
```

Each report contains:
- Overall verdict (SAFE/DANGEROUS) with reasons
- Severity summary table
- Per-layer verdict table (layers 1-5)
- Detailed findings per layer with file locations and descriptions
- Layer 5 per-file verdict table
- Compliance control pass/fail table
- Scan methodology reference

## LLM/Skill-Specific Risks Detected (Layer 2)

Based on [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/):

| OWASP Category | What We Check |
|----------------|---------------|
| LLM01: Prompt Injection | Override instructions, role hijack, constraint bypass, message boundary spoofing |
| LLM02: Sensitive Disclosure | Env var access, logging secrets, external HTTP requests, embedded keys |
| LLM03: Supply Chain | Unverified git clones, unpinned Docker/deps, remote module imports |
| LLM04: Data Poisoning | Training on untrusted data references |
| LLM05: Output Handling | innerHTML, dangerouslySetInnerHTML, document.write |
| LLM06: Excessive Agency | Root/sudo, destructive deletes, curl\|bash, eval/exec user input, shell=True, system dir writes, remote SSH |
| LLM07: Prompt Leakage | Instructions to disclose system prompt, reading secret files |
| LLM09: Misinformation | Instructions to skip verification |
| LLM10: Unbounded Consumption | Infinite loops, unbounded recursion |

## References

- [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Semgrep Security Rules](https://semgrep.dev/explore)
- Code security rules: `/home/node/git/pi-cool/semgrep-skills/skills/code-security/rules/`
- LLM security rules: `/home/node/git/pi-cool/semgrep-skills/skills/llm-security/rules/`

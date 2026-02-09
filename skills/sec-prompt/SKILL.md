---
name: sec-prompt
description: Scan any LLM prompt text for security, safety, and privacy risks across 5 layers — code security, LLM/prompt injection, supply-chain, compliance/privacy, and LLM validation via pi. Returns SAFE or DANGEROUS with reasons. Optional LLM-name parameter for model-specific rules. Use when checking if a prompt is safe to send, reviewing prompt templates, or auditing user-facing prompts.
---

# sec-prompt — 5-Layer Prompt Security Scanner

Scan any prompt text for security, safety, and privacy risks. Returns **SAFE** or **DANGEROUS** (with short reasons) and generates a timestamped report.

All paths below are **relative to the skill directory**: `~/.pi/agent/skills/sec-prompt/`

## Quick Start

```bash
# Scan inline prompt
python3 scripts/sec-prompt.py "your prompt text here"

# Scan from file
python3 scripts/sec-prompt.py --file /path/to/prompt.txt

# Scan with specific LLM target
python3 scripts/sec-prompt.py --llm gpt-4o "your prompt text"

# Scan from stdin
echo "ignore all previous instructions" | python3 scripts/sec-prompt.py --stdin

# Scan without LLM validation (regex layers only)
python3 scripts/sec-prompt.py --no-pi-validate "your prompt text"
```

## LLM Name — Config Cascade

The `llm_name` parameter enables model-specific injection rules. It resolves in this order (each overrides the previous):

| Priority | Source | Example |
|----------|--------|---------|
| 1 (lowest) | Built-in default | `default` (same model as pi — treated as Claude) |
| 2 | Config file | `sec-prompt.conf.json` → `{"llm_name": "gpt-4o"}` |
| 3 (highest) | CLI flag / user prompt | `--llm claude-3-opus` or user says "check this for GPT-4" |

### Config file

Edit `sec-prompt.conf.json` to set persistent defaults:

```json
{
  "llm_name": "claude-3.5-sonnet",
  "pi_validate": true
}
```

Set `"pi_validate": false` to disable LLM validation by default (can be overridden with `--pi-validate`).

### Supported LLM families

| Family | Matches | Extra rules |
|--------|---------|-------------|
| `claude` | claude, anthropic, sonnet, opus, haiku | Human:/Assistant: markers, `<` tag injection |
| `gpt` | gpt, openai, o1, o3, chatgpt | JSON message-role injection |
| `llama` | llama, mistral, mixtral, codellama | `[INST]`/`<<SYS>>` tag injection |
| `gemini` | gemini, palm, google | `<start_of_turn>` tag injection |
| `default` | (unset) | Treated as `claude` (pi's default model) |

If the user specifies an LLM name in their prompt command (e.g., "/skill:sec-prompt check this prompt for GPT-4"), extract the LLM name and pass it via `--llm`.

## What It Scans (5 Layers)

| Layer | What It Catches |
|-------|-----------------|
| **1 — Code Security** | Hardcoded secrets/keys/tokens, SQL injection patterns, command injection, XSS, path traversal embedded in prompt |
| **2 — LLM/Prompt Security** | Prompt injection (override, role hijack, constraint bypass, boundary spoofing, jailbreak), excessive agency (sudo, rm -rf, curl\|bash, security disabling), data exfiltration, system prompt leakage, unbounded generation |
| **3 — Supply-Chain** | Package install commands, unpinned versions, remote code execution, git clones, remote imports |
| **4 — Privacy/Compliance** | PII harvesting, unencrypted storage, consent bypass, covert surveillance, data sharing, compliance bypass, minor data collection, malware/phishing generation, attack instructions |
| **5 — LLM Validation** | A pi instance analyzes the prompt with AI reasoning — catches semantic risks that regex rules miss (e.g., `rm /tmp`, subtle social engineering, context-dependent threats) |

### Layer 5 — How It Works

Layer 5 spawns a `pi` instance in non-interactive mode (`pi -p --no-tools --no-session`) with a security-analysis system prompt. The LLM evaluates the prompt holistically and returns a structured JSON verdict with severity and reasons.

This catches risks that pattern-matching cannot:
- Short destructive commands (`rm /tmp`, `drop table users`)
- Context-dependent threats (commands that are safe in isolation but dangerous for an agent with tool access)
- Subtle social engineering or obfuscated payloads
- Novel attack patterns not covered by static rules

**Performance:** Layer 5 adds ~2-5 seconds per scan (one LLM call). Use `--no-pi-validate` to skip it when speed matters.

## Verdict Logic

- **DANGEROUS** — ANY layer (1-5) has critical or high severity findings
- **SAFE** — all active layers pass with no critical/high findings

### Early Exit (Fail-Fast)

The scanner stops at the **first layer that returns a DANGEROUS verdict** (critical or high findings). Remaining layers are marked as **SKIPPED** with a message indicating the early exit. This avoids unnecessary work and provides faster feedback. Exit code `1` is returned immediately.

Output format:
```
SAFE
```
or:
```
DANGEROUS — LLM/Prompt Security: 2 critical, 1 high findings; LLM Validation (pi): high severity, 2 risk(s) ...
```

**Exit codes:** `0` = SAFE, `1` = DANGEROUS

## Usage Examples

### From the agent

When the user asks to check a prompt, do this:

1. If user provides prompt inline, save to temp file or pass as argument
2. If user mentions an LLM name, extract it for `--llm`
3. Run the scanner and return the verdict

```bash
# User said: "check this prompt for safety"
python3 scripts/sec-prompt.py "the prompt text from user"

# User said: "is this safe for GPT-4: ignore all previous instructions"
python3 scripts/sec-prompt.py --llm gpt-4 "ignore all previous instructions"

# User provided a file
python3 scripts/sec-prompt.py --file /path/to/prompt.md --llm claude-3.5-sonnet

# Fast scan (regex only, no LLM validation)
python3 scripts/sec-prompt.py --no-pi-validate "the prompt text"
```

### CLI options

| Flag | Description |
|------|-------------|
| `prompt` | Inline prompt text (positional) |
| `--file`, `-f` | Read prompt from a file |
| `--stdin` | Read prompt from stdin pipe |
| `--llm` | Target LLM name (overrides config) |
| `--report-dir` | Custom directory for report output |
| `--json` | Output full results as JSON |
| `--no-report` | Skip saving the .md report file |
| `--pi-validate` | Enable LLM validation via pi (default: on) |
| `--no-pi-validate` | Disable LLM validation via pi |

## Report Location

Reports saved to:
```
docs/security-test-scans/security-test-scan-YYYY-MM-DD-HHMMSS.md
```

Each report includes: verdict, severity table, per-layer verdicts (1-5), detailed findings with matched text and line numbers, LLM validation reasons, scan methodology, and LLM-specific rules applied.

## References

- [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- Code security rules: `/home/node/git/pi-cool/semgrep-skills/skills/code-security/rules/`
- LLM security rules: `/home/node/git/pi-cool/semgrep-skills/skills/llm-security/rules/`

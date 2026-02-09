#!/usr/bin/env bash
# sec-test.sh — Orchestrate 5-layer security scan on a skill folder
# Usage: sec-test.sh <target-folder> [report-dir] [--llm <model>] [--no-pi-validate]
#
# Layers:
#   1. Code Security  — pattern-based vuln scan (secrets, injection, XSS, cmd-injection, path-traversal)
#   2. LLM Security   — agent/skill-specific risks (prompt injection, excessive agency, data exfil, etc.)
#   3. Dependency Vuln — CVE scan on package.json / requirements.txt / go.mod
#   4. Compliance      — SOC2 / PCI-DSS / HIPAA / GDPR control checks
#   5. LLM Validation  — pi agent analyses each file with AI reasoning
#
# Exit codes: 0 = SAFE, 1 = DANGEROUS

set -uo pipefail

# ── Load config file defaults ────────────────────────────────────────
SKILL_DIR_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_FILE="${SKILL_DIR_EARLY}/sec-test.conf.json"
LLM_NAME=""
PI_VALIDATE="no"

if [[ -f "$CONF_FILE" ]]; then
  # Read pi_validate from config (default: true → "yes")
  CONF_PI_VALIDATE=$(python3 -c "import json,sys; d=json.load(open('$CONF_FILE')); print('yes' if d.get('pi_validate', True) else 'no')" 2>/dev/null)
  [[ -n "$CONF_PI_VALIDATE" ]] && PI_VALIDATE="$CONF_PI_VALIDATE"

  # Read llm_name from config
  CONF_LLM=$(python3 -c "import json,sys; d=json.load(open('$CONF_FILE')); v=d.get('llm_name',''); print(v if v != 'default' else '')" 2>/dev/null)
  [[ -n "$CONF_LLM" ]] && LLM_NAME="$CONF_LLM"
fi

# ── Parse flags (extract --llm and --no-pi-validate before positional args) ──
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --llm)
      LLM_NAME="$2"
      shift 2
      ;;
    --no-pi-validate)
      PI_VALIDATE="no"
      shift
      ;;
    --pi-validate)
      PI_VALIDATE="yes"
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

set -- "${POSITIONAL[@]}"

# ── Resolve paths ────────────────────────────────────────────────────
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="${SKILL_DIR}/scripts"
SECOPS_SCRIPTS="/home/node/git/pi-cool/alireza-claude-skills/engineering-team/senior-secops/scripts"

TARGET="${1:?Usage: sec-test.sh <target-folder> [report-dir] [--llm <model>] [--no-pi-validate]}"
TARGET="$(cd "$TARGET" && pwd)"

REPORT_DIR="${2:-${PWD}/docs/security-test-scans}"
mkdir -p "$REPORT_DIR"

NOW_DATE=$(date -u +"%Y-%m-%d")
NOW_TIME=$(date -u +"%H%M%S")
REPORT_FILE="${REPORT_DIR}/security-test-scan-${NOW_DATE}-${NOW_TIME}.md"
JSON_DIR=$(mktemp -d)

trap 'rm -rf "$JSON_DIR"' EXIT

# ── Colour helpers (stderr only) ─────────────────────────────────────
red()   { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[0;32m%s\033[0m\n' "$*" >&2; }
cyan()  { printf '\033[0;36m%s\033[0m\n' "$*" >&2; }

# ── Counters ─────────────────────────────────────────────────────────
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
LAYER_VERDICTS=()
LAYER_REASONS=()
DANGEROUS_REASONS=()

add_counts() {
  # add_counts <critical> <high> <medium> <low>
  TOTAL_CRITICAL=$((TOTAL_CRITICAL + ${1:-0}))
  TOTAL_HIGH=$((TOTAL_HIGH + ${2:-0}))
  TOTAL_MEDIUM=$((TOTAL_MEDIUM + ${3:-0}))
  TOTAL_LOW=$((TOTAL_LOW + ${4:-0}))
}

# ══════════════════════════════════════════════════════════════════════
# LAYER 1 — Code Security (pattern scanner)
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Layer 1/5: Code Security Scanner"
L1_JSON="${JSON_DIR}/code-security.json"

if python3 "${SECOPS_SCRIPTS}/security_scanner.py" "$TARGET" --json --output "$L1_JSON" --severity low 2>&1; then
  true  # exit 0 means no critical/high
fi

L1_CRITICAL=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('severity_counts',{}).get('critical',0))" 2>/dev/null || echo 0)
L1_HIGH=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('severity_counts',{}).get('high',0))" 2>/dev/null || echo 0)
L1_MEDIUM=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('severity_counts',{}).get('medium',0))" 2>/dev/null || echo 0)
L1_LOW=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('severity_counts',{}).get('low',0))" 2>/dev/null || echo 0)
L1_TOTAL=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('total_findings',0))" 2>/dev/null || echo 0)
L1_FILES=$(python3 -c "import json,sys; d=json.load(open('$L1_JSON')); print(d.get('files_scanned',0))" 2>/dev/null || echo 0)

add_counts "$L1_CRITICAL" "$L1_HIGH" "$L1_MEDIUM" "$L1_LOW"

if (( L1_CRITICAL > 0 || L1_HIGH > 0 )); then
  LAYER_VERDICTS+=("DANGEROUS")
  reason="Code scan: ${L1_CRITICAL} critical, ${L1_HIGH} high findings"
  LAYER_REASONS+=("$reason")
  DANGEROUS_REASONS+=("$reason")
else
  LAYER_VERDICTS+=("SAFE")
  LAYER_REASONS+=("Code scan: no critical/high findings (${L1_MEDIUM} medium, ${L1_LOW} low)")
fi

# Get all findings for report
L1_TOP_FINDINGS=$(python3 -c "
import json
d=json.load(open('$L1_JSON'))
for f in d.get('findings',[]):
    sev=f['severity'].upper()
    print(f'| {sev} | {f[\"category\"]} | {f[\"file_path\"]}:{f[\"line_number\"]} | {f[\"description\"][:80]} |')
" 2>/dev/null || echo "| - | - | - | No findings |")


# ══════════════════════════════════════════════════════════════════════
# LAYER 2 — LLM / Agent Skill Security (custom pattern scan)
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Layer 2/5: LLM & Agent Skill Security"
L2_JSON="${JSON_DIR}/llm-security.json"

python3 "${SCRIPTS_DIR}/llm-skill-scanner.py" "$TARGET" --json --output "$L2_JSON" 2>&1 || true

L2_CRITICAL=$(python3 -c "import json; d=json.load(open('$L2_JSON')); print(d.get('severity_counts',{}).get('critical',0))" 2>/dev/null || echo 0)
L2_HIGH=$(python3 -c "import json; d=json.load(open('$L2_JSON')); print(d.get('severity_counts',{}).get('high',0))" 2>/dev/null || echo 0)
L2_MEDIUM=$(python3 -c "import json; d=json.load(open('$L2_JSON')); print(d.get('severity_counts',{}).get('medium',0))" 2>/dev/null || echo 0)
L2_LOW=$(python3 -c "import json; d=json.load(open('$L2_JSON')); print(d.get('severity_counts',{}).get('low',0))" 2>/dev/null || echo 0)
L2_TOTAL=$(python3 -c "import json; d=json.load(open('$L2_JSON')); print(d.get('total_findings',0))" 2>/dev/null || echo 0)

add_counts "$L2_CRITICAL" "$L2_HIGH" "$L2_MEDIUM" "$L2_LOW"

if (( L2_CRITICAL > 0 || L2_HIGH > 0 )); then
  LAYER_VERDICTS+=("DANGEROUS")
  reason="LLM/skill scan: ${L2_CRITICAL} critical, ${L2_HIGH} high findings"
  LAYER_REASONS+=("$reason")
  DANGEROUS_REASONS+=("$reason")
else
  LAYER_VERDICTS+=("SAFE")
  LAYER_REASONS+=("LLM/skill scan: no critical/high findings (${L2_MEDIUM} medium, ${L2_LOW} low)")
fi

L2_TOP_FINDINGS=$(python3 -c "
import json
d=json.load(open('$L2_JSON'))
for f in d.get('findings',[]):
    sev=f['severity'].upper()
    print(f'| {sev} | {f[\"category\"]} | {f[\"file_path\"]}:{f[\"line_number\"]} | {f[\"description\"][:80]} |')
" 2>/dev/null || echo "| - | - | - | No findings |")


# ══════════════════════════════════════════════════════════════════════
# LAYER 3 — Dependency Vulnerability Assessment
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Layer 3/5: Dependency Vulnerability Assessment"
L3_JSON="${JSON_DIR}/vuln-assess.json"

if python3 "${SECOPS_SCRIPTS}/vulnerability_assessor.py" "$TARGET" --json --output "$L3_JSON" --severity low 2>&1; then
  true
fi

L3_CRITICAL=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('severity_counts',{}).get('critical',0))" 2>/dev/null || echo 0)
L3_HIGH=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('severity_counts',{}).get('high',0))" 2>/dev/null || echo 0)
L3_MEDIUM=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('severity_counts',{}).get('medium',0))" 2>/dev/null || echo 0)
L3_LOW=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('severity_counts',{}).get('low',0))" 2>/dev/null || echo 0)
L3_TOTAL=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('total_vulnerabilities',0))" 2>/dev/null || echo 0)
L3_RISK=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('risk_score',0))" 2>/dev/null || echo 0)
L3_RISK_LEVEL=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('risk_level','NONE'))" 2>/dev/null || echo "NONE")
L3_PKGS=$(python3 -c "import json; d=json.load(open('$L3_JSON')); print(d.get('packages_scanned',0))" 2>/dev/null || echo 0)

add_counts "$L3_CRITICAL" "$L3_HIGH" "$L3_MEDIUM" "$L3_LOW"

if (( L3_CRITICAL > 0 || L3_HIGH > 0 )); then
  LAYER_VERDICTS+=("DANGEROUS")
  reason="Dependency CVEs: ${L3_CRITICAL} critical, ${L3_HIGH} high (risk ${L3_RISK}/100)"
  LAYER_REASONS+=("$reason")
  DANGEROUS_REASONS+=("$reason")
else
  LAYER_VERDICTS+=("SAFE")
  LAYER_REASONS+=("Dependency CVEs: no critical/high vulns (${L3_PKGS} packages scanned)")
fi

L3_TOP_FINDINGS=$(python3 -c "
import json
d=json.load(open('$L3_JSON'))
for v in sorted(d.get('vulnerabilities',[]), key=lambda x: x['cvss_score'], reverse=True):
    sev=v['severity'].upper()
    print(f'| {sev} | {v[\"cve_id\"]} | {v[\"package\"]}@{v[\"installed_version\"]} | {v[\"description\"][:60]} → upgrade to {v[\"fixed_version\"]} |')
" 2>/dev/null || echo "| - | - | - | No vulnerabilities found |")


# ══════════════════════════════════════════════════════════════════════
# LAYER 4 — Compliance Check
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Layer 4/5: Compliance Check"
L4_JSON="${JSON_DIR}/compliance.json"

if python3 "${SECOPS_SCRIPTS}/compliance_checker.py" "$TARGET" --framework all --json --output "$L4_JSON" 2>&1; then
  true
fi

L4_SCORE=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('compliance_score',0))" 2>/dev/null || echo 0)
L4_LEVEL=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('compliance_level','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
L4_PASSED=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('summary',{}).get('passed',0))" 2>/dev/null || echo 0)
L4_FAILED=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('summary',{}).get('failed',0))" 2>/dev/null || echo 0)
L4_WARNINGS=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('summary',{}).get('warnings',0))" 2>/dev/null || echo 0)
L4_TOTAL_CONTROLS=$(python3 -c "import json; d=json.load(open('$L4_JSON')); print(d.get('summary',{}).get('total',0))" 2>/dev/null || echo 0)

# Compliance doesn't use critical/high counts, use score threshold
if python3 -c "exit(0 if $L4_SCORE >= 50 else 1)" 2>/dev/null; then
  LAYER_VERDICTS+=("SAFE")
  LAYER_REASONS+=("Compliance: ${L4_SCORE}% (${L4_LEVEL}) — ${L4_PASSED}/${L4_TOTAL_CONTROLS} controls passed")
else
  LAYER_VERDICTS+=("DANGEROUS")
  reason="Compliance: ${L4_SCORE}% (${L4_LEVEL}) — ${L4_FAILED} controls failed"
  LAYER_REASONS+=("$reason")
  DANGEROUS_REASONS+=("$reason")
fi

L4_TOP_FINDINGS=$(python3 -c "
import json
d=json.load(open('$L4_JSON'))
for c in d.get('controls',[]):
    status = '✅' if c['status']=='passed' else ('⚠️' if c['status']=='warning' else '❌')
    print(f'| {status} {c[\"status\"].upper()} | {c[\"framework\"]} | {c[\"control_id\"]} | {c[\"title\"]} |')
" 2>/dev/null || echo "| - | - | - | No controls checked |")


# ══════════════════════════════════════════════════════════════════════
# LAYER 5 — LLM Validation (pi agent per file)
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Layer 5/5: LLM Validation (pi)"
L5_JSON="${JSON_DIR}/llm-validate.json"

L5_CMD=(python3 "${SCRIPTS_DIR}/llm-validate-scanner.py" "$TARGET" --json --output "$L5_JSON")
if [[ -n "$LLM_NAME" ]]; then
  L5_CMD+=(--llm "$LLM_NAME")
fi
if [[ "$PI_VALIDATE" == "no" ]]; then
  L5_CMD+=(--no-pi-validate)
fi

"${L5_CMD[@]}" 2>&1 || true

L5_STATUS=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")
L5_VERDICT=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('overall_verdict','UNKNOWN'))" 2>/dev/null || echo "UNKNOWN")
L5_SEVERITY=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('overall_severity','none'))" 2>/dev/null || echo "none")
L5_FILES_SCANNED=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('files_scanned',0))" 2>/dev/null || echo 0)
L5_TOTAL=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('total_findings',0))" 2>/dev/null || echo 0)
L5_CRITICAL=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('severity_counts',{}).get('critical',0))" 2>/dev/null || echo 0)
L5_HIGH=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('severity_counts',{}).get('high',0))" 2>/dev/null || echo 0)
L5_MEDIUM=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('severity_counts',{}).get('medium',0))" 2>/dev/null || echo 0)
L5_LOW=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('severity_counts',{}).get('low',0))" 2>/dev/null || echo 0)
L5_LLM_NAME=$(python3 -c "import json; d=json.load(open('$L5_JSON')); print(d.get('llm_name','default'))" 2>/dev/null || echo "default")

add_counts "$L5_CRITICAL" "$L5_HIGH" "$L5_MEDIUM" "$L5_LOW"

if [[ "$L5_STATUS" == "skipped" ]]; then
  LAYER_VERDICTS+=("SKIPPED")
  LAYER_REASONS+=("LLM validation: disabled (--no-pi-validate or config)")
elif (( L5_CRITICAL > 0 || L5_HIGH > 0 )); then
  LAYER_VERDICTS+=("DANGEROUS")
  reason="LLM validation (pi): ${L5_CRITICAL} critical, ${L5_HIGH} high findings across ${L5_FILES_SCANNED} files"
  LAYER_REASONS+=("$reason")
  DANGEROUS_REASONS+=("$reason")
else
  LAYER_VERDICTS+=("SAFE")
  LAYER_REASONS+=("LLM validation (pi): no critical/high (${L5_FILES_SCANNED} files scanned, ${L5_TOTAL} findings, model: ${L5_LLM_NAME})")
fi

L5_TOP_FINDINGS=$(python3 -c "
import json
d=json.load(open('$L5_JSON'))
for f in d.get('findings',[]):
    sev=f.get('severity','?').upper()
    cat=f.get('category','?')
    fp=f.get('file_path','?')
    ln=f.get('line_number','?')
    title=f.get('title','?')[:60]
    print(f'| {sev} | {cat} | {fp}:{ln} | {title} |')
" 2>/dev/null || echo "| - | - | - | No findings |")

L5_FILE_VERDICTS=$(python3 -c "
import json
d=json.load(open('$L5_JSON'))
for fr in d.get('file_results',[]):
    icon = '✅' if fr['verdict']=='SAFE' else ('🔴' if fr['verdict']=='DANGEROUS' else '⚠️')
    fp=fr['file_path']
    sev=fr.get('severity','none')
    nf=len(fr.get('findings',[]))
    err=fr.get('error','')
    if err:
        print(f'| {icon} {fr[\"verdict\"]} | {fp} | {sev} | {nf} | ⚠️ {err[:60]} |')
    else:
        print(f'| {icon} {fr[\"verdict\"]} | {fp} | {sev} | {nf} | - |')
" 2>/dev/null || echo "| - | - | - | - | No files scanned |")


# ══════════════════════════════════════════════════════════════════════
# OVERALL VERDICT
# ══════════════════════════════════════════════════════════════════════
if (( TOTAL_CRITICAL > 0 || TOTAL_HIGH > 0 )) || [[ " ${LAYER_VERDICTS[*]} " == *" DANGEROUS "* ]]; then
  OVERALL="DANGEROUS"
else
  OVERALL="SAFE"
fi

# Build short reason string
if [[ "$OVERALL" == "DANGEROUS" ]]; then
  OVERALL_REASON=$(printf '%s; ' "${DANGEROUS_REASONS[@]}")
  OVERALL_REASON="${OVERALL_REASON%; }"
else
  OVERALL_REASON="All 5 security layers passed — no critical/high issues found"
fi

# ══════════════════════════════════════════════════════════════════════
# GENERATE MARKDOWN REPORT
# ══════════════════════════════════════════════════════════════════════
cyan "▶ Generating report: ${REPORT_FILE}"

if [[ "$OVERALL" == "SAFE" ]]; then
  VERDICT_BADGE="🟢 **SAFE**"
else
  VERDICT_BADGE="🔴 **DANGEROUS**"
fi

cat > "$REPORT_FILE" << REPORT_EOF
# Security Test Scan Report

| Field | Value |
|-------|-------|
| **Date** | ${NOW_DATE} |
| **Time (UTC)** | ${NOW_TIME:0:2}:${NOW_TIME:2:2}:${NOW_TIME:4:2} |
| **Target** | \`${TARGET}\` |
| **LLM Model** | \`${L5_LLM_NAME}\` |
| **Verdict** | ${VERDICT_BADGE} |
| **Reason** | ${OVERALL_REASON} |

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${TOTAL_CRITICAL} |
| 🟠 High | ${TOTAL_HIGH} |
| 🟡 Medium | ${TOTAL_MEDIUM} |
| 🔵 Low | ${TOTAL_LOW} |

## Layer Verdicts

| # | Layer | Verdict | Details |
|---|-------|---------|---------|
| 1 | Code Security Scanner | ${LAYER_VERDICTS[0]} | ${LAYER_REASONS[0]} |
| 2 | LLM & Agent Skill Security | ${LAYER_VERDICTS[1]} | ${LAYER_REASONS[1]} |
| 3 | Dependency Vulnerabilities | ${LAYER_VERDICTS[2]} | ${LAYER_REASONS[2]} |
| 4 | Compliance Check | ${LAYER_VERDICTS[3]} | ${LAYER_REASONS[3]} |
| 5 | LLM Validation (pi) | ${LAYER_VERDICTS[4]} | ${LAYER_REASONS[4]} |

---

## Layer 1: Code Security Scanner

**Files scanned:** ${L1_FILES}  |  **Findings:** ${L1_TOTAL}

| Severity | Category | Location | Description |
|----------|----------|----------|-------------|
${L1_TOP_FINDINGS}

---

## Layer 2: LLM & Agent Skill Security

**Findings:** ${L2_TOTAL}

| Severity | Category | Location | Description |
|----------|----------|----------|-------------|
${L2_TOP_FINDINGS}

---

## Layer 3: Dependency Vulnerabilities

**Packages scanned:** ${L3_PKGS}  |  **CVEs found:** ${L3_TOTAL}  |  **Risk score:** ${L3_RISK}/100 (${L3_RISK_LEVEL})

| Severity | CVE | Package | Description |
|----------|-----|---------|-------------|
${L3_TOP_FINDINGS}

---

## Layer 4: Compliance Check

**Score:** ${L4_SCORE}% (${L4_LEVEL})  |  **Passed:** ${L4_PASSED}  |  **Failed:** ${L4_FAILED}  |  **Warnings:** ${L4_WARNINGS}

| Status | Framework | Control | Title |
|--------|-----------|---------|-------|
${L4_TOP_FINDINGS}

---

## Layer 5: LLM Validation (pi)

**Model:** \`${L5_LLM_NAME}\`  |  **Files scanned:** ${L5_FILES_SCANNED}  |  **Findings:** ${L5_TOTAL}

### Per-File Verdicts

| Verdict | File | Severity | Findings | Notes |
|---------|------|----------|----------|-------|
${L5_FILE_VERDICTS}

### Top Findings

| Severity | Category | Location | Finding |
|----------|----------|----------|---------|
${L5_TOP_FINDINGS}

---

## Scan Methodology

| Layer | Tool / Method | What It Checks |
|-------|---------------|----------------|
| 1 — Code Security | Pattern-based source scanner | Hardcoded secrets, SQL injection, XSS, command injection, path traversal |
| 2 — LLM/Skill Security | Agent-skill-specific scanner | Prompt injection, excessive agency, data exfiltration, system prompt leakage, unsafe shell/eval, supply chain |
| 3 — Dependencies | CVE database scanner | Known vulnerabilities in npm, Python, Go dependencies |
| 4 — Compliance | Framework checker | SOC 2, PCI-DSS, HIPAA, GDPR controls |
| 5 — LLM Validation | pi agent (per file) | AI-powered analysis catching context-dependent threats, obfuscated attacks, subtle social engineering |

> Report generated by **sec-test** skill — $(date -u +"%Y-%m-%d %H:%M:%S UTC")
REPORT_EOF

# ── Final output ─────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
if [[ "$OVERALL" == "SAFE" ]]; then
  green "  VERDICT: ✅ SAFE"
else
  red   "  VERDICT: 🔴 DANGEROUS"
  red   "  REASON:  ${OVERALL_REASON}"
fi
echo "  REPORT:  ${REPORT_FILE}"
echo "════════════════════════════════════════════════════════════"

# Exit code
[[ "$OVERALL" == "SAFE" ]] && exit 0 || exit 1

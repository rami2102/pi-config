#!/usr/bin/env python3
"""
LLM & Agent Skill Security Scanner

Scans skill folders for LLM-specific and agent-skill-specific security risks:
  - Prompt injection patterns
  - Excessive agency / privilege escalation
  - Data exfiltration / phone-home URLs
  - System prompt leakage instructions
  - Unsafe shell/eval execution in scripts
  - Supply-chain risks (curl|bash, remote code loading)
  - Sensitive data harvesting (env vars, credentials, private keys)
  - Unbounded resource consumption patterns

Based on OWASP Top 10 for LLM 2025 categories.

Usage:
    python llm-skill-scanner.py /path/to/skill-folder
    python llm-skill-scanner.py /path/to/skill-folder --json --output report.json
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple
from datetime import datetime


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str


# ── Detection Rules ──────────────────────────────────────────────────
# Each rule: (regex_pattern, category, title, description, severity, recommendation)
# Patterns are applied per-line with re.IGNORECASE

RULES: List[Tuple[str, str, str, str, str, str]] = [

    # ── PROMPT INJECTION (OWASP LLM01) ──────────────────────────────
    (r'ignore\s+(all\s+)?previous\s+instructions',
     'prompt-injection', 'Prompt Injection — Override Instructions',
     'Text that attempts to override prior system/user instructions',
     'critical',
     'Remove instruction-override language; use input validation and output filtering'),

    (r'(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as)',
     'prompt-injection', 'Prompt Injection — Role Hijack',
     'Attempts to reassign the model\'s role or persona',
     'high',
     'Avoid embedding role-change directives; enforce role via system prompt only'),

    (r'(disregard|forget|override)\s+(your|the|all)\s+(rules|instructions|guidelines|constraints)',
     'prompt-injection', 'Prompt Injection — Constraint Bypass',
     'Language designed to bypass safety constraints',
     'critical',
     'Remove constraint-bypass text; implement guardrails outside the prompt'),

    (r'<\s*(system|user|assistant)\s*>',
     'prompt-injection', 'Prompt Injection — Message Boundary Spoofing',
     'Fake message-role XML tags that could confuse chat-based models',
     'high',
     'Strip or escape role-boundary tags from untrusted content'),

    # ── EXCESSIVE AGENCY (OWASP LLM06) ──────────────────────────────
    (r'(sudo\s|as\s+root|chmod\s+777|chmod\s+\+s)',
     'excessive-agency', 'Excessive Agency — Root/Sudo Escalation',
     'Skill instructs the agent to run commands as root or set dangerous permissions',
     'critical',
     'Never require root; use least-privilege; avoid world-writable permissions'),

    (r'rm\s+(-rf?|--force)\s+(/|~|\$HOME|\$\{?HOME\}?)',
     'excessive-agency', 'Excessive Agency — Destructive Delete',
     'Skill instructs deletion of critical system or home directories',
     'critical',
     'Avoid recursive force-delete on root or home; scope deletions to project dirs'),

    (r'(curl|wget)\s+[^\|]*\|\s*(ba)?sh',
     'excessive-agency', 'Excessive Agency — Pipe Remote Code to Shell',
     'Downloads and immediately executes remote code (curl|bash anti-pattern)',
     'critical',
     'Download scripts first, review, then execute; pin to known hashes/versions'),

    (r'(npm\s+install|pip\s+install|go\s+install)\s+[^\s]*@(latest|master|main)',
     'excessive-agency', 'Excessive Agency — Unpinned Dependency Install',
     'Installs dependencies without pinned version (supply-chain risk)',
     'high',
     'Pin all dependencies to exact versions or verified commit hashes'),

    (r'eval\s*\(\s*(request|input|user|param|args|argv)',
     'excessive-agency', 'Excessive Agency — Eval of User Input',
     'Evaluates user-controlled input as code',
     'critical',
     'Never eval() untrusted input; use safe parsing (JSON.parse, ast.literal_eval)'),

    (r'exec\s*\(\s*(request|input|user|param|args|argv)',
     'excessive-agency', 'Excessive Agency — Exec of User Input',
     'Executes user-controlled input as code',
     'critical',
     'Never exec() untrusted input; use allow-listed commands only'),

    (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
     'excessive-agency', 'Excessive Agency — Shell=True Subprocess',
     'Uses shell=True which enables command chaining and injection',
     'high',
     'Use shell=False with argument lists; validate all command inputs'),

    (r'os\.system\s*\(',
     'excessive-agency', 'Excessive Agency — os.system()',
     'Uses os.system which runs commands in a shell',
     'high',
     'Use subprocess.run() with shell=False and argument lists'),

    # ── SENSITIVE DATA DISCLOSURE (OWASP LLM02) ─────────────────────
    (r'(process\.env|os\.environ|getenv)\s*[\[\.(]\s*["\']?(API_KEY|SECRET|TOKEN|PASSWORD|AWS_|OPENAI_|ANTHROPIC_)',
     'data-exfil', 'Sensitive Disclosure — Environment Secret Access',
     'Skill reads sensitive environment variables (API keys, tokens, passwords)',
     'high',
     'Audit which env vars the skill needs; limit to minimum necessary; never log secrets'),

    (r'(print|console\.log|logger?\.(info|debug|warn))\s*\([^)]*\b(password|secret|token|api.?key|credential)\b',
     'data-exfil', 'Sensitive Disclosure — Logging Secrets',
     'Skill may log sensitive values to stdout/stderr',
     'high',
     'Never log secrets; redact sensitive fields before logging'),

    (r'(fetch|axios|request|http\.get|urllib|requests\.(get|post))\s*\(\s*["\']https?://(?!localhost|127\.0\.0\.1)',
     'data-exfil', 'Sensitive Disclosure — External HTTP Request',
     'Skill makes outbound HTTP requests to external hosts (potential data exfil)',
     'medium',
     'Audit all outbound URLs; use allowlists; ensure no sensitive data in requests'),

    (r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----',
     'data-exfil', 'Sensitive Disclosure — Embedded Private Key',
     'Private key material embedded in skill files',
     'critical',
     'Never embed private keys; use secret managers or key vaults'),

    (r'(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})',
     'data-exfil', 'Sensitive Disclosure — Hardcoded API Key/Token',
     'API key or access token hardcoded in skill',
     'critical',
     'Remove hardcoded keys; use environment variables or secret managers'),

    # ── SYSTEM PROMPT LEAKAGE (OWASP LLM07) ─────────────────────────
    (r'(print|output|return|echo|display)\s+(the\s+)?(system\s+prompt|instructions|full\s+prompt)',
     'prompt-leakage', 'System Prompt Leakage — Disclosure Instruction',
     'Skill instructs the model to reveal its system prompt',
     'high',
     'Never instruct the model to output its system prompt; use external guardrails'),

    (r'(read|cat|type|dump)\s+.*\.(env|secret|key|pem|p12|pfx)',
     'prompt-leakage', 'System Prompt Leakage — Secret File Read',
     'Skill reads secret/key files which could be disclosed in output',
     'high',
     'Avoid reading secret files in skill instructions; use secure APIs instead'),

    # ── SUPPLY CHAIN (OWASP LLM03) ──────────────────────────────────
    (r'(git\s+clone|git\s+pull)\s+https?://(?!github\.com/(anthropics?|openai|google|microsoft)/)',
     'supply-chain', 'Supply Chain — Unverified Git Clone',
     'Clones from an unverified/untrusted git repository',
     'medium',
     'Verify repository authenticity; pin to specific commits; audit cloned code'),

    (r'(docker\s+pull|docker\s+run)\s+[^\s:]+(:latest|\s)',
     'supply-chain', 'Supply Chain — Unpinned Docker Image',
     'Uses Docker image without pinned tag/digest',
     'medium',
     'Pin Docker images to specific SHA256 digests'),

    (r'(import|require|from)\s+["\']https?://',
     'supply-chain', 'Supply Chain — Remote Module Import',
     'Imports code directly from a URL at runtime',
     'high',
     'Vendor dependencies locally; never import directly from URLs'),

    # ── OUTPUT HANDLING (OWASP LLM05) ────────────────────────────────
    (r'innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(',
     'output-handling', 'Unsafe Output Handling — DOM Injection',
     'Skill outputs may be rendered as unescaped HTML (XSS risk)',
     'high',
     'Always sanitize LLM output before DOM insertion; use textContent or DOMPurify'),

    # ── UNBOUNDED CONSUMPTION (OWASP LLM10) ─────────────────────────
    (r'while\s+True|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)',
     'unbounded-consumption', 'Unbounded Consumption — Infinite Loop',
     'Skill contains a potential infinite loop without visible break condition',
     'medium',
     'Add explicit termination conditions, timeouts, and iteration limits'),

    (r'(recursion|recursive)\s.*no\s*(limit|bound|max)',
     'unbounded-consumption', 'Unbounded Consumption — Unbounded Recursion',
     'Skill describes unbounded recursive behavior',
     'medium',
     'Set explicit recursion depth limits'),

    # ── DATA POISONING (OWASP LLM04) ────────────────────────────────
    (r'(fine.?tune|train|rlhf|lora)\s.*\b(user|untrusted|external)\b',
     'data-poisoning', 'Data Poisoning — Training on Untrusted Data',
     'Skill references training/fine-tuning on untrusted data',
     'high',
     'Validate and sanitize all training data; implement data provenance tracking'),

    # ── MISINFORMATION (OWASP LLM09) ────────────────────────────────
    (r'(do\s+not|don.?t|never)\s+(verify|check|validate|confirm)',
     'misinformation', 'Misinformation — Verification Bypass',
     'Skill instructs the model to skip verification or fact-checking',
     'medium',
     'Always encourage verification; use RAG with trusted sources'),

    # ── FILE SYSTEM ABUSE ────────────────────────────────────────────
    (r'(open|write|append)\s*\(\s*["\']?\s*(/etc/|/var/|/usr/|/bin/|/sbin/|C:\\Windows)',
     'excessive-agency', 'File System Abuse — System Directory Write',
     'Skill writes to system-critical directories',
     'critical',
     'Restrict file operations to project/workspace directories only'),

    (r'(ssh|scp|rsync)\s+.*@',
     'excessive-agency', 'Excessive Agency — Remote System Access',
     'Skill connects to remote systems via SSH/SCP',
     'medium',
     'Audit remote access; ensure credentials are not embedded; use allowlists'),
]

# Skip directories
SKIP_DIRS = {'node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', 'coverage', '.next'}

# Scan these extensions
SCAN_EXTENSIONS = {
    '.md', '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash', '.zsh',
    '.yaml', '.yml', '.json', '.toml', '.cfg', '.conf', '.env',
    '.java', '.go', '.rb', '.php', '.rs', '.swift', '.kt',
}


class LLMSkillScanner:
    def __init__(self, target: str, verbose: bool = False):
        self.target = Path(target)
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.files_scanned = 0

    def scan(self) -> Dict:
        start = datetime.now()
        files = self._collect_files()
        for f in files:
            self._scan_file(f)
            self.files_scanned += 1

        duration = (datetime.now() - start).total_seconds()

        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            'status': 'completed',
            'target': str(self.target),
            'files_scanned': self.files_scanned,
            'scan_duration_seconds': round(duration, 2),
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'findings': [asdict(f) for f in self.findings],
        }

    def _collect_files(self) -> List[Path]:
        files = []
        if self.target.is_file():
            return [self.target]
        for root, dirs, filenames in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(root) / fn
                if p.suffix.lower() in SCAN_EXTENSIONS or fn in ('.env', 'Dockerfile', 'Makefile'):
                    files.append(p)
        return files

    def _scan_file(self, path: Path):
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return

        rel = str(path.relative_to(self.target)) if self.target.is_dir() else path.name
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip pure comment lines in code files (not .md — we want to scan prose)
            if path.suffix not in ('.md', '.txt', '.yaml', '.yml', '.json'):
                if stripped.startswith('#') and not stripped.startswith('#!'):
                    continue
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue

            for pattern, category, title, desc, severity, rec in RULES:
                if re.search(pattern, line, re.IGNORECASE):
                    self.findings.append(Finding(
                        rule_id=f'llm-{category}-{len(self.findings)+1:04d}',
                        severity=severity,
                        category=category,
                        title=title,
                        description=desc,
                        file_path=rel,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        recommendation=rec,
                    ))
                    break  # one finding per line max

        if self.verbose:
            print(f'  Scanned: {rel}')


def main():
    ap = argparse.ArgumentParser(description='LLM & Agent Skill Security Scanner')
    ap.add_argument('target', help='Skill folder or file to scan')
    ap.add_argument('--json', action='store_true', help='JSON output')
    ap.add_argument('--output', '-o', help='Write results to file')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    scanner = LLMSkillScanner(args.target, verbose=args.verbose)
    result = scanner.scan()

    if args.json:
        out = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(out)
        else:
            print(out)
    else:
        # Pretty-print summary
        print(f'\nLLM Skill Security Scan — {result["target"]}')
        print(f'Files scanned: {result["files_scanned"]}')
        print(f'Findings: {result["total_findings"]}')
        for sev in ('critical', 'high', 'medium', 'low'):
            cnt = result['severity_counts'].get(sev, 0)
            if cnt:
                print(f'  {sev.upper()}: {cnt}')
        if result['findings']:
            print('\nTop findings:')
            for f in result['findings'][:10]:
                print(f'  [{f["severity"].upper()}] {f["title"]}')
                print(f'    {f["file_path"]}:{f["line_number"]}  {f["description"]}')

        if args.output:
            with open(args.output, 'w') as fh:
                json.dump(result, fh, indent=2)

    crits = result['severity_counts'].get('critical', 0)
    highs = result['severity_counts'].get('high', 0)
    if crits:
        sys.exit(2)
    if highs:
        sys.exit(1)


if __name__ == '__main__':
    main()

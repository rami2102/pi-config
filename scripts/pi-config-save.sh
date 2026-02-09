#!/usr/bin/env bash
set -euo pipefail

# pi-config-save.sh — Collect pi config into a git repo, commit & push
# Saves: settings.json, skills/, prompt templates
# Skips: auth.json, sessions/, binary tools (bin/)

PI_DIR="$HOME/.pi/agent"
REPO_DIR="$HOME/git/pi-config"
GITHUB_USER="rami1982"
REPO_NAME="pi-config"

# ─── Create repo if needed ───────────────────────────────────────────
if [ ! -d "$REPO_DIR/.git" ]; then
    echo "📁 Creating pi-config repo at $REPO_DIR"
    mkdir -p "$REPO_DIR"
    cd "$REPO_DIR"
    git init
    git config user.name "rami_sin2"
    git config user.email "rami.startup@gmail.com"

    # Create GitHub repo (public) — skip if already exists
    if command -v gh &>/dev/null; then
        gh repo create "$GITHUB_USER/$REPO_NAME" --public --source=. --remote=origin 2>/dev/null || \
            git remote add origin "git@github.com:$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || true
    else
        git remote add origin "git@github.com:$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || true
    fi

    # .gitignore — exclude secrets and ephemeral data
    cat > .gitignore << 'EOF'
auth.json
sessions/
bin/
*.key
*.pem
.env
.env.*
*.secret
__pycache__/
*.pyc
docs/security-test-scans/
EOF

    cat > README.md << 'EOF'
# pi-config

Portable [pi](https://github.com/mariozechner/pi) configuration — settings, skills, and prompt templates.

## Install on a new machine

```bash
git clone git@github.com:rami1982/pi-config.git ~/git/pi-config
~/git/pi-config/scripts/pi-config-install.sh
```

Then add your API keys with `pi --auth`.
EOF

    git add .
    git commit -m "Initial pi-config repo"
fi

cd "$REPO_DIR"

# ─── Collect config files ────────────────────────────────────────────
echo "📦 Collecting pi config..."

# settings.json
if [ -f "$PI_DIR/settings.json" ]; then
    cp "$PI_DIR/settings.json" "$REPO_DIR/settings.json"
    echo "  ✓ settings.json"
fi

# Skills (full copy, excluding docs/security-test-scans)
if [ -d "$PI_DIR/skills" ]; then
    mkdir -p "$REPO_DIR/skills"
    rsync -a --delete \
        --exclude='docs/security-test-scans/' \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        "$PI_DIR/skills/" "$REPO_DIR/skills/"
    echo "  ✓ skills/"
fi

# Prompt templates (from paths in settings.json)
if command -v jq &>/dev/null && [ -f "$PI_DIR/settings.json" ]; then
    mapfile -t PROMPT_DIRS < <(jq -r '.promptTemplates[]? // empty' "$PI_DIR/settings.json" 2>/dev/null)
    if [ ${#PROMPT_DIRS[@]} -gt 0 ]; then
        mkdir -p "$REPO_DIR/prompts"
        for pdir in "${PROMPT_DIRS[@]}"; do
            expanded="${pdir/#\~/$HOME}"
            if [ -d "$expanded" ]; then
                rsync -a "$expanded/" "$REPO_DIR/prompts/"
                echo "  ✓ prompts/ (from $pdir)"
            fi
        done
    fi
fi

# Copy this script and its companion into the repo
mkdir -p "$REPO_DIR/scripts"
cp "$HOME/scripts/pi-config-save.sh" "$REPO_DIR/scripts/pi-config-save.sh" 2>/dev/null || true
cp "$HOME/scripts/pi-config-install.sh" "$REPO_DIR/scripts/pi-config-install.sh" 2>/dev/null || true
chmod +x "$REPO_DIR/scripts/"*.sh 2>/dev/null || true
echo "  ✓ scripts/"

# ─── Commit & push ───────────────────────────────────────────────────
cd "$REPO_DIR"
git add -A

if git diff --cached --quiet; then
    echo "✅ No changes to commit."
else
    TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    git commit -m "pi-config update: $TIMESTAMP"
    echo "📤 Pushing to origin..."
    git push -u origin main 2>/dev/null || git push -u origin master 2>/dev/null || \
        (git branch -M main && git push -u origin main)
    echo "✅ Config saved and pushed."
fi

#!/usr/bin/env bash
set -euo pipefail

# pi-config-install.sh — Pull pi config from git and install into ~/.pi/agent
# Installs: settings.json, skills/, prompt templates
# Never touches: auth.json (keep your keys safe)

REPO_DIR="$HOME/git/pi-config"
PI_DIR="$HOME/.pi/agent"
GITHUB_USER="rami2102"
REPO_NAME="pi-config"

# ─── Clone or pull ───────────────────────────────────────────────────
if [ ! -d "$REPO_DIR/.git" ]; then
    echo "📥 Cloning pi-config repo..."
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone "git@github.com:$GITHUB_USER/$REPO_NAME.git" "$REPO_DIR"
else
    echo "📥 Pulling latest pi-config..."
    cd "$REPO_DIR"
    git pull --ff-only origin main 2>/dev/null || git pull --ff-only origin master 2>/dev/null || \
        git pull origin main 2>/dev/null || git pull
fi

cd "$REPO_DIR"

# ─── Create pi dir if needed ─────────────────────────────────────────
mkdir -p "$PI_DIR/skills"

# ─── Install settings.json ───────────────────────────────────────────
if [ -f "$REPO_DIR/settings.json" ]; then
    # Update paths to point to this repo's dirs
    if command -v jq &>/dev/null; then
        jq --arg skills "$REPO_DIR/skills" \
           --arg prompts "$REPO_DIR/prompts" \
           '.skills = [$skills] | if (.promptTemplates | length) > 0 then .promptTemplates = [$prompts] else . end' \
           "$REPO_DIR/settings.json" > "$PI_DIR/settings.json"
    else
        cp "$REPO_DIR/settings.json" "$PI_DIR/settings.json"
    fi
    echo "  ✓ settings.json"
fi

# ─── Install skills (symlink to repo so git pull updates them) ───────
if [ -d "$REPO_DIR/skills" ]; then
    for skill in "$REPO_DIR/skills"/*/; do
        [ -d "$skill" ] || continue
        name="$(basename "$skill")"
        target="$PI_DIR/skills/$name"

        # Remove existing (file, symlink, or dir)
        if [ -e "$target" ] || [ -L "$target" ]; then
            rm -rf "$target"
        fi

        ln -s "$skill" "$target"
        echo "  ✓ skill: $name → $skill"
    done
fi

# ─── Summary ─────────────────────────────────────────────────────────
echo ""
echo "✅ pi config installed from $REPO_DIR"
echo ""
if [ ! -f "$PI_DIR/auth.json" ]; then
    echo "⚠️  No auth.json found — run 'pi --auth' to set up your API keys."
else
    echo "🔑 auth.json already present (untouched)."
fi

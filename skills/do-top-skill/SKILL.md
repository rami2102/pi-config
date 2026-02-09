---
name: do-top-skill
description: Searches for the most relevant skill at $HOME/git/pi-cool, loads it, and executes the user's task in the current session. Use when the user wants to find and use a specialized skill from the pi-cool collection directly in this conversation.
---

# Do Top Skill

Finds the best matching skill from `$HOME/git/pi-cool` and executes it in the current session.

## How It Works

1. Search for the most relevant skill in `$HOME/git/pi-cool`
2. Read the full SKILL.md file to load its instructions
3. Follow the skill's instructions to execute the user's request

## Step 1: Find the Best Skill

Run the search script to find matching skills:

```bash
bash ~/.pi/agent/skills/do-top-skill/search-skills.sh "<keywords from user request>"
```

This outputs skill paths with their names and descriptions, ranked by relevance. Pick the top match.

## Step 2: Load the Skill

Read the full SKILL.md of the chosen skill:

```
read <path-to-SKILL.md>
```

## Step 3: Execute

Follow the loaded skill's instructions to complete the user's request in this current session. The skill may reference helper scripts, reference docs, or assets via relative paths from its directory — resolve those paths relative to the skill's parent directory.

## Example

User asks: "Audit my site's SEO"

1. Search: `bash ~/.pi/agent/skills/do-top-skill/search-skills.sh "SEO audit site"`
2. Find: `seo-audit` skill at `/home/node/git/pi-cool/marketingskills/skills/seo-audit/SKILL.md`
3. Read the full SKILL.md
4. Follow its instructions to perform the SEO audit

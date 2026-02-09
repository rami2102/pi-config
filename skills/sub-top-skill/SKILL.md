---
name: sub-top-skill
description: Starts a new pi subagent to search for the most relevant skill at $HOME/git/pi-cool, loads it, executes the user's task using that skill, and returns the result to the current agent session. Use when the user wants to delegate a task to a specialized skill from the pi-cool collection via a separate agent process.
---

# Sub Top Skill

Delegates a task to a new pi subagent that finds and uses the best matching skill from `$HOME/git/pi-cool`.

## How It Works

1. Search for the most relevant skill in `$HOME/git/pi-cool`
2. Spawn a new pi subagent with that skill loaded via `--skill`
3. The subagent executes the user's request
4. Return the subagent's output to the current session

## Step 1: Find the Best Skill

Run the search script to find matching skills:

```bash
bash ~/.pi/agent/skills/sub-top-skill/search-skills.sh "<keywords from user request>"
```

This outputs skill paths with their names and descriptions, ranked by relevance. Pick the top match.

## Step 2: Run the Subagent

Spawn a new pi subagent in print mode with the chosen skill:

```bash
pi -p --no-session --skill "<path-to-SKILL.md>" "<user's full request>"
```

**Important flags:**
- `-p` (print mode): non-interactive, outputs result and exits
- `--no-session`: ephemeral, don't save session
- `--skill <path>`: load the discovered skill

## Step 3: Return Result

Return the subagent's output to the user in the current session. Summarize if the output is very long, but preserve key details, code, and actionable items.

## Example

User asks: "Help me write an A/B test plan for my landing page"

1. Search: `bash ~/.pi/agent/skills/sub-top-skill/search-skills.sh "A/B test plan landing page"`
2. Find: `ab-test-setup` skill at `/home/node/git/pi-cool/marketingskills/skills/ab-test-setup/SKILL.md`
3. Run: `pi -p --no-session --skill "/home/node/git/pi-cool/marketingskills/skills/ab-test-setup/SKILL.md" "Help me write an A/B test plan for my landing page"`
4. Return the subagent's output

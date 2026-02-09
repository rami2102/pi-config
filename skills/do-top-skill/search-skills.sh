#!/usr/bin/env bash
# Search for relevant skills in $HOME/git/pi-cool by keywords
# Usage: search-skills.sh "keywords to search for"
#
# Searches skill names and descriptions in all SKILL.md files.
# Outputs matches ranked by relevance (name match > description match).

set -euo pipefail

SKILLS_DIR="$HOME/git/pi-cool"
QUERY="${1:-}"

if [ -z "$QUERY" ]; then
  echo "Usage: search-skills.sh \"<keywords>\""
  exit 1
fi

# Build index: extract name, description, and path from all SKILL.md files
INDEX_FILE="/tmp/pi-cool-skills-index.txt"

# Rebuild index if older than 1 hour or missing
if [ ! -f "$INDEX_FILE" ] || [ "$(find "$INDEX_FILE" -mmin +60 2>/dev/null)" ]; then
  > "$INDEX_FILE"
  while IFS= read -r skill_file; do
    # Extract frontmatter name and description
    name=""
    desc=""
    in_frontmatter=false
    in_desc=false
    while IFS= read -r line; do
      if [ "$line" = "---" ]; then
        if $in_frontmatter; then
          break
        else
          in_frontmatter=true
          continue
        fi
      fi
      if $in_frontmatter; then
        if [[ "$line" =~ ^name:\ *(.*) ]]; then
          name="${BASH_REMATCH[1]}"
          name="${name#\"}"
          name="${name%\"}"
        elif [[ "$line" =~ ^description:\ *(.*) ]]; then
          desc="${BASH_REMATCH[1]}"
          desc="${desc#\"}"
          desc="${desc%\"}"
          in_desc=true
        elif $in_desc && [[ "$line" =~ ^[[:space:]] ]]; then
          desc="$desc $line"
        else
          in_desc=false
        fi
      fi
    done < "$skill_file"
    if [ -n "$name" ] && [ -n "$desc" ]; then
      # Single line: PATH<TAB>NAME<TAB>DESCRIPTION
      echo -e "${skill_file}\t${name}\t${desc}" >> "$INDEX_FILE"
    fi
  done < <(find "$SKILLS_DIR" -name "SKILL.md" -type f 2>/dev/null)
fi

# Search: split query into words, score each skill
echo "=== Searching for: $QUERY ==="
echo ""

# Convert query to lowercase words
query_lower=$(echo "$QUERY" | tr '[:upper:]' '[:lower:]')

# Score and sort results
while IFS=$'\t' read -r path name desc; do
  score=0
  name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
  desc_lower=$(echo "$desc" | tr '[:upper:]' '[:lower:]')
  
  for word in $query_lower; do
    # Skip very short words
    [ ${#word} -lt 3 ] && continue
    # Name match = 10 points
    if [[ "$name_lower" == *"$word"* ]]; then
      score=$((score + 10))
    fi
    # Description match = 3 points
    if [[ "$desc_lower" == *"$word"* ]]; then
      score=$((score + 3))
    fi
  done
  
  if [ $score -gt 0 ]; then
    echo "${score}|${path}|${name}|${desc}"
  fi
done < "$INDEX_FILE" | sort -t'|' -k1 -nr | head -10 | while IFS='|' read -r score path name desc; do
  echo "Score: $score"
  echo "  Name: $name"
  echo "  Path: $path"
  echo "  Desc: ${desc:0:200}"
  echo ""
done

if [ -z "$(while IFS=$'\t' read -r path name desc; do
  for word in $query_lower; do
    [ ${#word} -lt 3 ] && continue
    name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    desc_lower=$(echo "$desc" | tr '[:upper:]' '[:lower:]')
    if [[ "$name_lower" == *"$word"* ]] || [[ "$desc_lower" == *"$word"* ]]; then
      echo "found"
      break
    fi
  done
done < "$INDEX_FILE")" ]; then
  echo "No matching skills found. Try different keywords."
fi

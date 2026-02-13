#!/usr/bin/env bash
# search-github.sh - Search GitHub for OSS repos matching criteria
# Usage: search-github.sh "<query>" [page]
# Returns JSON array of candidate repos (3000+ stars, pushed recently)
set -euo pipefail

QUERY="${1:?Usage: search-github.sh '<query>' [page]}"
PAGE="${2:-1}"
PER_PAGE=30
DATE_30D_AGO=$(date -u -d "30 days ago" +%Y-%m-%d 2>/dev/null || date -u -v-30d +%Y-%m-%d)

AUTH_HEADER=""
if [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH_HEADER="Authorization: token $GITHUB_TOKEN"
fi

# Build GitHub search query: stars>=3000, pushed in last 30 days
SEARCH_Q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${QUERY} stars:>=3000 pushed:>=${DATE_30D_AGO}'))")

URL="https://api.github.com/search/repositories?q=${SEARCH_Q}&sort=stars&order=desc&per_page=${PER_PAGE}&page=${PAGE}"

CURL_ARGS=(-s -H "Accept: application/vnd.github.v3+json")
if [ -n "$AUTH_HEADER" ]; then
  CURL_ARGS+=(-H "$AUTH_HEADER")
fi

RESPONSE=$(curl "${CURL_ARGS[@]}" "$URL")

# Check for errors
ERROR=$(echo "$RESPONSE" | jq -r '.message // empty')
if [ -n "$ERROR" ]; then
  echo "ERROR: GitHub API - $ERROR" >&2
  echo "$RESPONSE" | jq -r '.documentation_url // empty' >&2
  exit 1
fi

TOTAL=$(echo "$RESPONSE" | jq '.total_count')
echo "# Found $TOTAL repos matching query (page $PAGE)" >&2

# Output compact summary for each repo
echo "$RESPONSE" | jq '[.items[] | {
  full_name,
  html_url,
  description: (.description // "N/A"),
  stars: .stargazers_count,
  license_spdx: (.license.spdx_id // "NONE"),
  license_name: (.license.name // "Unknown"),
  pushed_at,
  created_at,
  topics,
  default_branch,
  has_wiki,
  language
}]'

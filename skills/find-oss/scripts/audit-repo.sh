#!/usr/bin/env bash
# audit-repo.sh - Deep audit a GitHub repo against OSS criteria
# Usage: audit-repo.sh "<owner/repo>"
# Outputs JSON with pass/fail for each criterion
set -euo pipefail

REPO="${1:?Usage: audit-repo.sh '<owner/repo>'}"
DATE_30D_AGO=$(date -u -d "30 days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30d +%Y-%m-%dT%H:%M:%SZ)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

CURL_ARGS=(-s -H "Accept: application/vnd.github.v3+json")
if [ -n "${GITHUB_TOKEN:-}" ]; then
  CURL_ARGS+=(-H "Authorization: token $GITHUB_TOKEN")
fi

gh_api() { curl "${CURL_ARGS[@]}" "https://api.github.com$1"; }

echo "Auditing $REPO ..." >&2

# 1. Repo metadata
META=$(gh_api "/repos/$REPO")
ERR=$(echo "$META" | jq -r '.message // empty')
if [ -n "$ERR" ]; then echo "ERROR: $ERR" >&2; exit 1; fi

STARS=$(echo "$META" | jq '.stargazers_count')
LICENSE_SPDX=$(echo "$META" | jq -r '.license.spdx_id // "NONE"')
LICENSE_NAME=$(echo "$META" | jq -r '.license.name // "Unknown"')
PUSHED_AT=$(echo "$META" | jq -r '.pushed_at')
CREATED_AT=$(echo "$META" | jq -r '.created_at')
DESC=$(echo "$META" | jq -r '.description // "N/A"')
TOPICS=$(echo "$META" | jq -c '[.topics[]?]')
LANG=$(echo "$META" | jq -r '.language // "N/A"')
DEFAULT_BRANCH=$(echo "$META" | jq -r '.default_branch')

# 2. Classify license
classify_license() {
  case "$1" in
    MIT|Apache-2.0|BSD-2-Clause|BSD-3-Clause|ISC|Unlicense|0BSD|Zlib)
      echo "permissive" ;;
    LGPL-2.1*|LGPL-3.0*|MPL-2.0|EUPL-1.2|CDDL-1.0)
      echo "weak-copyleft" ;;
    GPL-2.0*|GPL-3.0*|AGPL-3.0*)
      echo "copyleft" ;;
    NOASSERTION|NONE|"") echo "unknown" ;;
    *) echo "other" ;;
  esac
}
LICENSE_CLASS=$(classify_license "$LICENSE_SPDX")

# 3. Latest release / tag version
RELEASE=$(gh_api "/repos/$REPO/releases/latest" 2>/dev/null)
REL_TAG=$(echo "$RELEASE" | jq -r '.tag_name // empty')
if [ -z "$REL_TAG" ]; then
  # Fallback: latest tag
  REL_TAG=$(gh_api "/repos/$REPO/tags?per_page=1" | jq -r '.[0].name // empty')
fi
LATEST_VER="${REL_TAG:-none}"

# Check >= 1.0: extract numeric version
check_stable() {
  local ver="$1"
  local num
  num=$(echo "$ver" | grep -oP '\d+\.\d+' | head -1)
  if [ -z "$num" ]; then echo "false"; return; fi
  local major
  major=$(echo "$num" | cut -d. -f1)
  [ "$major" -ge 1 ] 2>/dev/null && echo "true" || echo "false"
}
IS_STABLE=$(check_stable "$LATEST_VER")

# 4. Check last commit date on default branch
LAST_COMMIT_DATA=$(gh_api "/repos/$REPO/commits?sha=$DEFAULT_BRANCH&per_page=1")
LAST_COMMIT_DATE=$(echo "$LAST_COMMIT_DATA" | jq -r '.[0].commit.committer.date // empty')
LAST_COMMIT_SHA=$(echo "$LAST_COMMIT_DATA" | jq -r '.[0].sha // empty' | head -c 7)

is_within_30d() {
  [ "$(date -u -d "$1" +%s 2>/dev/null || date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$1" +%s)" -ge \
    "$(date -u -d "$DATE_30D_AGO" +%s 2>/dev/null || date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$DATE_30D_AGO" +%s)" ] \
    2>/dev/null && echo "true" || echo "false"
}
IS_ACTIVE=$(is_within_30d "${LAST_COMMIT_DATE:-1970-01-01T00:00:00Z}")

# 5. Scan README + LICENSE for paid/enterprise keywords
PAID_KEYWORDS="enterprise license|commercial license|paid plan|premium tier|pro version|business edition|buy a license|purchase a license|proprietary license|dual.licens|source.available|BSL|SSPL|Elastic License|MariaDB Business|Commons Clause|fair.source"

scan_for_paid() {
  local content
  content=$(gh_api "/repos/$REPO/readme" | jq -r '.content // empty' | base64 -d 2>/dev/null || echo "")
  local lic_content
  lic_content=$(gh_api "/repos/$REPO/license" | jq -r '.content // empty' | base64 -d 2>/dev/null || echo "")
  local combined="${content} ${lic_content}"
  if echo "$combined" | grep -qiP "$PAID_KEYWORDS"; then
    echo "$combined" | grep -oiP ".{0,40}($PAID_KEYWORDS).{0,40}" | head -3
  fi
}
PAID_MATCHES=$(scan_for_paid)
HAS_PAID="false"
PAID_DETAIL="none"
if [ -n "$PAID_MATCHES" ]; then
  HAS_PAID="true"
  PAID_DETAIL=$(echo "$PAID_MATCHES" | tr '\n' ' | ' | head -c 200)
fi

# 6. Infer type from description + topics
infer_type() {
  local text
  text=$(echo "$DESC $TOPICS" | tr '[:upper:]' '[:lower:]')
  if echo "$text" | grep -qE "cli|command.line|terminal"; then echo "CLI"
  elif echo "$text" | grep -qE "framework"; then echo "Framework"
  elif echo "$text" | grep -qE "api|rest|graphql|sdk"; then echo "API"
  elif echo "$text" | grep -qE "tool|utility|devtool"; then echo "Tool"
  else echo "Library"; fi
}
REPO_TYPE=$(infer_type)

# 7. Stars check
STARS_PASS="false"
[ "$STARS" -ge 3000 ] 2>/dev/null && STARS_PASS="true"

# 8. License pass (not unknown/NONE)
LICENSE_PASS="false"
[ "$LICENSE_CLASS" != "unknown" ] && LICENSE_PASS="true"

# Overall pass
ALL_PASS="false"
if [ "$STARS_PASS" = "true" ] && [ "$LICENSE_PASS" = "true" ] && \
   [ "$IS_ACTIVE" = "true" ] && [ "$IS_STABLE" = "true" ] && \
   [ "$HAS_PAID" = "false" ]; then
  ALL_PASS="true"
fi

# Output JSON
cat <<EOF
{
  "repo": "$REPO",
  "url": "https://github.com/$REPO",
  "description": $(echo "$DESC" | jq -Rs .),
  "language": "$LANG",
  "stars": $STARS,
  "license_spdx": "$LICENSE_SPDX",
  "license_name": "$LICENSE_NAME",
  "license_class": "$LICENSE_CLASS",
  "latest_version": "$LATEST_VER",
  "is_stable": $IS_STABLE,
  "last_commit_date": "${LAST_COMMIT_DATE:-unknown}",
  "last_commit_sha": "${LAST_COMMIT_SHA:-unknown}",
  "is_active": $IS_ACTIVE,
  "created_at": "$CREATED_AT",
  "pushed_at": "$PUSHED_AT",
  "type": "$REPO_TYPE",
  "topics": $TOPICS,
  "has_paid_indicators": $HAS_PAID,
  "paid_detail": $(echo "$PAID_DETAIL" | jq -Rs .),
  "checks": {
    "stars_gte_3000": $STARS_PASS,
    "license_known": $LICENSE_PASS,
    "license_class": "$LICENSE_CLASS",
    "active_30d": $IS_ACTIVE,
    "stable_gte_1": $IS_STABLE,
    "no_paid_tier": $([ "$HAS_PAID" = "false" ] && echo true || echo false)
  },
  "all_pass": $ALL_PASS,
  "audit_time": "$NOW"
}
EOF

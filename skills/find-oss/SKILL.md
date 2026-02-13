---
name: find-oss
description: Find GitHub or other free repositories matching strict criteria - permissive open-source license (MIT/Apache/BSD/LGPL preferred, GPL second priority), no paid/enterprise requirements, 3000+ stars, active (commits within 30 days), stable (version >= 1.0). Returns repo URL, license, stars, latest version, last commit date, creation date, API/CLI type, and audit trail. Use when searching for production-ready open-source libraries or tools.
---

# Find OSS

Search for high-quality, truly free open-source repositories that meet strict production-readiness criteria.

## Criteria

| # | Requirement | Details |
|---|-------------|---------|
| 1 | **License** | Permissive first (MIT, Apache-2.0, BSD-2/3, ISC, LGPL, Unlicense, MPL-2.0). GPL second priority. |
| 2 | **No paid tiers** | LICENSE and README must NOT contain enterprise/paid/commercial tier language |
| 3 | **Stars** | ≥ 3,000 |
| 4 | **Active** | At least one commit in the last 30 days |
| 5 | **Stable** | Latest release/tag version ≥ 1.0 |

## How to Use

When the user asks to find OSS repos for a topic/category:

### Step 1: Search GitHub

Use the search script to find candidate repos:

```bash
bash ~/.pi/agent/skills/find-oss/scripts/search-github.sh "<search query>" [page]
```

This returns up to 30 repos per page sorted by stars, pre-filtered to 3000+ stars and recent pushes.

### Step 2: Audit Each Candidate

For each candidate repo from Step 1, run the audit script:

```bash
bash ~/.pi/agent/skills/find-oss/scripts/audit-repo.sh "<owner/repo>"
```

This checks:
- License type and classification (permissive / copyleft / unknown)
- Stars count
- Last commit date (must be within 30 days)
- Latest release version (must be ≥ 1.0)
- Repo creation date
- README and LICENSE scan for paid/enterprise keywords
- Topics and description for API/CLI classification

### Step 3: Compile Results

Present **only repos that pass ALL criteria** in a table:

| Repo URL | License | Stars | Latest Version | Last Commit | Created | Type | Audit Notes |
|----------|---------|-------|----------------|-------------|---------|------|-------------|

- **Repo URL**: Full GitHub URL
- **License**: SPDX identifier
- **Stars**: Current count
- **Latest Version**: Tag/release version string
- **Last Commit**: Date of most recent commit (default branch)
- **Created**: Repository creation date
- **Type**: API / CLI / Library / Framework / Tool (inferred from description + topics)
- **Audit Notes**: License tier (permissive/copyleft), any warnings

### Step 4: Rank Results

Order results by:
1. License permissiveness (MIT/Apache/BSD first, then LGPL/MPL, then GPL)
2. Stars (descending)
3. Recency of last commit

## Supplementary Web Search

If GitHub search yields few results, also search via SearXNG:

```bash
curl -s "http://localhost:8888/search?q=URL_ENCODED_QUERY+site:github.com&format=json" | jq '[.results[:10][] | {title, url}]'
```

Extract `owner/repo` from URLs and audit them with the same script.

## Edge Cases

- If `GITHUB_TOKEN` env var is set, scripts use it for higher rate limits
- If a repo has no releases/tags, it fails the stable (≥ 1.0) check
- If license file cannot be fetched, mark as "unknown license - FAIL"
- Repos with dual licensing where one path is paid → FAIL the no-paid check

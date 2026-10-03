# Frontend Blocklist

[![Daily discovery](https://github.com/P4vizal/frontend-blocklist/actions/workflows/discover-search-frontends.yml/badge.svg)](https://github.com/P4vizal/frontend-blocklist/actions/workflows/discover-search-frontends.yml)

Privacy-focused blocklist data and automated discovery for alternative web frontends and viewers for **Reddit, X/Twitter, and Tumblr**.

The project focuses on finding real, usable frontend/viewer domains while filtering out news articles, software directories, analytics tools, repository catalog pages, parked domains, and unrelated search results.

## What this repository provides

The original blocklist pipeline is kept separate from the automated discovery list. The discovery system is deliberately conservative: a domain is published only after page-level validation provides enough independent evidence that it behaves like an alternative frontend or viewer.

The discovery output is:

- `search-discovered-blocklist.txt` — domains accepted by the automated validator.
- `search-discovered-report.json` — validation evidence, source health, pending candidates, and rejection statistics.

## Discovery pipeline

The daily workflow combines several complementary discovery layers:

1. Maintained frontend registries and instance catalogs, including Farside, Redlib, LibRedirect, Libreddit, Priviblur, and curated alternative-frontends projects.
2. GitHub repository discovery, extracting service URLs from relevant repository documentation.
3. Multilingual Bing RSS discovery with a bounded HTML fallback and rotating language coverage. The daily schedule is fixed at **72 high-signal queries**.
4. Optional deeper discovery sources for manual runs, including GitLab, Codeberg, Common Crawl, and URLScan.
5. Page validation using platform identity, frontend/viewer signals, routes, controls, metadata, and lightweight runtime/JavaScript hints.
6. Persistent pending verification with bounded retries for strong candidates that are temporarily unreachable.

## Stability and safety

The discovery list is append-only: previously accepted domains are not removed automatically.

The validator uses fail-soft network handling, bounded retries, same-origin route checks, redirect validation, challenge-page detection, explicit rejection rules, and a separate near-miss/pending state for candidates that need another verification attempt.

The GitHub Actions workflow uses minimal permissions, a concurrency guard to prevent overlapping writers, pinned official actions, and a separate read-only CI workflow. External source failures are recorded in the JSON report instead of silently appearing as zero candidates.

The workflow also verifies that these protected files remain unchanged:

- `scripts/generate_blocklist.py`
- `blocklist.txt`
- `portmaster.txt`
- `hagezi-overlap.txt`

## Schedule

The automated discovery workflow runs every day at **03:41 UTC** and can also be started manually with `workflow_dispatch`.

The preventive CI workflow runs on pull requests that change the discovery code or workflow configuration.

## Search coverage and quality

Search coverage deliberately uses several naming patterns for public profiles, posts, subreddits, blogs, viewers, browsers, frontends, mirrors, read-only clients, and no-login access.

The validator gives more weight to maintained registries, independent source evidence, repeated service-intent queries, service-like hostnames/routes, and page-level service identity. It also rejects common SEO/search noise such as analytics, statistics, tracking, guides, news, repository indexes, and generic article pages.

## Why this matters

Alternative frontend projects and public instances can move, disappear, or change hostnames over time. A bounded automated discovery loop provides a repeatable way to surface new domains without weakening the publication threshold.

The README keeps the core project terms explicit for GitHub visitors and search indexing: **privacy**, **alternative frontends**, **alternative viewers**, **Reddit**, **X/Twitter**, **Tumblr**, **blocklist**, **domain discovery**, **automation**, and **frontend instances**.

GitHub repository topics can also improve project classification and discovery, but the available GitHub connector in this environment does not expose a safe repository-topic mutation operation, so no metadata outside the repository files was changed.

## Development

The discovery script uses only the Python standard library and is tested without third-party dependencies:

```bash
python -m py_compile scripts/discover_search_frontends.py tests/test_discover_search_frontends_smoke.py
python tests/test_discover_search_frontends_smoke.py
```

The discovery generator and the primary blocklist files are intentionally kept separate from this automated discovery process.
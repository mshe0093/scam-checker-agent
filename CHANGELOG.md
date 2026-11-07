# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). It has no tagged
releases yet, so entries are grouped by milestone (see [docs/PLAN.md](docs/PLAN.md#7-milestones)).

## [Unreleased]

### Added
- README, usage guide, contributing guide, security policy, and issue and pull request templates.
- `scamcheck check` now works without an API key: it falls back to the offline rules engine and says so.

## M7.5: Detection upgrades (2026-11-07)

### Added
- Lookalike detection with **dnstwist** permutations of every official domain.
- Punycode decoding and folding of look-alike Cyrillic and Greek letters.
- URL-shape signals: an official domain used as a disguise, login words in the link path (EN and BM),
  stacked subdomains, and random-looking names.
- Trust signals:
  - **Established domain.** Not given when the link path looks like a planted login page.
  - **Protective security advice** such as "never share your TAC".
- `data/rules.json`: rules-engine weights, a threshold, and a cap that stops an unresolved short link from being cleared.

### Changed
- Levenshtein matching is stricter for short names.
- The rules engine now weighs trust against risk. On the eval set, genuine messages cleared went from 64% to 79%,
  and 100% of scams were still flagged.

## M6–M7: Web UI and MCP server (2026-11-06)

### Added
- Next.js UI with a live tool-call trace, a verdict card, official channels from the dataset, and follow-ups.
- An offline rules engine, so the UI and API run without an API key.
- MCP server (`scamcheck-mcp`): the six tools, the `investigate_message` prompt and the official-contacts resource.

## M4–M5: API and evaluation (2026-11-06)

### Added
- FastAPI with Server-Sent Events streaming, follow-up sessions and per-IP rate limiting.
- A labelled eval set of 40 messages, `scamcheck eval`, and the rules-only baseline.

## M1–M3: Tools and agent (2026-11-06)

### Added
- Six verification tools, an SSRF-guarded redirect resolver, and curated Malaysian datasets with sources.
- The Claude tool-use agent loop:
  - parallel tools
  - a strict verdict schema
  - a deterministic verdict floor
  - follow-up Q&A
- The CLI.

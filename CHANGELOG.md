# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). It has no tagged
releases yet, so entries are grouped by milestone (see [docs/PLAN.md](docs/PLAN.md#7-milestones)).

## [Unreleased]

### Added
- **25 scam tactics** in `data/tactics.json`, detected by `extract_entities`. Examples:
  - `.apk` app files and app installs from links
  - requests to share a code, a banking login, bank details or an IC
  - "safe account" transfers and fake criminal cases
  - bank-account rental (money mules)
  - "new number" family scams
  - gift cards, task jobs, guaranteed returns, crypto pitches and sextortion
  - advance fees, fake buyer payments and pay-first sellers
  - payments to personal accounts, disconnection threats and aid or prize claims

  Each tactic has a plain-language explanation and advice.
- Rules-engine verdicts now explain themselves:
  - a headline naming the two strongest reasons and the organisation
  - findings ranked strongest first
  - advice tailored to the tactics found
  - the claimed organisation's real hotline from the dataset
  - a `score` breakdown
- `data/explanations.json` for headline wording, signal groups and advice for each category.
- 18 organisations in the dataset:
  - government: KWSP, PERKESO and the Finance Ministry's STR/SARA aid
  - TNB
  - telcos: CelcomDigi, Maxis and U Mobile
  - marketplaces: Shopee, Lazada and Carousell
  - Grab
  - banks: AmBank, Bank Rakyat, OCBC, UOB, HSBC, Alliance and Affin
- 12 scam templates with sources, covering:
  - `.apk` invites
  - WhatsApp code theft
  - Macau and money-mule scams
  - task jobs
  - TNB, KWSP and STR scams
- New verdict categories: `malware_apk`, `account_takeover`, `money_mule`, `online_shopping`,
  `extortion` and `utility_telco`.
- `evals/challenge.jsonl`: 32 messages covering newer scam types.
- `CODE_OF_CONDUCT.md`: a code written for this project, covering victim-blaming, privacy in shared messages and handling scam links safely.
- README, usage guide, contributing guide, security policy, and issue and pull request templates.
- `scamcheck check` now works without an API key: it falls back to the offline rules engine and says so.

### Changed
- Naming an organisation no longer counts as evidence. Previously, a fake Bank Negara "safe account"
  scam with no link was cleared as legitimate.
- Everyday words ("today", "pay", "transfer") no longer count as pressure on their own, and one weak hint no longer triggers a warning.
- "won" no longer matches inside "won't".
- On the challenge set:
  - scams flagged went from 80% to 100%
  - firm `likely_scam` verdicts went from 4 to 19
  - false "suspicious" verdicts on genuine messages went from 3 to 0

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

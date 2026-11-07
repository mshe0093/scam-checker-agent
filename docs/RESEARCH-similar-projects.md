# Similar projects on GitHub: what they do differently

Researched 2026-11-07 using `gh search repos`, sorted by stars, across about 20 queries (phishing detection, scam
detection, smishing, typosquatting, phishing email analysis, brand impersonation, url scanner, scam checker…).
Star counts are as of that date.

**Main finding:** none of the well-starred projects does what this one does, which is checking a whole *message*
with an agent and pointing people to official contacts. Repos that closely match the idea (a "paste an SMS, get a
verdict" app for one country) all have fewer than 20 stars. The high-star projects each cover **one layer** that we
also cover, often more deeply: URL analysis, lookalike domains, threat feeds, or email forensics. The useful lessons
come from those layers.

## The projects

| ★ | Repo | What it is | Most relevant lesson |
|---:|---|---|---|
| 5.8k | [elceef/dnstwist](https://github.com/elceef/dnstwist) | Generates lookalike permutations of a domain and checks which ones are registered | Many named fuzzers (homoglyph, bitsquatting, hyphenation, vowel-swap, dictionary, TLD-swap). Fuzzy hashes and pHash to spot a cloned page |
| 2.0k | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist) | Curated phishing/scam domain blocklist with a free API | A ready-made threat feed in hosts/plain formats on a CDN |
| 1.8k | [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher) | Watches Certificate Transparency logs for suspicious new domains | **Scores live in a YAML file** (`'login': 25`, risky TLDs) with thresholds 65/80/90, so you tune it without code changes |
| 1.6k | [Phishing-Database/Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | Phishing domain/URL lists, re-tested for liveness | A threat feed that separates active from dead entries |
| 1.4k | [emalderson/ThePhish](https://github.com/emalderson/ThePhish) | Forward a phishing email as .eml; it extracts observables, runs analysers and emails back a verdict | **"Forward it to us" as the input channel.** Verdicts are final or need an analyst. A whitelist. Configurable weights per analyser |
| 1.0k | [atenreiro/opensquat](https://github.com/atenreiro/opensquat) | Finds newly registered lookalike domains for a brand | Combo-squatting (`brand-login.com`). Also ships an **MCP server**, as we do |
| 700 | [cyberdefenders/email-header-analyzer](https://github.com/cyberdefenders/email-header-analyzer) | Parses email headers | SPF/DKIM/DMARC results and the hop path show sender spoofing |
| 361 / 263 | [lindsey98/Phishpedia](https://github.com/lindsey98/Phishpedia), [PhishIntention](https://github.com/lindsey98/PhishIntention) | Research (USENIX'21): detects the brand logo on a page and compares it to the domain | Reference-based detection asks whether *this brand* uses *this domain*. That's the same idea as our `official_orgs` check, applied to page visuals |
| 109 | [urlvet/urlvet](https://github.com/urlvet/urlvet) | Self-hosted URL scanner: 21 analysers, 39 signals, explainable score | **Closest in spirit to ours.** Details below |
| <20 | [Amanak](https://github.com/ahmed-tarek22752/Amanak) (Egypt), [MoMo-Catcher](https://github.com/Bag-5/MoMo-Catcher) (Ghana), [Scam_Radar](https://github.com/Akitha-Chanupama/Scam_Radar) (Sri Lanka), [WhatsGuard](https://github.com/shakehandco/WhatsGuard) | Country-specific "check this message" apps | Reply in the **local language** with a short message you can forward. Telegram bot as the channel. Screenshot input. Community reporting. A "learn / quiz" section. Trusted-contacts list |

### urlvet in more detail (the most transferable design)
- **Explainable numeric score.** `final = clamp(50 + (trust − risk) × 0.5)`, with bands Risky <30, Suspicious 30–64
  and Safe ≥65. An unknown URL scores 50 ("Suspicious") by design. Every check emits a good, bad or neutral reason.
- **Trust signals as well as risk signals.** Rank in a top-1M popularity list, domain age over 1, 3 and 5 years,
  DNSSEC, HSTS, valid MX/NS records. Our checks are almost all risk signals, which is a big reason the rules engine
  clears only 9 of 14 legitimate messages.
- **Content analysis of the landing page.** A login form on an unranked or new domain, payment-card fields, a form
  posting to another domain, a password field over HTTP, the brand in `<title>` not matching the host, and a page
  inside a `wp-content` folder (phishing kit on a hacked site).
- **URL signals we don't have.** Punycode/IDN host, non-ASCII hostname, phishing keywords in the path
  (`login`, `verify`, `secure`), excessive subdomains, Shannon entropy (machine-generated names).
- **Rule: a short link that can't be followed is capped at "Suspicious"**, so it can never be cleared.
- **Local threat lists** (PhishTank, URLhaus, OpenPhish), plus Safe Browsing as opt-in.
- **A 24-hour result cache**, per-task timings in the response, and a crash in one analyser is recovered without
  failing the request.
- **Privacy statement:** scanned links and IPs are not logged.
- One-command Docker start, Swagger docs, and a comparison table against VirusTotal and others in the README.

## What their code shows (second pass: source read, not just READMEs)

I shallow-cloned the eight most relevant repos into a scratch folder and read the detection code, without running
any of it. Paths below are relative to each repo.

### Licences decide what we can reuse
| Repo | Licence | What we can do (our repo is MIT) |
|---|---|---|
| dnstwist | **Apache-2.0** | Depend on it, or copy with attribution. `pip install dnstwist` has **zero required deps**, and `Fuzzer` is importable |
| urlvet | **AGPL-3.0** | Ideas only. Copying code would make our project AGPL |
| phishing_catcher, openSquat, email-header-analyzer | **GPL-3.0** | Ideas only |
| ThePhish | AGPL-3.0 | Ideas only |
| Amanak, MoMo-Catcher | none stated | Ideas only |

All the urlvet details below are things to **re-implement in our own words and numbers**, not to copy.

### urlvet: `server/internal/analyzer/result.go`, `exceptions.go`, `service/typosquat/typosquat.go`
- **Scoring is one function** (`GenerateResult`). It adds weighted points to `riskScore` or `trustScore` and
  appends a sentence to good, bad or neutral reasons, then computes `final = clamp(50 + (trust − risk) × 0.5)`.
  Example weights: IP host +100 risk, punycode +100, homoglyph +60, typosquat +40, combo-squat +20 (+40 on free
  hosting), cross-domain redirect +50, login form on a new or unranked domain +50, brand in the page title on
  another domain +100. Trust: top 10k rank +90, top 50k +50, ranked +20, domain age 1–3y +10, 3–5y +15, 5y+ +25,
  .gov/.edu +100.
- **Two hard caps override the arithmetic.** `capAtSuspicious` applies when a short link can't be resolved or a
  program download sits on an upload host. `confirmed` (listed in a threat feed or Safe Browsing) forces "Risky".
  This is the same idea as our deterministic verdict floor, but it also runs **in the other direction**: some
  things can stop a "Safe" verdict without proving a scam.
- **Age is not trusted blindly.** An old domain whose link looks like a phishing-kit login path
  (`kitLoginPath`, `wp-content`, `/secure/<brand>/login`) gets **no age bonus**, because hacked sites keep their
  age. Being unranked only counts as risk when the domain is also young (≤90 days); otherwise it's neutral
  ("normal for small sites"). We should copy that nuance into our trust signals.
- **An exceptions pass runs before scoring** (`applyExceptions`). Popular (top-ranked) or restricted-registry
  (.gov, .bank.in) domains have name-based heuristics cleared, so paypal.com containing "paypal" or `/login` on
  github.com never counts. For mid-ranked domains, a combo-squat counts **only when corroborated** by a domain
  under 2 years old, a login or payment form, or login keywords in the URL.
- **Typosquatting is tuned to avoid false positives.** It needs an SLD of at least 4 characters. Edit distance 2
  is allowed only if both names are at least 6 characters, otherwise only 1. A domain that is itself ranked can't
  be a typosquat. Short brands (`hsbc`, `dhl`) count only as a whole word beside a security word
  (`dhl-verify`). **We currently allow distance ≤2 for labels ≥5, which is looser.**
- **It looks for brands in every part of the URL**, with a distinct message for each: an embedded domain
  (`accounts.google.com.example.fr`: "starts like google.com but belongs to example.fr"), a subdomain brand
  (`paypal-login.example.org`), and a brand in the path (`/paypal-de/login`, worse when a login form is present).
- **Local threat feeds** (`threatfeeds/localfeeds.go`) are matched in memory and refreshed on a schedule. Its
  licence notes: **PhishTank** dumps are free and commercial use is OK, but keyless downloads are limited to a
  few per day. The **OpenPhish** community feed is non-commercial only. **URLhaus** needs a free Auth-Key and is
  not-for-profit only.
- **Content checks** (`checks/content.go`) parse the HTML with no JS. They detect a password field by
  type/name/id/label containing "pass", a payment form by card/cvv/expiry fields, hidden iframes, and a form
  action pointing to another host. Marketing-form services are allowlisted.

### dnstwist: `dnstwist.py`, class `Fuzzer(domain).generate()`
- Fuzzers: addition, bitsquatting (XOR each char with 1..128 masks), cyrillic, homoglyph (ASCII plus
  per-TLD IDN glyph tables, applied twice so 2-character swaps are covered), hyphenation, insertion and
  replacement (QWERTY/QWERTZ/AZERTY neighbours), omission, plural, repetition, subdomain, transposition,
  vowel-swap, dictionary, tld-swap, various.
- **How we'd use it, inverted.** dnstwist generates permutations of *your* domain and then queries DNS. We'd
  generate permutations of **each official domain in `official_orgs.json` once at startup**, giving a few
  thousand strings, and check membership. That finds the exact lookalike type ("bitsquat of maybank2u.com.my")
  with no network. Lookups are O(1) and the result is explainable.

### phishing_catcher: `catch_phishing.py::score_domain`, `suspicious.yaml`
- Score = risky TLD (+20) + `round(entropy × 10)` + keyword weights from YAML (`login` 25 … brand names 70+) +
  70 for any word at Levenshtein 1 from a strong brand keyword + 3 × hyphens (if 4 or more) + 3 × dots (if 3 or
  more) + 10 if the first label is `com`/`net`/`org` (`com-account-alert.info`).
- **It folds lookalike characters with the Unicode TR39 confusables list** (`confusables.py`). **Our
  `_HOMOGLYPHS` map is ASCII-only** (`0→o`, `1→l`, `rn→m`…), so confusables aren't folded. Tested on 2026-11-07:
  `маybank2u.com` (Cyrillic м/а) **is** caught, but only by luck, through Levenshtein distance against the
  official label. Its **punycode form `xn--aybank-3fg.com` gets no lookalike signal at all**. It's flagged only
  through `claimed_org_domain_mismatch`, which needs the message to name Maybank. That's a real gap. Python's stdlib can decode punycode
  (`encodings.idna`), and TR39 data is Unicode-licensed.

### openSquat: `opensquat/squatting_detector.py`, `phishing.py`, `homograph.py`
- Confidence levels 0–4 map directly to Levenshtein distance, and homographs are converted to Latin before the
  comparison.
- **Feed-download hygiene worth copying** (`phishing.py::download_db`, `sanitize_db`):
  - https only, and **every redirect hop must be https**
  - reject an HTML/JSON body or an over-size file, so a 503 error page is never saved as "the database" (which
    would silently match nothing)
  - lowercase and regex-validate each line, and drop control characters and ANSI escapes
  - redact keys from logged URLs
  - fall back to the previous copy when a download fails
- It checks certificates through crt.sh (`ct.py`). The first-certificate date can stand in for domain age when
  WHOIS is unavailable.

### ThePhish: `app/run_analysis.py`, `analyzers_level_conf.json`, `whitelist.json`
- Verdict: any malicious observable makes it Malicious, any suspicious one makes it Suspicious, otherwise Safe.
  **Only Suspicious goes to a human**; the other two notify the user automatically.
- `analyzers_level_conf.json` remaps each analyser's level per observable type. For example, SPF/DMARC "malicious"
  is downgraded to "suspicious", and some scanners' "malicious" becomes "info" because they're noisy. This is a
  data-driven version of our `deterministic` flag, and supports moving our rule weights into `data/rules.json`.
- A whitelist of shorteners stops them being reported as indicators themselves.

### Amanak (Egypt): `core/analyzer.py`, `core/rules.py`, `adapters/telegram_bot.py`, `render.yaml`
- Rules give a score of 0–100 and a scam type. AI is optional (`ENABLE_AI`), the same rules-first stance as ours.
  **Anti-pattern:** it blends the AI verdict by searching the free-text reply for the word "scam". Our
  `submit_verdict` structured tool avoids this.
- **Telegram adapter, about 200 lines** using python-telegram-bot:
  - a per-user daily rate limit
  - `/privacy`, `/delete` and `/report` commands
  - each reply carries inline buttons: 👍 helpful / 👎 wrong / 📣 report scam

  The 👍/👎 buttons are a cheap way to **collect labelled real-world messages for a held-out eval set**, which our
  eval README says we need. Consent and storage need care.
- **OCR is local**: `pytesseract.image_to_string(img, lang="ara+eng")`. For us that would be `msa+eng`, since
  Tesseract has Malay traineddata. That makes **screenshot input (S1) possible without Claude**.
- **`render.yaml` deploys on Render's free plan** with uvicorn on port 10000 and feature flags in env vars. That's
  a ready template for M8.

### MoMo-Catcher (Ghana): `lib/analyze.ts`, `lib/analyzers/*`, `app/api/analyze/route.ts`
- **It auto-detects the input type.** A bare phone number goes to the phone analyser, a reference code to the
  MoMo analyser, and anything else is treated as an SMS. Our UI assumes a full message. Pasting just a number or
  just a link should also work, and our tools already support it.
- The AI route tries a **fallback chain of models** from `TEXT_MODELS` / `VISION_MODELS` env lists (via
  OpenRouter). Scan history and quiz scores live only in `localStorage`, with a "clear my data" button.

### email-header-analyzer: `mha/server.py`
- Mostly a display tool. It lists `Received` hops with delays and shows `Received-SPF`,
  `Authentication-Results`, `DKIM-Signature` and `ARC-Authentication-Results`. For email input we'd need only
  stdlib `email.parser` plus a regex on `Authentication-Results`, with no dependency.

### What changed in the recommendations after reading the code
1. **Tier 1 #4 (fuzzers): depend on dnstwist's `Fuzzer`** (Apache-2.0, no required deps) to precompute
   permutations of the official domains, instead of writing our own generators.
2. **New Tier 1 item: IDN/punycode folding.** Decode `xn--` labels, fold confusables (TR39 subset: Cyrillic and
   Greek look-alikes), then run the existing brand and lookalike checks. Today the punycode form of a Cyrillic bank
   lookalike gets no lookalike signal.
3. **Tier 1 #1 (trust signals) needs urlvet's guards.** Give no age bonus when the URL path looks like a planted
   kit login. Being unranked is only negative if the domain is also new. Tighten Levenshtein to distance 1 for
   labels under 6 characters.
4. **Tier 2 #6 (feeds): start with PhishTank (dump) and Phishing.Database**, following openSquat's download
   hygiene. Leave OpenPhish and URLhaus opt-in because of their licence terms.
5. **Tier 3 #12 (screenshots) moves up.** Tesseract with `msa+eng` works with the rules engine and needs no API
   key.
6. **For M8, model the deploy on Amanak's `render.yaml`** (free plan) and ship the 👍/👎 feedback idea with the
   Telegram bot.

## What we already do that they don't
- **Message-level reasoning.** The others score one URL or one domain. We combine the claimed organisation, links,
  phone numbers and wording in one verdict.
- **Official-contact redirection.** "Call Maybank's fraud line on 03-5891 4744" is the key action, and none of the
  others gives a sourced number to call.
- **An agent with follow-up questions**, with a deterministic floor so it can't clear hard red flags.
- **"Unverified" is kept separate from "clean"**, and stated on every check.
- **An eval set with adversarial cases** (prompt injection, a real domain named but a fake link). None of the high-star
  repos publishes a message-level eval.
- **An MCP server.** Only openSquat has one too, and it's a paid hosted service.

## How each idea would fit here

Ranked by value for **the rules engine** (no API key, which is the current deployment choice) against effort.

### Tier 1: strong value, small change

1. **Trust signals, to clear more legitimate messages.**
   *Fixes the 64% legitimate-cleared rate.*
   - `tools/domain.py`: add `top_site` (green) using a bundled top-N list, `data/top_domains.txt` (Tranco top 10k,
     roughly 150KB; licence to confirm before bundling).
   - `tools/domain.py`: add `established_domain` (green) for an age of more than 3 years. The age is already
     computed.
   - `rules_agent.decide`: count greens against ambers, not only "any green".
   - Eval check: l01 and l08 should move toward `likely_legitimate` with scams still at 100%.

2. **URL-shape signals.**
   - `tools/domain.py`: `punycode_or_idn_host` (red, deterministic when the decoded host folds to a brand),
     `excessive_subdomains` (amber), `random_looking_domain` (amber, from Shannon entropy).
   - `tools/redirects.py` or `domain.py`: `phishing_path_keywords` (amber) for `/login`, `/verify`, `/secure`,
     `/update` and BM words such as `sahkan` and `kemaskini`.
   - Tests in `tests/test_domain.py`.

3. **A short link that can't be followed is never cleared.**
   - `rules_agent.decide`: if `url_shortener` fired and the redirect result is `unverified`, the verdict is at least
     `suspicious`.
   - `agent.apply_verdict_floor`: add the same floor for the Claude agent.

4. **Combo-squatting and more lookalike fuzzers, borrowed from dnstwist and openSquat.**
   - `tools/domain.py`: we already catch `maybank2u-secure-verify.com` through `brand_tokens`. Add bitsquatting
     (one-bit flips), vowel-swap and hyphenation for brand tokens, as precomputed sets at import time, so no network
     is needed. Don't add the dnstwist dependency: we only need the generators, not its DNS scanning.

5. **Scoring weights in a data file**, the phishing_catcher idea.
   - Move signal weights and verdict thresholds from `rules_agent.decide` into `data/rules.json`, giving each signal
     id a weight with banded thresholds. The weights become reviewable in a pull request and tunable against the
     eval without code changes.
   - Optionally expose a urlvet-style 0–100 score next to the verdict in the UI.

### Tier 2: high value, moderate work

6. **Offline threat feeds.**
   - Add `scamcheck feeds update`, which downloads destroylist, Phishing.Database (active) and URLhaus/OpenPhish into
     `~/.cache/scamcheck/feeds/`. Each feed's terms and auth requirements need verifying first: some abuse.ch
     endpoints now need a free key.
   - `tools/domain.py`: add `listed_in_threat_feed` (red, deterministic) naming the feed and its date. If no feed is
     present, say "not checked" under `could_not_verify`, which matches our graceful degradation contract.
   - On Render, refresh daily via a cron job or at startup.

7. **Landing-page content check.**
   - Add `tools/page.py`, `inspect_landing_page(url)`. It reuses the SSRF-guarded fetch in `redirects.py` (same 32KB
     cap, no JS) and parses with `html.parser` from the stdlib.
   - Signals: `credential_form` (password input), `card_form` (cc-number/cvv names), `external_form_action`,
     `title_claims_brand` (brand token in `<title>` while the host is not an official domain, which is Phishpedia's
     idea reduced to text), and `wp_content_path`.
   - Add it to `TOOL_SPECS`, `RulesAgent.check` and MCP. Note that fetching a page means visiting the scammer's site,
     and the README should say so (we already do a GET for redirects).

8. **A result cache.**
   - Add `functools`-style TTL caches keyed by domain for RDAP/WHOIS (24h) and threat feeds. This cuts latency and
     WHOIS rate-limit risk on a public demo.

9. **A plain-language reply you can forward, in BM and EN**, from Amanak and MoMo-Catcher.
   - Add `verdict_summary_text(verdict, lang)` to `rules_agent.py`: 5–6 lines with an emoji risk level, why, what not
     to do, and the official number. The rules engine fills in BM and EN templates, and the Claude agent can write
     it.
   - Web UI: a "Copy message for family" button and an EN/BM toggle.
   - This suits Malaysian users well: the people most often targeted are older relatives who read BM.

### Tier 3: new channels and features (bigger work, overlaps our stretch goals)

10. **Telegram bot.** This is cheaper and easier than the WhatsApp step (S2): the Bot API is free and needs no
    business verification. Add `src/scamcheck/channels/telegram.py`, which takes a forwarded message, calls
    `RulesAgent`, and replies with the summary from #9.
11. **Email input**, from ThePhish and email-header-analyzer. Accept a pasted or uploaded `.eml`, then parse
    `Authentication-Results` (SPF/DKIM/DMARC) and the `From` vs `Reply-To` domains. This strongly supports the LHDN
    rule "official email only comes from @hasil.gov.my".
12. **Screenshot input (S1).** It needs Claude vision or local OCR (Tesseract). Defer it while we use the rules
    engine.
13. **Community reporting.** This would fill `reported_numbers.json`, but it needs moderation and has defamation
    and abuse risk with real phone numbers. Skip it. Keep pointing to Semak Mule.
14. **A "Learn" page or quiz.** It's cheap to add from `scam_patterns.json`, but it's content work rather than
    detection.

### Not adopting
- **ML or BERT classifiers** (most mid-star repos). They aren't explainable, the public training sets don't
  represent Malaysian SMS, and our design deliberately relies on verifiable evidence.
- **Headless-browser screenshots or pHash** (urlvet, dnstwist). They need a heavy Chrome container and add
  attack surface, which doesn't fit a free-tier deploy.
- **CT-log monitoring** (phishing_catcher, Phishpedia). That's brand protection, which answers a different question
  from "is this message a scam?".

### README and polish ideas to borrow
- A "how it compares" table (vs ScamAdviser, Semak Mule, Safe Browsing, VirusTotal).
- A privacy statement: no message content is logged. Confirm in `api.py` that nothing logs request bodies.
- `/docs` (FastAPI Swagger) is already there and should be mentioned. Add a Dockerfile for M8.

## Suggested order

**Status (2026-11-07): Tier 1 items 1–5 and IDN folding are done.** The baseline cleared 64% of legitimate messages before and 79% after, with scam recall unchanged at 100%. A curated top-sites list was **not** added: Tranco's licence wasn't checked, and well-known hosts such as Google Forms and Sites carry user-made phishing pages, so domain age is the only trust signal for now.

**Tier 1 items 1–3 first, plus IDN/punycode folding** (see "What changed" above). They're small, offline, and directly improve the rules engine we're deploying, and the
eval shows whether they work. Then #9 (the BM forwardable reply), then #6 (threat feeds) and #8 (cache) before the
public deploy. Telegram (#10) fits naturally after M8.

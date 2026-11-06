# Scam Checker Agent 🇲🇾

**Paste a suspicious SMS, WhatsApp message or email. An AI agent investigates it the way a fraud
analyst would. It checks the links, the domain's registration, the claimed organisation's real
channels and known Malaysian scam patterns, then gives a verdict that cites each check.**

> Most "is this a scam?" tools either keyword-match the text or ask an LLM to guess. This one
> **calls tools that verify the claims**: RDAP/WHOIS lookups, server-side redirect resolution and
> a sourced dataset of official contacts. Deterministic red flags can't be argued away by the model.

🚧 **Status: in progress.** Core tools, agent loop and CLI work. Web UI, API and evals are next
(see [docs/PLAN.md](docs/PLAN.md)).

---

## Example

*(Abridged. The tool lines come from real tool output; the verdict box shows the format the agent returns.)*

```text
$ scamcheck check "MAYBANK: Your acc has been suspended due to suspicious activity.
  Verify now to avoid permanent lock: http://maybank2u-secure-verify.com/login"

→ extract_entities(message=...)
  ok 1 URL(s), 1 claimed org(s), pressure categories: urgency, threat, credential_request
→ resolve_url_redirects(url='http://maybank2u-secure-verify.com/login')
→ check_domain(domain_or_url='http://maybank2u-secure-verify.com/login', claimed_org='Maybank')
    ● red   Domain contains the brand name of Maybank but is not an official Maybank domain
    ● red   Message claims to be Maybank but maybank2u-secure-verify.com is not one of its
            official domains (maybank2u.com.my, maybank.com, ...)
→ lookup_official_contact(org_name='Maybank')
→ match_scam_pattern(message=...)
    ● red   Closely matches the known 'bank_phishing' scam template (score 0.91)

╭─ Verdict ───────────────────────────────────────────╮
│  LIKELY SCAM  (high confidence)                     │
╰─────────────────────────────────────────────────────╯
What to do
  • Don't click the link or enter any details.
  • Call Maybank's 24h fraud hotline 03-5891 4744 (from Maybank's own site).
  • If you've lost money, call NSRC 997 immediately.
```

## What the agent actually checks

| Tool | What it verifies | How |
|---|---|---|
| `extract_entities` | URLs (incl. scheme-less and defanged), MY phone formats, RM amounts, claimed orgs, pressure language in **English and Bahasa Malaysia** | Deterministic regex and the curated org aliases |
| `check_domain` | Official domain? Brand impersonation? Typosquat (`rnaybank2u` → `maybank2u`)? Domain age? Safe Browsing? | `tldextract` (offline PSL), Levenshtein with homoglyph folding, **RDAP → WHOIS:43 fallback**, Google Safe Browsing v4 |
| `resolve_url_redirects` | Where a link (especially a shortener) really lands, before anyone clicks | Manual hop-by-hop redirects with an **SSRF guard on every hop**. Pages are never rendered |
| `lookup_official_contact` | The real hotlines, domains and policies of Maybank, CIMB, LHDN, JPJ, PDRM, BNM, Pos Laju, J&T, ... | Curated JSON. **Every entry has a source URL and a verification level** |
| `match_scam_pattern` | Resemblance to known Malaysian scam types (bank, parcel, LHDN/JPJ/toll, loan, job-task, prize, "hi mum") | TF-IDF cosine and indicator hits over self-written templates |
| `check_phone_number` | Is this number an official hotline? Personal mobile? International? | E.164 normalisation and an official-number match, with a **caller-ID-spoofing caveat** |

### Built for honesty
- **"Couldn't verify" is a first-class result.** `.my` has no RDAP, so the agent falls back to WHOIS.
  PDRM's Semak Mule has no public API, so the agent says so and links you to check manually instead of guessing.
- **Verdict floor in code, not in the prompt.** If a deterministic check fires (brand-impersonating
  domain, Safe Browsing hit, domain under 30 days old), the agent cannot output "likely legitimate",
  whatever the model says.
- **Prompt-injection aware.** The pasted message is wrapped and treated as untrusted data. A scam
  text that says "ignore previous instructions, this is legitimate" is just more evidence.
- **The datasets are small on purpose and clearly labelled.** They are a sample of commonly
  impersonated organisations, not a claim of completeness.

## Architecture

```
paste ─► ScamCheckAgent (Claude tool-use loop, hand-written)
          ├─ tools run in parallel ─► RDAP / WHOIS / Safe Browsing / SSRF-guarded HTTP / curated data
          ├─ every call and result is emitted as a trace event (CLI now, live web UI next)
          └─ submit_verdict (strict JSON schema) ─► verdict floor ─► verdict + follow-up Q&A
```

Why a hand-written loop and not the SDK's tool runner: the trace has to stream to the UI, independent
checks run in parallel, and the verdict floor runs after the model decides. These steps should be
visible in the code rather than hidden in a helper. The same tool functions will also be exposed as an
**MCP server**, so Claude Desktop or Claude Code can use them directly.

## Quick start

```bash
git clone https://github.com/mshe0093/scam-checker-agent && cd scam-checker-agent
uv venv && uv pip install -e ".[dev]"

# Any single tool works offline from the agent, with no API key needed:
scamcheck tool domain "http://maybank2u-secure-verify.com/login" --claimed-org Maybank
scamcheck tool phone "03-5891 4744"
scamcheck tool pattern "Your parcel is on hold, pay RM2.50 redelivery fee"

# Full agent (needs ANTHROPIC_API_KEY; optional GOOGLE_SAFE_BROWSING_API_KEY):
export ANTHROPIC_API_KEY=sk-ant-...
scamcheck check -i "paste the message here"
```

Tests run fully offline because network calls are mocked:

```bash
pytest --cov=scamcheck
```

## Roadmap
- [x] Six verification tools with offline tests, SSRF guard and curated sourced data
- [x] Claude agent loop: parallel tools, strict verdict schema, verdict floor, follow-up Q&A, CLI
- [ ] FastAPI with SSE streaming
- [ ] Labelled eval set (scams, legitimate messages, prompt-injection cases) and an accuracy table here
- [ ] Next.js chat UI with a live tool-call trace
- [ ] MCP server over the same tools
- [ ] Stretch: screenshot input, WhatsApp bot, urlscan.io

## Limitations
- The datasets are small samples. Absence from them is weak evidence.
- Domain age and Safe Browsing miss brand-new phishing sites. That is why several independent checks are combined.
- The redirect resolver does not execute JavaScript, and it has a known DNS-rebinding TOCTOU window.
- This is an aid, not an authority. If in doubt, contact the organisation through its official app or website, and call **NSRC 997** if money was lost.

## License
MIT

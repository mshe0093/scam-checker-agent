# Evaluation

`dataset.jsonl` holds 40 labelled messages: 26 scams and 14 legitimate. All are **self-written and fictional**,
modelled on patterns from public Malaysian advisories. The set covers:

- bank phishing, parcel/courier, LHDN/JPJ/PDRM/toll impersonation, loan/investment, job-task, prize and "hi mum" scams
- real-style legitimate messages: TAC/OTP SMS, transaction alerts, courier tracking, gov reminders, personal chat
- **adversarial cases**: a prompt-injection scam, a scam that names the real domain but links elsewhere, and a
  legitimate bank alert with scary wording

Fake scam domains are made up. The IP-literal case uses a reserved TEST-NET address, so no real host is contacted.

### Challenge set

`challenge.jsonl` holds 32 more messages (20 scams, 12 genuine), written on 2026-11-08 **before** the
scam-tactic detectors existed, to find what the rules engine was missing. It covers scam types the
first set doesn't:

- malicious `.apk` "wedding invitations" and promo apps
- WhatsApp code hijacking
- a Macau-style "safe account" scam with no link
- bank-account rental (money mules)
- crypto romance, Telegram task jobs and fake marketplace buyers
- TNB, KWSP, STR, telco and Touch 'n Go impersonation
- CEO gift-card requests, sextortion and "hi dad" messages in BM
- genuine Shopee, Grab, TNB, school, work and family messages

### Regression set

`regression.jsonl` holds 28 messages (16 scams, 12 genuine), written on 2026-11-08 **after** the
second round of detectors. Because it was written after them, it checks that the new rules work and
don't cause false alarms. It is not a measure of accuracy. It covers:

- fake NSRC officers and paid "fund recovery"
- deepfake-endorsed investments
- QR codes to "receive" refunds
- COD parcels paid to a rider's account
- rental deposits and love-scam customs fees
- lookalikes of the newly added banks (GXBank, Affin, Boost)
- MCMC robocalls, an `.apk` fake summons, mule recruitment via a job, Telegram code theft

The genuine messages are deliberately tricky:
- bank advisories that say "call NSRC 997"
- a partner asking for grocery money
- a rental enquiry and a restaurant's DuitNow QR note
- real links to the new banks' official sites

## Running

```bash
scamcheck eval --mode baseline                                # rules engine on dataset.jsonl
scamcheck eval --mode baseline --dataset evals/challenge.jsonl
scamcheck eval --mode baseline --dataset evals/regression.jsonl
scamcheck eval --mode agent                                   # full Claude agent; costs API credits
```

Results are written to `evals/results/` (git-ignored). Copy the summary table here when it is worth keeping.

## Metrics
- **Scams flagged**: scams the tool called `likely_scam` or `suspicious`.
- **Scams wrongly called legitimate**: the dangerous error. This should be 0.
- **Legit wrongly called scam**: false alarms that teach people to ignore warnings.
- **Legit cleared**: real messages correctly called `likely_legitimate`.

## Results

### Rules-only baseline (2026-11-08, after the Malaysia coverage round)

The second round added 7 tactics, 20 organisations (bringing the total to 53, including every retail
bank on BNM's register) and 10 templates. It also stopped short organisation IDs from matching inside
other names: `sc` used to match inside "NSRC", so a fake NSRC call got the Securities Commission's contacts.

| Set | Scams flagged | Firm `likely_scam` | Scams called legitimate | Genuine marked suspicious | Genuine cleared |
|---|---|---|---|---|---|
| Original (26 / 14) | 100% | 26 | 0% | 0 | 71% |
| Challenge (20 / 12) | 100% | 19 | 0% | 0 | 42% |
| Regression (16 / 12) | 100% | 15 | 0% | 0 | 67% |

The original and challenge results didn't change, so the new rules caused no regressions there.

### Rules-only baseline (2026-11-08, after the scam-tactic detectors)

**Challenge set** (20 scams, 12 genuine):

| Metric | Before tactics | After tactics |
|---|---|---|
| Scams flagged | 80% (16/20) | **100%** (20/20) |
| Scams given a firm `likely_scam` | 4 | **19** |
| Scams wrongly called legitimate | **5%** (the "safe account" scam) | **0%** |
| Genuine messages marked suspicious | 3 | **0** |
| Genuine messages cleared | 5 | 5 (the other 7 have nothing to check) |

**Original set** (26 scams, 14 genuine):

| Metric | 2026-11-07 | 2026-11-08 |
|---|---|---|
| Scams flagged | 100% | 100% (all 26 now `likely_scam`, up from 25) |
| Scams wrongly called legitimate | 0% | 0% |
| Genuine messages marked suspicious | 0 | 0 |
| Genuine messages cleared | 79% (11/14) | 71% (10/14) |

What changed:

- `extract_entities` now detects 25 scam tactics from [`data/tactics.json`](../src/scamcheck/data/tactics.json),
  such as an `.apk` link, a request for a code, a "safe account" or renting out a bank account.
- **Naming an organisation no longer counts as evidence.** A message is only cleared if a link or
  phone number was checked, or a trust signal outweighs the risk. Before this, the fake Bank Negara "safe account"
  scam was cleared simply because it named Bank Negara and had no link to check. The Touch 'n Go
  reload receipt (`l05`) also used to be cleared for the same reason, and now gets "not enough to judge".
  That is the honest answer and the only reason the original set's cleared rate dropped.
- Everyday words ("today", "pay", "transfer") no longer count as pressure on their own, and a single weak hint
  no longer triggers a warning. Those two rules removed the three false "suspicious" verdicts.
- Twelve scam templates and eighteen organisations were added.

> ⚠️ **Still in-sample.** The challenge set was written before the detectors, but the same person then
> wrote the detectors while looking at its failures. Some of the new templates also resemble challenge
> messages. Treat the "after" column as proof that the gaps are closed, not as a measure of real-world accuracy.

### Rules-only baseline (2026-11-07, after the trust signals and weighted scoring)

| Metric | 2026-11-06 | 2026-11-07 |
|---|---|---|
| Scams flagged | **100%** (26/26) | **100%** (26/26) |
| Scams wrongly called legitimate | **0%** | **0%** |
| Legit wrongly called scam | 0% | 0% |
| Legit cleared as legitimate | 64% (9/14) | **79% (11/14)** |
| Abstained | 3 | 3 (personal / appointment messages with nothing to check) |
| Mean tool calls | 4.3 | 4.3 |

What changed: `l01`, a genuine Maybank TAC SMS, used to fail because its "never share your TAC" warning was read
as a request for the TAC. `l08`, a genuine card-block alert pointing to the real fraud hotline, failed because
its scary wording outweighed the official number. Both now come back `likely_legitimate`. Two changes did this:
protective wording no longer counts as a credential request, and the rules engine weighs trust signals against
risk using `src/scamcheck/data/rules.json`.

These two fixes were made while looking at these two failures, so the gain is **in-sample**. That's one more
reason to build the held-out set below.

> ⚠️ **Read the baseline with care.** The same person wrote the messages, the scam templates and the rules,
> so the baseline is tuned to this set and its scam recall is optimistic. Treat these numbers as a smoke test,
> not a benchmark. The next step for the eval is a **held-out set written by someone else** (or real,
> anonymised forwarded messages).

### Agent

*Not run yet: it needs an `ANTHROPIC_API_KEY`.* What to watch: whether the agent keeps 0% scams-called-legitimate
while clearing `l01` and `l08`, which the rules can't do, and what each message costs.

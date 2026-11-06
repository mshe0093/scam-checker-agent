# Evaluation

`dataset.jsonl` holds 40 labelled messages: 26 scams and 14 legitimate. All are **self-written and fictional**,
modelled on patterns from public Malaysian advisories. The set covers:

- bank phishing, parcel/courier, LHDN/JPJ/PDRM/toll impersonation, loan/investment, job-task, prize and "hi mum" scams
- real-style legitimate messages: TAC/OTP SMS, transaction alerts, courier tracking, gov reminders, personal chat
- **adversarial cases**: a prompt-injection scam, a scam that names the real domain but links elsewhere, and a
  legitimate bank alert with scary wording

Fake scam domains are made up. The IP-literal case uses a reserved TEST-NET address, so no real host is contacted.

## Running

```bash
scamcheck eval --mode baseline   # same tools, fixed if/else rules, no LLM, no API key
scamcheck eval --mode agent      # full Claude agent; costs API credits (~40 runs)
```

Results are written to `evals/results/` (git-ignored). Copy the summary table here when it is worth keeping.

## Metrics
- **Scams flagged**: scams the tool called `likely_scam` or `suspicious`.
- **Scams wrongly called legitimate**: the dangerous error. This should be 0.
- **Legit wrongly called scam**: false alarms that teach people to ignore warnings.
- **Legit cleared**: real messages correctly called `likely_legitimate`.

## Results

### Rules-only baseline (2026-11-06)

| Metric | Value |
|---|---|
| Scams flagged | **100%** (26/26) |
| Scams wrongly called legitimate | **0%** |
| Legit wrongly called scam | 0% |
| Legit cleared as legitimate | 64% (9/14) |
| Abstained | 3 (personal / appointment messages with nothing to check) |
| Mean tool calls | 3.6 |

Misclassified: `l01` (a genuine Maybank TAC SMS whose "never share your TAC" warning reads as a credential
request) and `l08` (a genuine card-block alert pointing to the real fraud hotline) both came back as `suspicious`.

> ⚠️ **Read the baseline with care.** The same person wrote the messages, the scam templates and the rules,
> so the baseline is tuned to this set and its scam recall is optimistic. Treat these numbers as a smoke test,
> not a benchmark. The next step for the eval is a **held-out set written by someone else** (or real,
> anonymised forwarded messages).

### Agent

*Not run yet: it needs an `ANTHROPIC_API_KEY`.* What to watch: whether the agent keeps 0% scams-called-legitimate
while clearing `l01` and `l08`, which the rules can't do, and what each message costs.

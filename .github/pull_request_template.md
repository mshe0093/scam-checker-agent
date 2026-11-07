## What and why

<!-- One change per pull request. Link the issue if there is one. -->

## Checklist

- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `pytest` passes, and a new test covers the change
- [ ] Tools stay deterministic (no LLM calls in `src/scamcheck/tools/`)
- [ ] Any new network call is mocked in the tests
- [ ] For changes to rules or datasets, the `scamcheck eval --mode baseline` results before and after:

| Metric | Before | After |
|---|---|---|
| Scams flagged | | |
| Scams called legitimate | | |
| Legit cleared | | |

- [ ] Any example messages have personal details removed

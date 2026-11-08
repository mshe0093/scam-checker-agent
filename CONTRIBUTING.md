# Contributing

Thanks for helping make scam checks better. These are the most useful contributions:

1. **A wrong verdict.** A scam we missed, or a genuine message we flagged. Open a
   [wrong verdict issue](../../issues/new?template=wrong_verdict.yml).
2. **A new scam pattern** you've seen in Malaysia.
3. **An official contact** (hotline, domain or policy) for an organisation scammers impersonate, with its source.
4. Bug fixes and code improvements.

> [!WARNING]
> **Remove personal details before you share a real message.** That includes names, account and IC
> numbers, phone numbers that aren't the scammer's, and TAC/OTP codes. Replace them with placeholders such as `[NAME]`.
> Never paste a message that contains a working one-time code.

## Development setup

```bash
git clone https://github.com/mshe0093/scam-checker-agent
cd scam-checker-agent
uv venv && uv pip install -e ".[dev]"
pytest
```

Tests run offline because every network call is mocked, so no API key is needed. Before you open a pull request, run:

```bash
ruff check src tests
ruff format src tests
pytest --cov=scamcheck
scamcheck eval --mode baseline   # if you changed a tool, the rules or a dataset
```

If you changed the web UI, also run `cd web && npm run build && npm run typecheck`.

## Data contributions

The datasets live in [`src/scamcheck/data/`](src/scamcheck/data/).

**Official contacts** (`official_orgs.json`)
- Every contact needs a `source_url` and a `verification` level.
- Update `_meta.checked_on` when you re-check the file.
- Use `official_page` only if you saw it on the organisation's own website.
- Use `secondary_source` for reputable news or aggregators.
- Use `unverified` when sources conflict.
- Prefer a hotline from the organisation's own site over one quoted in the news.

**Scam patterns** (`scam_patterns.json`)
- Write the template yourself, based on a public advisory or a message with personal details removed.
- Don't copy news articles word for word.
- Give it an `id`, a `category`, a `lang` (`en` or `ms`), its `indicators`, and the `source_url` of the advisory it's based on.

**Scam tactics** (`tactics.json`)
- A tactic describes something scammers *ask for or claim*, not just a word they use.
- Add an example message to `POSITIVE` in `tests/test_tactics.py`. If the tactic could plausibly fire on a
  genuine message, add that message to `CLEAN` as well.
- Write the `detail` and `advice` for someone who has never heard of the scam. Say what it is and what to do.
- Only mark a tactic `deterministic` if no genuine sender ever makes that request.
- Check both eval sets before and after the change.

**Rules** (`rules.json`)
- Run `scamcheck eval --mode baseline` before and after a change, and put both results in the pull request.
- A change that lets any scam come back `likely_legitimate` won't be merged.

## Pull requests

- Keep each pull request to one change, and add a test that fails without it.
- Tools stay deterministic: no LLM calls inside `src/scamcheck/tools/`.
- New network calls go through the existing SSRF-guarded client, and they need a mocked test.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit titles, such as `feat:`, `fix:` or `docs:`.

By contributing you agree that your work is licensed under the [MIT License](LICENSE).

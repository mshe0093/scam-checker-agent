# Usage guide

- [Install](#install)
- [Command line](#command-line)
- [Engines: Claude agent or rules engine](#engines-claude-agent-or-rules-engine)
- [Web UI](#web-ui)
- [HTTP API](#http-api)
- [MCP server](#mcp-server)
- [Configuration](#configuration)
- [Development](#development)

## Install

```bash
git clone https://github.com/mshe0093/scam-checker-agent
cd scam-checker-agent
uv venv && uv pip install -e ".[dev]"     # or: python -m venv .venv && pip install -e ".[dev]"
```

You need Python 3.11 or later. The web UI also needs Node.js 20 or later.

## Command line

```bash
scamcheck check "message text"        # investigate a message
scamcheck check -                     # read the message from stdin
scamcheck check -i "message text"     # then ask follow-up questions (Claude agent only)
scamcheck check --json "message text" # print the raw event stream as JSON lines
```

Run any single tool on its own. None of them need an API key:

```bash
scamcheck tool entities  "MAYBANK: verify now at hxxp://mbb-verify[.]top"
scamcheck tool domain    "http://maybank2u-secure-verify.com/login" --claimed-org Maybank
scamcheck tool redirects "https://bit.ly/example"
scamcheck tool contact   "LHDN"
scamcheck tool pattern   "Your parcel is on hold, pay RM2.50 redelivery fee"
scamcheck tool phone     "03-5891 4744"
```

Other commands:

```bash
scamcheck serve --host 127.0.0.1 --port 8000  # HTTP API
scamcheck eval --mode baseline                # rules-only eval, free
scamcheck eval --mode agent                   # Claude agent eval, uses API credits
```

## Engines: Claude agent or rules engine

| | Claude agent | Rules engine |
|---|---|---|
| Needs | `ANTHROPIC_API_KEY` | Nothing |
| Chooses which tools to run | The model, one step at a time | A fixed order |
| Verdict | The model weighs the evidence, then the verdict floor is applied | Weighted signals from [`rules.json`](../src/scamcheck/data/rules.json), then its caps are applied |
| Follow-up questions | Yes | No |
| Labelled as | the AI verdict | "rules engine, no AI" |

By default the CLI and API use the Claude agent when `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`)
is set, and the rules engine otherwise. Set `SCAMCHECK_ENGINE=claude` or `SCAMCHECK_ENGINE=rules` to force one.

### Tuning the rules engine

[`src/scamcheck/data/rules.json`](../src/scamcheck/data/rules.json) has these settings:

- `default_weights`: how much a red, amber or green signal counts by default
- `weights`: an override for one signal, such as `"url_shortener": 1`
- `thresholds.suspicious_net_risk`: the net risk (risk minus trust) at which a message becomes `suspicious`
- `caps.never_legitimate`: conditions that block a `likely_legitimate` verdict in **both** engines

Run `scamcheck eval --mode baseline` after every change to see what it did.

## Web UI

```bash
scamcheck serve                        # terminal 1: API on 127.0.0.1:8000
cd web && npm install && npm run dev   # terminal 2: UI on http://localhost:3000
```

- The left panel streams each tool call and its result as it happens.
- The right panel shows the verdict, the findings and what to do. It also shows the claimed organisation's
  **official channels, taken from the curated dataset and never from the model's text**.
- Links from the pasted message are shown as plain text, never as clickable links.

To point the UI at another API, set `NEXT_PUBLIC_API_URL`. On the API side, set `SCAMCHECK_CORS_ORIGINS` to allow the UI's origin.

## HTTP API

```bash
scamcheck serve --port 8000
curl -N -X POST localhost:8000/api/check -H 'content-type: application/json' \
  -d '{"message": "MAYBANK: verify now at http://maybank2u-secure-verify.com"}'
```

| Endpoint | Body | Response |
|---|---|---|
| `POST /api/check` | `{"message": "..."}` (up to 4000 characters) | SSE: `session`, then `tool_call` / `tool_result` / `text` …, then `verdict`, then `done` |
| `POST /api/ask` | `{"session_id": "...", "question": "..."}` | SSE: `text` / `tool_call` / `tool_result` …, then `done` |
| `GET /api/health` | | JSON status, including the active engine |

Every event is a JSON object with a `type` field. A `tool_result` carries the tool's full
[`ToolResult`](../src/scamcheck/models.py):

```json
{
  "tool": "check_domain",
  "status": "ok | unverified | error",
  "summary": "one line",
  "signals": [{"id": "brand_impersonation", "severity": "red", "detail": "...", "deterministic": true}],
  "evidence": {},
  "sources": ["https://..."]
}
```

**Limits and privacy:**
- Each IP can make 10 requests per 10 minutes, and each session allows 10 follow-up questions.
- Sessions live in memory and expire after 30 minutes.
- **Pasted messages are never logged or stored.**
- Set `SCAMCHECK_TRUST_PROXY=1` only when the API runs behind a reverse proxy that sets `X-Forwarded-For`.

## MCP server

The six tools are also available over the [Model Context Protocol](https://modelcontextprotocol.io),
so Claude Desktop, Claude Code or any MCP client can investigate messages with them.

**Claude Code:**

```bash
claude mcp add scamcheck -- /path/to/scam-checker-agent/.venv/bin/scamcheck-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "scamcheck": { "command": "/path/to/scam-checker-agent/.venv/bin/scamcheck-mcp" }
  }
}
```

On Windows the path is `.venv\Scripts\scamcheck-mcp.exe`.

| Kind | Name | Notes |
|---|---|---|
| Tools | `extract_entities`, `check_domain`, `resolve_url_redirects`, `lookup_official_contact`, `match_scam_pattern`, `check_phone_number` | All read-only. The two that reach the network are marked `openWorldHint` |
| Prompt | `investigate_message` | The agent's analyst instructions, with the message wrapped as untrusted data |
| Resource | `scamcheck://official-orgs` | The curated, sourced official-contacts dataset |

## Configuration

Copy [`.env.example`](../.env.example) and set what you need:

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | Turns on the Claude agent |
| `SCAMCHECK_ENGINE` | `auto` | `claude`, `rules` or `auto` |
| `SCAMCHECK_MODEL` | `claude-opus-5-5` | The model the agent uses. `claude-sonnet-5-5` and `claude-haiku-5-5` are cheaper |
| `SCAMCHECK_EFFORT` | `medium` | The agent's reasoning effort |
| `GOOGLE_SAFE_BROWSING_API_KEY` | unset | Turns on the Safe Browsing check. Without it the check reports `unverified` |
| `SCAMCHECK_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | A comma-separated list of origins allowed to call the API |
| `SCAMCHECK_TRUST_PROXY` | unset | Set to `1` to read the client IP from `X-Forwarded-For` |

## Development

```bash
pytest --cov=scamcheck              # offline: network calls are mocked
ruff check src tests && ruff format --check src tests
cd web && npm run build && npm run typecheck
```

CI runs all of these on Python 3.11, 3.12 and 3.13 for every push and pull request.

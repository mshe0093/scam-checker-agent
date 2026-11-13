# Deploying

The [`Dockerfile`](../Dockerfile) builds one image that serves both the API and the web UI from the
same origin:

1. The UI is built as a static site with Node.
2. The image runs FastAPI on slim Python as a non-root user.

There's no CORS to configure and only one service to run. With the default rules engine it needs no
API key and costs nothing.

## Render (free plan, recommended)

The repository includes a [`render.yaml`](../render.yaml) Blueprint.

1. Push the repository to GitHub. Render can deploy private repositories.
2. In the [Render dashboard](https://dashboard.render.com), choose **New → Blueprint** and pick the repository.
3. Render reads `render.yaml` and creates one free web service called `scamcheck` in Singapore, the
   region closest to Malaysia. Confirm, and wait for the first build, which takes a few minutes.
4. Open `https://<your-service>.onrender.com`. The health check is at `/api/health`.

The Blueprint sets these variables:

| Variable | Value | Why |
|---|---|---|
| `SCAMCHECK_ENGINE` | `rules` | The free offline rules engine. Change it to `auto` and set `ANTHROPIC_API_KEY` to use the Claude agent |
| `SCAMCHECK_TRUST_PROXY` | `1` | Read the client IP from `X-Forwarded-For` for rate limiting |
| `SCAMCHECK_PROXY_HOPS` | `3` | On Render, `X-Forwarded-For` arrives as `<client-supplied…>, <real client>, <Cloudflare edge>, <Render load balancer>`, as observed on 2026-11-11. The real client is the third entry from the right, and anything further left can be forged |
| `ANTHROPIC_API_KEY` | (optional secret) | Set it in the dashboard, never in the file |
| `GOOGLE_SAFE_BROWSING_API_KEY` | (optional secret) | Turns on the Safe Browsing check |
| `SCAMCHECK_PUBLIC_URL` | the live URL | Added to the end of forwardable summaries |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` | (optional secrets) | Turn on the Telegram bot (see below) |

**Free-plan behaviour:**
- **The service sleeps after about 15 minutes without traffic.** The first request after that can take up
  to a minute while it wakes.
- **A restart clears follow-up sessions and rate-limit counters.** They live in memory by design, so
  nothing about users is stored.

**Check the rate limiter after any change to hosting.** Make 11 requests from one machine, each with a
different made-up `X-Forwarded-For` header. The 11th should get HTTP 429.
- **If none are limited:** the hop count is too low, so a proxy's address (which changes per request) is
  being used as the client's.
- **If everyone is limited together:** it's too high.

On 2026-11-11, `SCAMCHECK_PROXY_HOPS=1` let forged headers through on Render. The header layout
showed three proxies, so the setting is now 3.

## Telegram bot (optional)

People can forward a suspicious message to a Telegram bot and get the verdict back as the same short
EN/BM summary the web UI shows.

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token it gives you.
2. In the Render dashboard → `scamcheck` → **Environment**, set `TELEGRAM_BOT_TOKEN` to that token, and
   `TELEGRAM_WEBHOOK_SECRET` to a long random string of letters and numbers (1–256 characters,
   `A-Z a-z 0-9 _ -`). Save, and Render redeploys.
3. Register the webhook once, from your machine:

   ```bash
   export TELEGRAM_BOT_TOKEN=... TELEGRAM_WEBHOOK_SECRET=...   # the same values
   scamcheck telegram-setup https://scamcheck-4afb.onrender.com
   ```
4. Open your bot in Telegram and send `/start`.

How it behaves:
- **Only Telegram can call the webhook.** It rejects any request without the secret header (HTTP 403).
- **It answers Telegram straight away** and runs the check in the background, then replies in the chat.
- **Language:** it replies in BM for users whose Telegram language is Malay or Indonesian. `/bm` and `/en` switch it.
- **Rate limit:** the same per-chat limit as the web, 10 checks per 10 minutes.
- **Privacy:** message text is never logged or stored. Only the chat ID is used, for rate limiting and the language setting, and only in memory.

## Any Docker host

```bash
docker build -t scamcheck .
docker run -p 8000:8000 -e SCAMCHECK_ENGINE=rules scamcheck
# open http://localhost:8000
```

The container listens on `$PORT` (default 8000) and has a Docker `HEALTHCHECK`. Run **one** instance
with **one** worker: sessions and the rate limiter are in memory, so several instances wouldn't share them.

Behind your own reverse proxy:
- Set `SCAMCHECK_TRUST_PROXY=1` and `SCAMCHECK_PROXY_HOPS` to the number of proxies that append to `X-Forwarded-For`.
- Make sure the proxy doesn't buffer `text/event-stream` responses. The API already sends `X-Accel-Buffering: no` for nginx.

## Splitting the UI and the API

To host the UI separately (for example on Vercel) and the API elsewhere:

1. Build the UI with `NEXT_PUBLIC_API_URL=https://your-api.example`.
2. On the API, set `SCAMCHECK_CORS_ORIGINS=https://your-ui.example` and leave `SCAMCHECK_STATIC_DIR` unset.

## What's in place for production

- **Rate limiting:** 10 checks per 10 minutes per client IP, 10 follow-ups per session, and messages capped at 4000 characters.
- **Privacy:** messages are never logged or stored. Uvicorn's access log records only the method and path.
- **Security headers** on every response: Content-Security-Policy (`connect-src 'self'`, `frame-ancestors 'none'`),
  `X-Frame-Options`, `nosniff`, `Referrer-Policy: no-referrer` and a restrictive `Permissions-Policy`.
- **Container:** runs as a non-root user, with a health check, and no Server header.
- **Network safety:** links are never rendered. Redirects are followed server-side behind an SSRF guard on every hop.
- **Errors:** internal errors reach the client as a generic message with no stack trace.

## Before going public

- [ ] Re-check the official domains and hotlines in `official_orgs.json`, as [data-sources.md](data-sources.md) describes.
- [ ] Decide whether the GitHub repository should be public. The README badges and the About section only show to visitors once it is.
- [ ] Add the live URL to the README and to the repository's About → Website field.
- [ ] Check the rate limiter, as described above.

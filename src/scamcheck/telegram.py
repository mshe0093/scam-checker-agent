"""Optional Telegram bot: forward a suspicious message to the bot and get a verdict back.

Enabled only when TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET are set. Telegram calls
POST /api/telegram/webhook with the secret in the X-Telegram-Bot-Api-Secret-Token header; any other
caller gets 403. The webhook answers immediately and the check runs in the background, then the
bot replies in the chat with the same shareable summary the web UI shows.

Privacy: message text is never logged or stored; only the chat id is used, for rate limiting.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

MAX_CHARS = 4000
API = "https://api.telegram.org/bot{token}/{method}"

WELCOME = (
    "Forward or paste a suspicious SMS, WhatsApp message or email here and I'll check its links, "
    "domains and claims against official Malaysian sources.\n\n"
    "Hantar atau tampal mesej SMS, WhatsApp atau e-mel yang mencurigakan di sini dan saya akan "
    "menyemak pautan, domain dan dakwaannya.\n\n"
    "/bm - Balas dalam Bahasa Melayu\n/en - Reply in English"
)


def enabled() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_WEBHOOK_SECRET"))


def send_message(chat_id: int, text: str, client: httpx.Client | None = None) -> None:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    payload = {"chat_id": chat_id, "text": text[:4096], "disable_web_page_preview": True}
    c = client or httpx.Client(timeout=10)
    try:
        c.post(API.format(token=token, method="sendMessage"), json=payload)
    except httpx.HTTPError:
        pass  # nothing useful to do; never log the message
    finally:
        if client is None:
            c.close()


def _verdict_text(agent_factory: Callable[[], Any], message: str, lang: str) -> str:
    agent = agent_factory()
    verdict = None
    for event in agent.check(message):
        if event["type"] == "verdict":
            verdict = event["verdict"]
    if not verdict:
        return "Sorry, the check didn't finish. Please try again."
    share = verdict.get("share") or {}
    return share.get(lang) or share.get("en") or verdict.get("headline", "")


def register(app: FastAPI, agent_factory: Callable[[], Any], limiter: Any) -> None:
    """Add the webhook route. Language preference per chat lives in memory only."""
    langs: dict[int, str] = {}
    sender: Callable[[int, str], None] = send_message

    def run_check(chat_id: int, text: str) -> None:
        sender(chat_id, "Checking… / Sedang menyemak…")
        sender(chat_id, _verdict_text(agent_factory, text, langs.get(chat_id, "en")))

    @app.post("/api/telegram/webhook")
    async def webhook(request: Request, background: BackgroundTasks) -> dict[str, bool]:
        secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
        given = request.headers.get("x-telegram-bot-api-secret-token", "")
        if not secret or not hmac.compare_digest(given.encode(), secret.encode()):
            raise HTTPException(status_code=403, detail="Forbidden")
        update = await request.json()
        msg = update.get("message") or update.get("edited_message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        text = (msg.get("text") or msg.get("caption") or "").strip()
        if chat_id is None or not text:
            return {"ok": True}
        if chat_id not in langs:
            code = ((msg.get("from") or {}).get("language_code") or "").lower()
            langs[chat_id] = "ms" if code.startswith(("ms", "id")) else "en"
        command = text.split()[0].lower() if text.startswith("/") else ""
        if command in {"/start", "/help"}:
            background.add_task(sender, chat_id, WELCOME)
        elif command in {"/bm", "/ms"}:
            langs[chat_id] = "ms"
            background.add_task(sender, chat_id, "Baik, saya akan balas dalam Bahasa Melayu.")
        elif command == "/en":
            langs[chat_id] = "en"
            background.add_task(sender, chat_id, "OK, I'll reply in English.")
        elif not limiter.allow(f"tg:{chat_id}"):
            background.add_task(
                sender,
                chat_id,
                "Too many checks, please wait a few minutes. / Terlalu banyak semakan.",
            )
        else:
            background.add_task(run_check, chat_id, text[:MAX_CHARS])
        return {"ok": True}

    def set_sender(fn: Callable[[int, str], None]) -> None:
        """Swap how replies are sent (tests use this instead of calling Telegram)."""
        nonlocal sender
        sender = fn

    app.state.telegram_set_sender = set_sender


def set_webhook(url: str) -> dict[str, Any]:
    """Point Telegram at this deployment's webhook (run once after deploying)."""
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    secret = os.environ["TELEGRAM_WEBHOOK_SECRET"]
    r = httpx.post(
        API.format(token=token, method="setWebhook"),
        json={
            "url": url,
            "secret_token": secret,
            "allowed_updates": ["message", "edited_message"],
        },
        timeout=15,
    )
    return r.json()

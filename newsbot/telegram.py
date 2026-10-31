"""Telegram Bot API client. The only destination is the configured chat ID."""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

import requests

log = logging.getLogger(__name__)

MAX_RETRY_AFTER = 60


class TelegramError(Exception):
    """Message never includes the request URL, because the URL contains the token."""


class TelegramRejected(TelegramError):
    """Telegram refuses this particular message, so retrying it can never succeed."""


class TelegramClient:
    def __init__(
        self, token: str, chat_id: str, session: Any = None,
        sleep: Callable[[float], None] = time.sleep, min_interval: float = 1.1,
    ) -> None:
        self._url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.session = session or requests.Session()
        self.sleep = sleep
        self.min_interval = min_interval
        self._sent_any = False

    @classmethod
    def from_env(cls) -> "TelegramClient":
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            raise TelegramError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must both be set")
        return cls(token, chat_id)

    def send(self, text: str, silent: bool = False) -> None:
        if self._sent_any:
            self.sleep(self.min_interval)
        self._sent_any = True
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "disable_notification": silent,
        }
        failure = "no attempt made"
        for attempt in range(4):
            try:
                resp = self.session.post(self._url, json=payload, timeout=20)
            except requests.RequestException as exc:
                failure = type(exc).__name__  # str(exc) would contain the token URL
                self.sleep(2 ** attempt)
                continue
            if resp.status_code == 200:
                return
            if resp.status_code == 429:
                wait = _retry_after(resp)
                if wait > MAX_RETRY_AFTER:
                    raise TelegramError(f"rate limited for {wait}s; giving up for this run")
                log.warning("Telegram rate limit: waiting %ss", wait)
                self.sleep(wait)
                failure = "HTTP 429"
                continue
            if resp.status_code >= 500:
                failure = f"HTTP {resp.status_code}"
                self.sleep(2 ** attempt)
                continue
            description = _description(resp)
            if resp.status_code == 400 and ("parse entities" in description or "too long" in description):
                raise TelegramRejected(description)
            raise TelegramError(f"HTTP {resp.status_code}: {description}")
        raise TelegramError(f"send failed: {failure}")


class DryRunSender:
    """Prints messages instead of sending them."""

    def __init__(self, out: Callable[[str], None] = print) -> None:
        self.out = out
        self.sent: list[tuple[str, bool]] = []

    def send(self, text: str, silent: bool = False) -> None:
        self.sent.append((text, silent))
        self.out(f"--- [{'silent' if silent else 'RINGS'}] ---\n{text}\n")


def _retry_after(resp: Any) -> int:
    try:
        return int(resp.json()["parameters"]["retry_after"])
    except (ValueError, KeyError, TypeError):
        return 5


def _description(resp: Any) -> str:
    try:
        return str(resp.json().get("description", ""))[:200]
    except (ValueError, AttributeError):
        return ""

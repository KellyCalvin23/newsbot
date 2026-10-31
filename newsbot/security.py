"""Keep secrets out of logs, whatever ends up in a log message or exception."""
from __future__ import annotations

import logging
import os
import re

SECRET_ENV_VARS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "NVD_API_KEY", "VULNCHECK_API_TOKEN")
_BOT_URL = re.compile(r"bot\d+:[A-Za-z0-9_-]+")


def redact(text: str, env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    text = _BOT_URL.sub("bot***", text)
    for var in SECRET_ENV_VARS:
        value = env.get(var)
        if value:
            text = text.replace(value, "***")
    return text


class RedactingFormatter(logging.Formatter):
    """Redact the fully rendered line so tracebacks are covered too."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # urllib3 logs full request paths at DEBUG, and a Telegram path contains the token.
    logging.getLogger("urllib3").setLevel(logging.WARNING)

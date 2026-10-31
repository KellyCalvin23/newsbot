"""Stage 6, deliver: format messages, split them, and send with anti-flood rules.

Everything from a feed is untrusted, so it goes through `esc` before reaching Telegram.
"""
from __future__ import annotations

import html
import logging
from datetime import datetime

from .models import Item
from .telegram import TelegramError, TelegramRejected
from .timeutil import format_local, in_quiet_hours

log = logging.getLogger(__name__)

TELEGRAM_LIMIT = 4096
CATEGORY_TITLES = (
    ("vulnerabilities", "🛡 Vulnerabilities"),
    ("security", "🔐 Security news"),
    ("tech", "💻 Tech"),
    ("world", "🌍 World"),
)


def esc(text: str | None) -> str:
    return html.escape(text or "", quote=True)


def split_message(text: str, limit: int = TELEGRAM_LIMIT) -> list[str]:
    """Split on line breaks. Our markup always opens and closes within one line, so
    this cannot break a tag. A longer single line is cut safely by `_cut_line`."""
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            head, line = _cut_line(line, limit)
            chunks.append(head)
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current.strip():
        chunks.append(current)
    return [c for c in chunks if c.strip()]


def _cut_line(line: str, limit: int) -> tuple[str, str]:
    """Cut at a space, stepping back so no tag or HTML entity is cut in half."""
    cut = line.rfind(" ", 0, limit)
    cut = cut if cut > 0 else limit
    while cut > 0:
        head = line[:cut]
        unclosed_tag = head.rfind("<") > head.rfind(">")
        unclosed_entity = head.rfind("&") > head.rfind(";")
        if not unclosed_tag and not unclosed_entity:
            break
        cut -= 1
    cut = cut or limit
    return line[:cut], line[cut:].lstrip()


def _why(item: Item) -> str:
    shown = [r for r in item.reasons if not r.startswith("source weight")]
    return " · ".join(shown) if shown else "—"


def format_alert(item: Item, tz_name: str) -> str:
    icon = "🔁" if item.is_update else "🔴"
    label = "Update: " if item.is_update else ""
    lines = [
        f"{icon} <b>[{item.score}/10] {label}{esc(item.title)}</b>",
        f"{esc(item.source)} · {esc(format_local(item.published or item.first_seen, tz_name))}",
        f"Why: {esc(_why(item))}",
    ]
    if item.cve_ids:
        lines.append(esc(", ".join(item.cve_ids[:5])))
    lines.append(esc(item.url))
    return "\n".join(lines)


def format_bundle(items: list[Item]) -> str:
    noun = "alert" if len(items) == 1 else "alerts"
    lines = [f"🟠 <b>{len(items)} more {noun} this run</b>"]
    for item in items:
        lines.append(f'• [{item.score}/10] <a href="{esc(item.url)}">{esc(item.title)}</a>')
    return "\n".join(lines)


def format_digest_line(item: Item) -> str:
    why = _why(item)
    return f'• <b>[{item.score}]</b> <a href="{esc(item.url)}">{esc(item.title)}</a>\n  <i>{esc(item.source)} · {esc(why)}</i>'


def build_digest(items: list[Item], max_per_category: int, now_text: str) -> list[tuple[str, list[str]]]:
    """Build (message, ids in that message) pairs. Ids are tracked per message so a
    failure part-way through re-sends only what did not go out."""
    messages: list[tuple[str, list[str]]] = []
    header = f"📰 <b>Daily digest</b> · {esc(now_text)}"
    current, current_ids = header, []
    overflow_ids: list[str] = []

    def add(block: str, ids: list[str]) -> None:
        nonlocal current, current_ids
        if len(current) + len(block) + 2 > TELEGRAM_LIMIT:
            messages.append((current, current_ids))
            current, current_ids = block, []
        else:
            current = f"{current}\n\n{block}"
        current_ids.extend(ids)

    for category, title in CATEGORY_TITLES:
        group = [i for i in items if i.category == category]
        group.sort(key=lambda i: i.published or "", reverse=True)  # newest first within a score
        group.sort(key=lambda i: -i.score)
        if not group:
            continue
        shown, hidden = group[:max_per_category], group[max_per_category:]
        add(f"<b>{title}</b> ({len(group)})", [])
        for item in shown:
            add(format_digest_line(item), [item.id])
        if hidden:
            add(f"<i>…and {len(hidden)} lower-scored items not shown</i>", [])
            overflow_ids.extend(i.id for i in hidden)
    if current_ids or current != header:
        current_ids.extend(overflow_ids)
        messages.append((current, current_ids))
    return messages


def deliver_alerts(pending: list[dict], sender, cfg: dict, now: datetime) -> list[dict]:
    """Send alerts and return those that could not be sent, to retry next run."""
    settings = cfg["settings"]
    tz = settings["timezone"]
    quiet = settings["quiet_hours"]
    is_quiet = quiet.get("enabled", True) and in_quiet_hours(now, quiet["start"], quiet["end"], tz)
    always_ring = quiet["always_ring_score"]
    max_loud = settings["max_alerts_per_run"]

    items = sorted((Item.from_dict(p) for p in pending), key=lambda i: -i.score)
    top, rest = items[:max_loud], items[max_loud:]
    unsent = {i.id: i for i in items}
    try:
        for item in top:
            silent = item.silent_update or (is_quiet and item.score < always_ring)
            try:
                for part in split_message(format_alert(item, tz)):
                    sender.send(part, silent=silent)
            except TelegramRejected as exc:
                # Retrying would block every later alert forever, so skip this one.
                log.error("Telegram rejected the alert for %s: %s", item.id, exc)
            del unsent[item.id]
        if rest:
            ring = any(i.score >= always_ring for i in rest)
            for n, part in enumerate(split_message(format_bundle(rest))):
                sender.send(part, silent=not (ring and n == 0))
            for item in rest:
                del unsent[item.id]
    except TelegramError as exc:
        log.error("Alert delivery stopped: %s; %d kept for retry", exc, len(unsent))
    remaining = set(unsent)
    return [p for p in pending if p.get("id") in remaining]


def deliver_digest(queue: list[dict], sender, cfg: dict, now: datetime) -> list[dict]:
    """Send the digest and return the queue entries that were not delivered."""
    settings = cfg["settings"]
    items = [Item.from_dict(q) for q in queue]
    now_text = format_local(now.isoformat(), settings["timezone"])
    remaining = {i.id for i in items}
    try:
        for text, ids in build_digest(items, settings["digest_max_per_category"], now_text):
            try:
                sender.send(text, silent=True)
            except TelegramRejected as exc:
                log.error("Telegram rejected a digest message: %s", exc)
            remaining -= set(ids)
    except TelegramError as exc:
        log.error("Digest delivery stopped: %s; %d kept for tomorrow", exc, len(remaining))
    return [q for q in queue if q.get("id") in remaining]

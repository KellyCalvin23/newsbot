"""Command line. The same commands work locally, on GitHub Actions, and on a VPS."""
from __future__ import annotations

import argparse
import logging
from datetime import date

from .config import ConfigError, load_config
from .http import FetchError
from .pipeline import EXIT_FAILED, EXIT_OK, make_client, run_alerts, run_digest
from .security import setup_logging
from .storage import JsonStorage, MemoryStorage, State, StateError
from .suggest import count_candidates, format_candidates
from .telegram import DryRunSender, TelegramClient, TelegramError
from .timeutil import utcnow
from .watchlist import build_matchers

log = logging.getLogger("newsbot")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="newsbot", description=__doc__)
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument("--verbose", action="store_true", help="debug logging (secrets stay redacted)")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the alert pipeline or send the digest")
    run.add_argument("--mode", choices=("alerts", "digest"), required=True)
    run.add_argument("--dry-run", action="store_true", help="print messages; send nothing, save no state")
    run.add_argument("--state-dir", default="state", help="where state files live")
    run.add_argument("--source", help="only use this source (by name), for testing")

    sub.add_parser("suggest-watchlist", help="list frequently exploited vendors not on the watchlist")
    sub.add_parser("test-telegram", help="send one test message")
    return parser


def cmd_run(args, cfg) -> int:
    disk = JsonStorage(args.state_dir)
    if args.dry_run:
        # Reads real state, writes only to memory, so a dry run cannot lose anything.
        storage = MemoryStorage({
            name: disk.load(name, default)
            for name, default in (("seen", {}), ("digest_queue", []), ("pending_alerts", []))
        })
        sender = DryRunSender()
    else:
        storage = disk
        sender = TelegramClient.from_env()
    state = State(storage)
    now = utcnow()
    if args.mode == "digest":
        return run_digest(cfg, state, sender, now)
    return run_alerts(cfg, state, make_client(cfg), sender, now, only_source=args.source)


def cmd_suggest(cfg) -> int:
    url = next(s["url"] for s in cfg["sources"] if s["type"] == "cisa_kev")
    client = make_client(cfg)
    data = client.get_json(url)
    rows = count_candidates(data["vulnerabilities"], build_matchers(cfg), date.today())
    print(format_candidates(rows))
    return EXIT_OK


def cmd_test_telegram() -> int:
    TelegramClient.from_env().send("✅ newsbot test message: Telegram delivery works.")
    print("Test message sent.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    try:
        cfg = load_config(args.config)
        if args.command == "run":
            return cmd_run(args, cfg)
        if args.command == "suggest-watchlist":
            return cmd_suggest(cfg)
        return cmd_test_telegram()
    except (ConfigError, StateError, TelegramError, FetchError) as exc:
        log.error("%s", exc)
        return EXIT_FAILED

"""Run the stages in order. GitHub Actions, cron and systemd all end up here."""
from __future__ import annotations

import logging
import time
from datetime import datetime

from .config import active_sources
from .dedup import ingest, prune
from .deliver import deliver_alerts, deliver_digest
from .enrich import enrich_cvss, enrich_epss
from .fetch import FetchResult, fetch_all
from .http import HttpClient
from .models import Item
from .normalize import normalize_entries
from .route import route_story
from .score import score_item
from .storage import State
from .telegram import TelegramError
from .watchlist import build_matchers, classify

log = logging.getLogger(__name__)

EXIT_OK, EXIT_FAILED = 0, 1


def make_client(cfg: dict) -> HttpClient:
    s = cfg["settings"]
    return HttpClient(
        timeout=s["http_timeout_seconds"],
        retries=s["http_retries"],
        backoff=s["http_backoff_seconds"],
        max_bytes=s["max_response_bytes"],
        deadline=time.monotonic() + s["run_budget_seconds"],
    )


def _source_url(cfg: dict, source_type: str) -> str | None:
    src = next((s for s in cfg["sources"] if s["type"] == source_type and s.get("enabled", True)), None)
    return src["url"] if src else None


def normalize_results(results: list[FetchResult], state: State, cfg: dict, now: datetime, matchers) -> tuple[list[Item], list[Item]]:
    """Split fetched items into (seed, live). Seed items are remembered but never
    delivered. That covers the first run, plus any source that is newly enabled or
    that failed during the first run, whose whole backlog would otherwise alert."""
    seed: list[Item] = []
    live: list[Item] = []
    max_age = cfg["settings"]["max_item_age_days"]
    # CISA first, so the VulnCheck check below sees this run's additions.
    for result in sorted(results, key=lambda r: 0 if r.source["type"] == "cisa_kev" else 1):
        if not result.ok:
            continue
        src = result.source
        first_time = src["name"] not in state.seeded_sources
        items = normalize_entries(result.entries, src, now, max_age)
        if src["type"] == "cisa_kev":
            fresh = [i for i in items if i.id not in state.kev_known]
            state.kev_known.update(i.id for i in items)
            items = [] if first_time else fresh
        elif src["type"] == "vulncheck_kev":
            items = [i for i in items if i.id not in state.kev_known]
        for item in items:
            classify(item, matchers)
        (seed if first_time else live).extend(items)
        state.seeded_sources.add(src["name"])
        if "nvd_cursor" in result.meta:
            state.meta["nvd_cursor"] = result.meta["nvd_cursor"]
    return seed, live


def process_live(items: list[Item], state: State, client: HttpClient, cfg: dict, now: datetime) -> dict[str, int]:
    counts = {"alert": 0, "digest": 0, "drop": 0, "unchanged": 0}
    changed = ingest(items, state, cfg, now)
    stories = list(changed.values())
    epss_url = cfg["settings"]["epss_url"]
    # Enrich only what could still matter; this keeps API use proportional to real news.
    enrich_epss([s for s in stories if s.cve_ids], client, epss_url)
    enrich_cvss(stories, state.stories, client, _source_url(cfg, "nvd"), cfg["settings"]["nvd_lookups_per_run"])
    for story in sorted(stories, key=lambda s: 0 if s.source_type == "nvd" else 1):
        story.score, story.reasons = score_item(story, cfg)
        outcome = route_story(story, state, cfg)
        counts[outcome] = counts.get(outcome, 0) + 1
        # NVD publishes ~700 CVEs a day, mostly dropped. Keeping those would bloat the
        # state; if NVD later adds a score, the CVE simply comes back for re-scoring.
        if outcome == "drop" and story.source_type == "nvd" and story.coverage_count == 1:
            state.stories.pop(story.id, None)
        else:
            state.stories[story.id] = story.to_dict()
    return counts


def run_alerts(cfg: dict, state: State, client: HttpClient, sender, now: datetime, only_source: str | None = None) -> int:
    sources = active_sources(cfg)
    if only_source:
        sources = [s for s in sources if s["name"] == only_source]
        if not sources:
            log.error("No active source named %r", only_source)
            return EXIT_FAILED
    was_empty = state.is_empty
    ctx = {
        "now": now,
        "nvd_cursor": state.meta.get("nvd_cursor"),
        "max_item_age_days": cfg["settings"]["max_item_age_days"],
    }
    results = fetch_all(sources, client, ctx, budget=cfg["settings"]["fetch_budget_seconds"])
    ok = sum(r.ok for r in results)
    log.info("Fetched %d/%d sources successfully", ok, len(results))
    if was_empty and ok == 0:
        log.error("Every source failed on the first run; not initializing")
        return EXIT_FAILED

    matchers = build_matchers(cfg)
    seed, live = normalize_results(results, state, cfg, now, matchers)

    if seed:
        for fp, story in ingest(seed, state, cfg, now).items():
            if story.route == "new":
                story.route = "seed"
                state.stories[fp] = story.to_dict()
        log.info("Seeded %d items silently", len(seed))
    if live:
        counts = process_live(live, state, client, cfg, now)
        log.info("Routed: %s", counts)

    failed = False
    if was_empty:
        state.meta["init_pending"] = True
    if state.meta.get("init_pending"):
        try:
            sender.send(f"✅ Bot initialized, monitoring {len(sources)} sources.", silent=False)
            state.meta.pop("init_pending")
        except TelegramError as exc:
            log.error("Could not send the init message: %s", exc)
            failed = True

    if state.pending_alerts:
        state.pending_alerts = deliver_alerts(state.pending_alerts, sender, cfg, now)
        failed = failed or bool(state.pending_alerts)

    prune(state, cfg, now)
    # Bound the queue so a broken digest can never grow state without limit.
    limit = cfg["settings"]["digest_queue_max"]
    if len(state.digest_queue) > limit:
        state.digest_queue = sorted(state.digest_queue, key=lambda q: -q.get("score", 0))[:limit]
    state.save()
    return EXIT_FAILED if failed else EXIT_OK


def run_digest(cfg: dict, state: State, sender, now: datetime) -> int:
    if not state.digest_queue:
        log.info("Digest queue is empty; nothing to send")
        return EXIT_OK
    before = len(state.digest_queue)
    state.digest_queue = deliver_digest(state.digest_queue, sender, cfg, now)
    log.info("Digest: delivered %d of %d", before - len(state.digest_queue), before)
    state.save()
    return EXIT_FAILED if state.digest_queue else EXIT_OK

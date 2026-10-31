"""Stage 5, route: decide what happens to a scored story.

Routes only move forward (drop -> digest -> alert), so more coverage can promote a
story but nothing is ever delivered twice at the same level.
"""
from __future__ import annotations

from .models import ROUTE_RANK, Item

_KEV_TAGS = ("cisa_kev", "vulncheck_kev")


def alerted_cves(stories: dict[str, dict], exclude: str = "") -> set[str]:
    found: set[str] = set()
    for fp, story in stories.items():
        if story.get("alerted") and fp != exclude:
            found.update(story.get("cve_ids") or [])
    return found


def route_story(story: Item, state, cfg: dict) -> str:
    """Set the story's route and update the queues. Returns what happened."""
    settings = cfg["settings"]
    alert_min, digest_min = settings["alert_threshold"], settings["digest_threshold"]
    new_kev_tags = [t for t in _KEV_TAGS if t in story.tags and t not in story.alerted_tags]

    if story.alerted:
        # Already alerted, and news coverage never rings twice. Being newly confirmed as
        # exploited is different: that is one update, silent if a KEV alert already went out.
        if not new_kev_tags:
            return "unchanged"
        story.is_update = True
        story.silent_update = bool(story.alerted_tags)
        _queue_alert(story, state)
        return "alert"

    wants_alert = story.score >= alert_min
    if wants_alert and not new_kev_tags and set(story.cve_ids) & alerted_cves(state.stories, story.id):
        wants_alert = False  # another story already alerted on this CVE

    if wants_alert:
        state.digest_queue = [q for q in state.digest_queue if q.get("id") != story.id]
        _queue_alert(story, state)
        return "alert"

    if story.score >= digest_min:
        queued = next((q for q in state.digest_queue if q.get("id") == story.id), None)
        if queued is not None:
            state.digest_queue[state.digest_queue.index(queued)] = story.to_dict()
            return "digest"
        if ROUTE_RANK.get(story.route, 0) < ROUTE_RANK["digest"]:
            story.route = "digest"
            state.digest_queue.append(story.to_dict())
            return "digest"
        return "unchanged"

    if ROUTE_RANK.get(story.route, 0) < ROUTE_RANK["drop"]:
        story.route = "drop"
    return "drop"


def _queue_alert(story: Item, state) -> None:
    story.route = "alert"
    story.alerted = True
    story.alerted_tags = sorted(set(story.alerted_tags) | {t for t in _KEV_TAGS if t in story.tags})
    state.pending_alerts = [p for p in state.pending_alerts if p.get("id") != story.id]
    state.pending_alerts.append(story.to_dict())

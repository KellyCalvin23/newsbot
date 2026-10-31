"""Stage 3, dedup: merge incoming items into known stories and record coverage.

A story is identified by, in order:
  1. exact fingerprint (CVE ID, or hash of the canonical URL)
  2. a shared CVE (an article about a CVE joins that CVE's story)
  3. a similar title within the fuzzy window
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from rapidfuzz import fuzz

from .models import Item
from .normalize import VULN_SOURCE_TYPES
from .timeutil import parse_iso, to_iso

_CVE_FP = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Articles naming many CVEs are roundups, not reports about any one of them.
MAX_CVES_FOR_CVE_MERGE = 3
# token_set_ratio scores 100 whenever one title's words are a subset of the other's, so
# a short title such as "Ransomware attack" would match every story containing it.
MIN_TOKENS_FOR_FUZZY = 5


def titles_match(a: str, b: str, threshold: float) -> bool:
    a, b = a.lower(), b.lower()
    if min(len(a.split()), len(b.split())) < MIN_TOKENS_FOR_FUZZY:
        return False
    return fuzz.token_set_ratio(a, b) >= threshold


def _is_cve_story(fp: str) -> bool:
    return bool(_CVE_FP.match(fp))


def find_story(item: Item, stories: dict[str, dict], now: datetime, window_hours: float, threshold: float) -> str | None:
    if item.id in stories:
        return item.id
    is_vuln_record = _is_cve_story(item.id)
    cutoff = now - timedelta(hours=window_hours)

    def recent(story: dict) -> bool:
        seen = parse_iso(story.get("first_seen"))
        return seen is not None and seen >= cutoff

    if not is_vuln_record and 0 < len(item.cve_ids) <= MAX_CVES_FOR_CVE_MERGE:
        for cve in item.cve_ids:
            if cve in stories:
                return cve
        wanted = set(item.cve_ids)
        for fp, story in stories.items():
            cves = story.get("cve_ids") or []
            if len(cves) <= MAX_CVES_FOR_CVE_MERGE and wanted & set(cves) and recent(story):
                return fp

    if is_vuln_record:
        return None  # CVE records are told apart by ID, however alike their titles are

    for fp, story in stories.items():
        if _is_cve_story(fp) or not story.get("title") or not recent(story):
            continue
        # A feed's own items look alike ("October Security Update"), and one outlet
        # repeating itself is not independent coverage.
        if item.source in (story.get("sources") or []):
            continue
        cves_a, cves_b = set(item.cve_ids), set(story.get("cve_ids") or [])
        if cves_a and cves_b and not cves_a & cves_b:
            continue  # same template, different vulnerabilities
        if titles_match(item.title, story["title"], threshold):
            return fp
    return None


def merge_into(story: Item, item: Item) -> bool:
    """Fold `item` into `story`. Returns True if anything affecting the score changed."""
    before = (
        story.coverage_count, story.cvss, story.epss, sorted(story.tags), sorted(story.cve_ids),
        [m["tier"] for m in story.vendor_matches], bool(story.keyword_hits),
        bool(story.topic_hits), bool(story.big_story_hits),
    )
    story.sources = sorted(set(story.sources) | set(item.sources))
    story.coverage_count = max(len(story.sources), 1)
    if item.cvss is not None:
        story.cvss = max(item.cvss, story.cvss or 0)
    if item.epss is not None:
        story.epss = max(item.epss, story.epss or 0)
    story.tags = sorted(set(story.tags) | set(item.tags))
    story.cve_ids = list(dict.fromkeys(story.cve_ids + item.cve_ids))[:20]
    story.keyword_hits = list(dict.fromkeys(story.keyword_hits + item.keyword_hits))
    story.topic_hits = list(dict.fromkeys(story.topic_hits + item.topic_hits))
    story.big_story_hits = list(dict.fromkeys(story.big_story_hits + item.big_story_hits))
    if item.vendor_matches:
        new_tier = item.vendor_matches[0]["tier"]
        old_tier = story.vendor_matches[0]["tier"] if story.vendor_matches else 99
        # An article can mention other vendors in passing, so it never relabels a CVE
        # record that already knows which product it belongs to.
        locked = _is_cve_story(story.id) and story.vendor_matches and not _is_cve_story(item.id)
        if new_tier < old_tier and not locked:
            story.vendor_matches = item.vendor_matches
    story.weight = max(story.weight, item.weight)
    # Old stories have their text compacted away, so take it from whichever copy has it.
    for attr in ("title", "url", "summary", "published"):
        if not getattr(story, attr) and getattr(item, attr):
            setattr(story, attr, getattr(item, attr))
    after = (
        story.coverage_count, story.cvss, story.epss, sorted(story.tags), sorted(story.cve_ids),
        [m["tier"] for m in story.vendor_matches], bool(story.keyword_hits),
        bool(story.topic_hits), bool(story.big_story_hits),
    )
    return before != after


def ingest(items: list[Item], state, cfg: dict, now: datetime) -> dict[str, Item]:
    """Merge items into state. Returns the new or changed stories that need scoring."""
    settings = cfg["settings"]
    window = settings["fuzzy_window_hours"]
    threshold = settings["fuzzy_threshold"]
    today = now.strftime("%Y-%m-%d")
    changed: dict[str, Item] = {}
    # Authoritative records go first so that news can attach to the CVE story.
    ordered = sorted(items, key=lambda i: 0 if i.source_type in VULN_SOURCE_TYPES else 1 if _is_cve_story(i.id) else 2)
    for item in ordered:
        fp = find_story(item, state.stories, now, window, threshold)
        if fp is None:
            item.first_seen = to_iso(now)
            item.last_seen = today
            state.stories[item.id] = item.to_dict()
            changed[item.id] = item
            continue
        story = changed.get(fp) or Item.from_dict(state.stories[fp])
        story.id = fp
        story.last_seen = today
        if merge_into(story, item):
            changed[fp] = story
        state.stories[fp] = story.to_dict()
    return changed


def prune(state, cfg: dict, now: datetime) -> None:
    """Forget stories unseen for the retention period, and drop the text of older ones."""
    settings = cfg["settings"]
    retention_cutoff = (now - timedelta(days=settings["retention_days"])).strftime("%Y-%m-%d")
    compact_cutoff = now - timedelta(hours=settings["fuzzy_window_hours"] + 24)
    for fp in list(state.stories):
        story = state.stories[fp]
        # Measured from last sighting, so an item still in its feed stays known.
        if (story.get("last_seen") or "") < retention_cutoff:
            del state.stories[fp]
            continue
        story.pop("summary", None)
        first = parse_iso(story.get("first_seen"))
        if first is not None and first < compact_cutoff:
            for key in ("title", "url", "reasons", "published"):
                story.pop(key, None)

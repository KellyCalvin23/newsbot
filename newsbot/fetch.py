"""Stage 1, fetch: pull raw entries from every enabled source.

Each adapter returns plain dicts for normalize.py. One failing source is logged and
skipped, and never affects the others.
"""
from __future__ import annotations

import calendar
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import feedparser

from .http import FetchError, HttpClient
from .normalize import truncate
from .timeutil import parse_iso, to_iso

log = logging.getLogger(__name__)


@dataclass
class FetchResult:
    source: dict
    ok: bool = True
    entries: list[dict] = field(default_factory=list)
    error: str = ""
    meta: dict = field(default_factory=dict)


def _struct_to_iso(value: Any) -> str | None:
    if not value:
        return None
    try:
        return to_iso(datetime.fromtimestamp(calendar.timegm(value), timezone.utc))
    except (TypeError, ValueError, OverflowError):
        return None


def fetch_rss(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    # Parse bytes that we fetched ourselves. Handing feedparser a URL or a path would
    # bypass the timeout, the size cap and the scheme check.
    body = client.get(src["url"], max_bytes=src.get("max_bytes"))
    parsed = feedparser.parse(body)
    if not parsed.entries and parsed.get("bozo"):
        raise FetchError(f"{src['name']}: not a parseable feed")
    entries = []
    for e in parsed.entries:
        summary = e.get("summary") or ""
        if not summary and e.get("content"):
            summary = e["content"][0].get("value", "")
        entries.append({
            "title": e.get("title", ""),
            "url": e.get("link", ""),
            "published": _struct_to_iso(e.get("published_parsed") or e.get("updated_parsed")),
            "summary": summary,
        })
    return FetchResult(src, entries=entries)


def fetch_cisa_kev(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    data = client.get_json(src["url"], max_bytes=src.get("max_bytes"))
    entries = []
    for v in data["vulnerabilities"]:
        cve = v.get("cveID", "")
        tags = ["cisa_kev"]
        if v.get("knownRansomwareCampaignUse") == "Known":
            tags.append("ransomware_known")
        entries.append({
            "title": f"{cve}: {v.get('vulnerabilityName') or v.get('product', '')}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "published": (v.get("dateAdded") or "") + "T00:00:00Z" if v.get("dateAdded") else None,
            "summary": f"{v.get('vendorProject', '')} {v.get('product', '')}. {v.get('shortDescription', '')}",
            "cve_ids": [cve],
            "tags": tags,
        })
    return FetchResult(src, entries=entries)


def fetch_vulncheck_kev(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    token = os.environ.get(src.get("requires_secret", "VULNCHECK_API_TOKEN"), "")
    data = client.get_json(
        src["url"],
        params={"limit": src.get("limit", 100), "sort": "date_added", "order": "desc"},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        secret_headers=True,
    )
    entries = []
    for v in data.get("data", []):
        cves = v.get("cve") or []
        cves = [cves] if isinstance(cves, str) else cves
        if not cves:
            continue
        tags = ["vulncheck_kev"]
        if v.get("knownRansomwareCampaignUse") == "Known":
            tags.append("ransomware_known")
        entries.append({
            "title": f"{cves[0]}: {v.get('name') or v.get('vulnerabilityName') or v.get('product', '')}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cves[0]}",
            "published": v.get("date_added"),
            "summary": f"{v.get('vendorProject', '')} {v.get('product', '')}. {v.get('shortDescription', '')}",
            "cve_ids": cves[:1],
            "tags": tags,
        })
    return FetchResult(src, entries=entries)


def nvd_headers() -> dict:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def nvd_cvss(cve: dict) -> float | None:
    """Highest v4.0/v3.1/v3.0 score. NVD often has only the CNA's score at first."""
    metrics = cve.get("metrics") or {}
    scores = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                scores.append(float(score))
    return max(scores) if scores else None


def nvd_entry(cve: dict) -> dict:
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cve_id = cve.get("id", "")
    first_sentence = truncate(desc.split(". ")[0], 140)
    return {
        "title": f"{cve_id}: {first_sentence}",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "published": to_iso(parse_iso(cve["published"])) if parse_iso(cve.get("published")) else None,
        "summary": desc,
        "cve_ids": [cve_id],
        "cvss": nvd_cvss(cve),
    }


NVD_TIME = "%Y-%m-%dT%H:%M:%S.000Z"


def fetch_nvd(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    now: datetime = ctx["now"]
    cursor = parse_iso(ctx.get("nvd_cursor"))
    if cursor is None:
        # First run: start watching from now, without downloading any history.
        return FetchResult(src, meta={"nvd_cursor": to_iso(now)})
    max_age = timedelta(days=ctx.get("max_item_age_days", 14))
    # A small overlap protects against clock skew; dedup absorbs any repeats.
    start = max(cursor - timedelta(minutes=10), now - max_age)
    # NVD modifies ~3,000 CVEs a day. After an outage, catch up one day per run instead
    # of re-requesting a window too large to ever finish.
    end = min(now, start + timedelta(days=1))
    oldest_published = now - max_age
    pause = 0.7 if os.environ.get("NVD_API_KEY") else 6.5  # public limit: 5 requests/30 s
    page_size = src.get("page_size", 2000)
    index = total = pages = 0
    entries: list[dict] = []
    while True:
        if pages:
            client.sleep(pause)
        data = client.get_json(
            src["url"],
            params={
                "lastModStartDate": start.strftime(NVD_TIME),
                "lastModEndDate": end.strftime(NVD_TIME),
                "resultsPerPage": page_size,
                "startIndex": index,
            },
            headers=nvd_headers(),
            secret_headers=True,
            retry_status={403},  # NVD signals rate limiting with 403
            timeout=src.get("timeout", 45),
        )
        total = data.get("totalResults", 0)
        for wrapper in data.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            if cve.get("vulnStatus") == "Rejected":
                continue
            published = parse_iso(cve.get("published"))
            # Old CVEs get modified constantly; a metadata edit is not news.
            if published and published >= oldest_published:
                entries.append(nvd_entry(cve))
        index += page_size
        pages += 1
        if index >= total or pages >= src.get("max_pages", 4):
            break
    if index < total:
        # Not everything was read, so keep the old cursor and resume next run.
        log.warning("NVD: read %d of %d results; will continue next run", index, total)
        return FetchResult(src, entries=entries, meta={})
    return FetchResult(src, entries=entries, meta={"nvd_cursor": to_iso(end)})


def nvd_lookup_cvss(url: str, cve_id: str, client: HttpClient) -> float | None:
    data = client.get_json(
        url, params={"cveId": cve_id}, headers=nvd_headers(),
        secret_headers=True, retry_status={403}, timeout=30,
    )
    for wrapper in data.get("vulnerabilities", []):
        return nvd_cvss(wrapper.get("cve", {}))
    return None


def fetch_hn(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    base = src["url"].rsplit("/", 1)[0]
    ids = client.get_json(src["url"])[: src.get("top_n", 30)]
    min_score = src.get("min_score", 300)

    def one(item_id: int) -> dict | None:
        try:
            return client.get_json(f"{base}/item/{int(item_id)}.json")
        except FetchError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        stories = list(pool.map(one, ids))
    entries = []
    for s in stories:
        if not s or s.get("dead") or s.get("deleted") or s.get("score", 0) < min_score:
            continue
        entries.append({
            "title": s.get("title", ""),
            "url": s.get("url") or f"https://news.ycombinator.com/item?id={s.get('id')}",
            "published": to_iso(datetime.fromtimestamp(s["time"], timezone.utc)) if s.get("time") else None,
            "summary": "",
            "tags": ["hn"],
        })
    return FetchResult(src, entries=entries)


ADAPTERS: dict[str, Callable[[dict, HttpClient, dict], FetchResult]] = {
    "rss": fetch_rss,
    "cisa_kev": fetch_cisa_kev,
    "vulncheck_kev": fetch_vulncheck_kev,
    "nvd": fetch_nvd,
    "hn": fetch_hn,
}


def fetch_source(src: dict, client: HttpClient, ctx: dict) -> FetchResult:
    started = time.monotonic()
    try:
        result = ADAPTERS[src["type"]](src, client, ctx)
        log.info("%s: %d entries in %.1fs", src["name"], len(result.entries), time.monotonic() - started)
        return result
    except FetchError as exc:
        error = str(exc)
    except (KeyError, TypeError, ValueError, AttributeError, json.JSONDecodeError) as exc:
        # Feeds are untrusted and may change shape. The text could echo payload data,
        # so log only the exception type.
        error = f"unexpected response shape ({type(exc).__name__})"
    log.warning("%s: FAILED: %s", src["name"], error)
    return FetchResult(src, ok=False, error=error)


def fetch_all(sources: list[dict], client: HttpClient, ctx: dict, budget: float = 150) -> list[FetchResult]:
    """Fetch concurrently. A source still running when the budget ends counts as failed."""
    pool = ThreadPoolExecutor(max_workers=8)
    futures = {src["name"]: pool.submit(fetch_source, src, client, ctx) for src in sources}
    wait(futures.values(), timeout=budget)
    results = []
    for src in sources:
        fut = futures[src["name"]]
        if fut.done() and not fut.cancelled():
            results.append(fut.result())
        else:
            log.warning("%s: FAILED: exceeded the %ss fetch budget", src["name"], budget)
            results.append(FetchResult(src, ok=False, error="fetch budget exceeded"))
    pool.shutdown(wait=False, cancel_futures=True)
    return results

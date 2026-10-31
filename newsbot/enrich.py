"""Add EPSS and CVSS to stories that are about to be scored."""
from __future__ import annotations

import logging
import os

from .fetch import nvd_lookup_cvss
from .http import FetchError, HttpClient
from .models import Item

log = logging.getLogger(__name__)

EPSS_BATCH = 90  # the API allows about 100 IDs per request


def enrich_epss(items: list[Item], client: HttpClient, url: str) -> None:
    cves = sorted({c for i in items for c in i.cve_ids})
    scores: dict[str, float] = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start:start + EPSS_BATCH]
        try:
            data = client.get_json(url, params={"cve": ",".join(batch)})
        except FetchError as exc:
            # A vulnerability still scores without EPSS, so this must not stop the run.
            log.warning("EPSS lookup failed: %s", exc)
            return
        for row in data.get("data", []):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    for item in items:
        values = [scores[c] for c in item.cve_ids if c in scores]
        if values:
            item.epss = max([*values, item.epss or 0])


def enrich_cvss(items: list[Item], stories: dict[str, dict], client: HttpClient, url: str | None, limit: int) -> None:
    """Fill in missing CVSS, first from state, then from a few direct NVD lookups."""
    missing: list[Item] = []
    for item in items:
        if item.cvss is not None or not item.cve_ids:
            continue
        known = [stories[c]["cvss"] for c in item.cve_ids if stories.get(c, {}).get("cvss") is not None]
        if known:
            item.cvss = max(known)
        else:
            missing.append(item)
    if not url:
        return
    # KEV entries first: their score decides whether the phone rings.
    missing.sort(key=lambda i: 0 if {"cisa_kev", "vulncheck_kev"} & set(i.tags) else 1)
    for n, item in enumerate(missing[:limit]):
        if n:
            client.sleep(0.7 if os.environ.get("NVD_API_KEY") else 6.5)
        try:
            item.cvss = nvd_lookup_cvss(url, item.cve_ids[0], client)
        except FetchError as exc:
            log.warning("NVD CVSS lookup failed: %s", exc)
            return

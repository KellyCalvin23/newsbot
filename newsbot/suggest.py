"""`suggest-watchlist`: find KEV vendors being exploited that we do not watch.

It only prints suggestions and never edits config.yaml.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta

from .watchlist import Matchers, is_watched_vendor

MIN_ADDITIONS = 2


def count_candidates(entries: list[dict], matchers: Matchers, today: date, months: int = 12, min_additions: int = MIN_ADDITIONS) -> list[dict]:
    cutoff = today - timedelta(days=round(months * 30.44))
    stats: dict[str, dict] = defaultdict(lambda: {"count": 0, "ransomware": 0, "products": Counter()})
    for e in entries:
        try:
            added = date.fromisoformat(e.get("dateAdded", ""))
        except ValueError:
            continue
        vendor, product = e.get("vendorProject", "").strip(), e.get("product", "").strip()
        if added < cutoff or not vendor or is_watched_vendor(vendor, product, matchers):
            continue
        row = stats[vendor]
        row["count"] += 1
        row["products"][product] += 1
        if e.get("knownRansomwareCampaignUse") == "Known":
            row["ransomware"] += 1
    rows = [
        {"vendor": v, "count": s["count"], "ransomware": s["ransomware"], "products": s["products"].most_common(4)}
        for v, s in stats.items() if s["count"] >= min_additions
    ]
    return sorted(rows, key=lambda r: (-r["count"], -r["ransomware"], r["vendor"]))


def format_candidates(rows: list[dict]) -> str:
    if not rows:
        return "No unwatched vendor has 2 or more KEV additions in the last 12 months."
    lines = [f"{'KEV':>4} {'Ransom':>6}  Vendor: top products", "-" * 60]
    for r in rows:
        products = ", ".join(f"{p} ({n})" for p, n in r["products"])
        lines.append(f"{r['count']:>4} {r['ransomware']:>6}  {r['vendor']}: {products}")
    lines.append("\nSuggestions only. Edit the watchlist in config.yaml if you agree.")
    return "\n".join(lines)

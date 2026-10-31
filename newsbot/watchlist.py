"""Compile the watchlist and keyword lists from config and match them against text."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_TIERS = (("tier1", 1), ("tier2", 2), ("tier3", 3))


def term_pattern(term: str) -> str:
    """Whole-term regex. Boundaries are added only where the term begins or ends with
    an alphanumeric, so "% off" matches in "50% off" and "FortiOS" matches "FortiOS-based"."""
    body = r"\s+".join(re.escape(part) for part in term.split())
    prefix = r"(?<![A-Za-z0-9])" if term[0].isalnum() else ""
    suffix = r"(?![A-Za-z0-9])" if term[-1].isalnum() else ""
    return f"{prefix}{body}{suffix}"


def compile_terms(terms: list[str], flags: int = re.IGNORECASE) -> list[tuple[str, re.Pattern]]:
    return [(t, re.compile(term_pattern(t), flags)) for t in terms]


@dataclass
class VendorEntry:
    vendor: str
    tier: int
    points: int
    vendor_terms: list[tuple[str, re.Pattern]]
    product_terms: list[tuple[str, re.Pattern]]
    vendor_context_terms: list[tuple[str, re.Pattern]]
    platform_terms: list[tuple[str, re.Pattern]] = field(default_factory=list)

    def match(self, text: str, cve_record: bool = False) -> str | None:
        """Return the product that matched, or the vendor's name, or None."""
        for term, rx in self.product_terms:
            if rx.search(text):
                return term
        # A CVE record for third-party software often names its platform ("installer
        # for Windows"). That is not a Microsoft bug. In news, "Windows zero-day" is.
        if not cve_record:
            for term, rx in self.platform_terms:
                if rx.search(text):
                    return term
        if not any(rx.search(text) for _, rx in self.vendor_terms):
            return None
        # "Office" or "Safari" alone are ordinary words; with the vendor they are products.
        for term, rx in (*self.vendor_context_terms, *self.platform_terms):
            if rx.search(text):
                return term
        return self.vendor


@dataclass
class Matchers:
    entries: list[VendorEntry] = field(default_factory=list)
    keywords: list[tuple[str, re.Pattern]] = field(default_factory=list)
    extra: list[tuple[str, re.Pattern]] = field(default_factory=list)
    regional: list[tuple[str, re.Pattern]] = field(default_factory=list)
    big_story: list[tuple[str, re.Pattern]] = field(default_factory=list)
    muted: list[tuple[str, re.Pattern]] = field(default_factory=list)
    watch_categories: set[str] = field(default_factory=set)
    big_story_categories: set[str] = field(default_factory=set)


def _muted_pattern(term: str) -> re.Pattern:
    # "state-sponsored hackers" is exactly what this bot exists for, so the mute term
    # must not fire after a hyphen, nor after "state " or "government ".
    guard = r"(?<![\w-])(?<!state )(?<!government )" if term[0].isalnum() else ""
    return re.compile(guard + term_pattern(term), re.IGNORECASE)


def build_matchers(cfg: dict) -> Matchers:
    wl, kw = cfg["watchlist"], cfg["keywords"]
    weights = cfg["scoring"]["watchlist_points"]
    entries = []
    for tier_key, tier_num in _TIERS:
        for raw in wl.get(tier_key) or []:
            entries.append(VendorEntry(
                vendor=raw["vendor"],
                tier=tier_num,
                points=weights[tier_key],
                vendor_terms=compile_terms([raw["vendor"], *raw.get("aliases", [])]),
                product_terms=compile_terms(raw.get("products", [])),
                vendor_context_terms=compile_terms(raw.get("products_need_vendor", [])),
                platform_terms=compile_terms(raw.get("platforms", [])),
            ))
    extra = compile_terms(kw.get("extra") or [])
    for term in kw.get("extra_case_sensitive") or []:
        if term.startswith("re:"):
            extra.append((term[3:].replace(r"\d*", ""), re.compile(term[3:])))
        else:
            extra.extend(compile_terms([term], flags=0))
    return Matchers(
        entries=entries,
        keywords=compile_terms(kw.get("critical") or []),
        extra=extra,
        regional=compile_terms(kw.get("regional") or []),
        big_story=compile_terms(kw.get("big_story") or []),
        muted=[(t, _muted_pattern(t)) for t in kw.get("muted") or []],
        watch_categories=set(cfg["scoring"].get("watchlist_categories") or []),
        big_story_categories=set(cfg["scoring"].get("big_story_categories") or []),
    )


def _hits(terms: list[tuple[str, re.Pattern]], text: str) -> list[str]:
    return [t for t, rx in terms if rx.search(text)]


def match_watchlist(text: str, matchers: Matchers, cve_record: bool = False) -> list[dict]:
    """Entries from the highest matching tier only; tiers never stack."""
    best_tier = None
    found = []
    for entry in matchers.entries:
        if best_tier is not None and entry.tier > best_tier:
            break  # entries are ordered by tier
        term = entry.match(text, cve_record)
        if term:
            best_tier = entry.tier
            found.append({"vendor": entry.vendor, "term": term, "tier": entry.tier, "points": entry.points})
    return found


def is_watched_vendor(vendor: str, product: str, matchers: Matchers) -> bool:
    """Used by suggest-watchlist: is this KEV vendor/product already covered?"""
    return bool(match_watchlist(f"{vendor} {product}", matchers))


def classify(item, matchers: Matchers) -> None:
    """Fill in the item's match fields. Scoring reads these, not the raw text."""
    text = f"{item.title} {item.summary}"
    item.keyword_hits = _hits(matchers.keywords, text)
    item.topic_hits = _hits(matchers.regional, text)
    if item.category in matchers.watch_categories:
        item.vendor_matches = match_watchlist(text, matchers, cve_record=item.source_type == "nvd")
        item.topic_hits += _hits(matchers.extra, text)
    if item.category in matchers.big_story_categories:
        item.big_story_hits = _hits(matchers.big_story, item.title)
    # Muting reads the title only: "how to deal with" in a summary must not bury a story.
    if item.source_type not in ("cisa_kev", "vulncheck_kev", "nvd"):
        item.muted_hits = _hits(matchers.muted, item.title)

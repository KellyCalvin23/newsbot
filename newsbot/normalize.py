"""Stage 2, normalize: turn raw source entries into `Item` records."""
from __future__ import annotations

import hashlib
import html
import re
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import Item
from .timeutil import parse_iso

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CVSS_TEXT_RE = re.compile(r"CVSS(?:v?\d(?:\.\d)?)?(?:\s+base)?(?:\s+score)?\s*[:=]?\s*(\d{1,2}\.\d)\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_BLOCK_RE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_WS_RE = re.compile(r"\s+")
_TRACKING_PREFIXES = ("utm_", "at_", "mc_", "pk_", "hsa_", "vs_")
MAX_URL_LENGTH = 1500
_TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "msclkid", "yclid", "igshid", "twclid", "ref", "ref_src",
    "source", "maca", "ocid", "cmpid", "cid", "feature", "share", "smid", "sr_share",
    "mkt_tok", "_hsenc", "_hsmi", "guccounter",
}
SUMMARY_LIMIT = 300
TITLE_LIMIT = 300
VULN_SOURCE_TYPES = {"cisa_kev", "vulncheck_kev", "nvd"}


def strip_html(text: str | None) -> str:
    if not text:
        return ""
    text = _BLOCK_RE.sub(" ", text)
    text = _TAG_RE.sub(" ", text)
    # Twice, because some feeds (SANS ISC among them) double-encode their entities.
    text = html.unescape(html.unescape(text))
    text = _TAG_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


def truncate(text: str, limit: int = SUMMARY_LIMIT) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0] or text[:limit]
    return cut.rstrip(" ,;:.") + "…"


def extract_cves(text: str | None) -> list[str]:
    """Unique CVE IDs, uppercased, in order of first appearance."""
    return list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text or "")))


def extract_cvss(text: str | None) -> float | None:
    """Advisories such as FortiGuard state the score only in their prose."""
    scores = [float(m) for m in CVSS_TEXT_RE.findall(text or "") if float(m) <= 10.0]
    return max(scores) if scores else None


def safe_url(url: str | None) -> str | None:
    """Feed links are untrusted. Only http(s) may ever end up in a message."""
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc or len(url) > MAX_URL_LENGTH:
        return None
    return url


def _strip_tracking(query: str) -> list[tuple[str, str]]:
    return [
        (k, v) for k, v in parse_qsl(query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING_PREFIXES) and k.lower() not in _TRACKING_PARAMS
    ]


def clean_url(url: str) -> str:
    """The link shown to the reader: same page, without tracking parameters."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(_strip_tracking(parts.query)), ""))


def canonical_url(url: str) -> str:
    parts = urlsplit(url.strip())
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    host = host.removesuffix(":443").removesuffix(":80")
    query = _strip_tracking(parts.query)
    path = parts.path.rstrip("/")
    # The scheme is dropped so that http and https versions of a link are one story.
    return urlunsplit(("", host, path, urlencode(sorted(query)), "")).lstrip("/")


def url_fingerprint(url: str) -> str:
    return hashlib.sha256(canonical_url(url).encode()).hexdigest()


def fingerprint(source_type: str, category: str, cve_ids: list[str], url: str) -> str:
    """CVE ID for vulnerability records, otherwise a hash of the canonical URL."""
    if source_type in VULN_SOURCE_TYPES and cve_ids:
        return cve_ids[0]
    if category == "vulnerabilities" and len(cve_ids) == 1:
        return cve_ids[0]
    return url_fingerprint(url)


def normalize_entry(entry: dict, src: dict) -> Item | None:
    url = safe_url(entry.get("url"))
    title = truncate(strip_html(entry.get("title")), TITLE_LIMIT)
    if not url or not title:
        return None
    full_summary = strip_html(entry.get("summary"))
    cve_ids = entry.get("cve_ids") or extract_cves(f"{title} {full_summary}")
    cve_ids = [c.upper() for c in cve_ids if CVE_RE.fullmatch(c)]
    source_type = src["type"]
    category = src["category"]
    tags = list(entry.get("tags") or [])
    return Item(
        id=fingerprint(source_type, category, cve_ids, url),
        source=src["name"],
        title=title,
        url=clean_url(url),
        published=entry.get("published"),
        summary=truncate(full_summary),
        cve_ids=cve_ids[:20],
        cvss=entry.get("cvss") if entry.get("cvss") is not None else extract_cvss(full_summary),
        tags=tags,
        source_type=source_type,
        category=category,
        weight=src.get("weight", 0),
        sources=[src["name"]],
    )


def normalize_entries(entries: list[dict], src: dict, now: datetime, max_age_days: int) -> list[Item]:
    """Normalize a feed and drop entries too old to be news.

    Some feeds carry years of history (MSRC has over 5,000 items). The age limit is
    shorter than state retention, so a pruned item can never look new again.
    KEV is exempt because it is matched by CVE ID against the known set.
    """
    cutoff = now - timedelta(days=max_age_days)
    items = []
    for entry in entries:
        item = normalize_entry(entry, src)
        if item is None:
            continue
        published = parse_iso(item.published)
        if src["type"] != "cisa_kev" and published is not None and published < cutoff:
            continue
        items.append(item)
    return items

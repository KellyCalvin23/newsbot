"""The one record every source is normalized into."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

# Routes only ever move forward, so a story is never delivered twice at the same level.
ROUTE_RANK = {"new": 0, "seed": 0, "drop": 1, "digest": 2, "alert": 3}


@dataclass
class Item:
    id: str  # dedup fingerprint: CVE ID for vulnerabilities, else sha256(canonical URL)
    source: str
    title: str
    url: str
    published: str | None = None  # ISO 8601 UTC
    summary: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    vendor_matches: list[dict] = field(default_factory=list)  # highest matching tier only
    tags: list[str] = field(default_factory=list)  # e.g. cisa_kev, ransomware_known

    source_type: str = "rss"
    category: str = "security"  # vulnerabilities | security | tech | world
    weight: float = 0
    keyword_hits: list[str] = field(default_factory=list)
    topic_hits: list[str] = field(default_factory=list)  # extra / regional keywords
    big_story_hits: list[str] = field(default_factory=list)
    muted_hits: list[str] = field(default_factory=list)

    sources: list[str] = field(default_factory=list)
    coverage_count: int = 1
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    route: str = "new"
    alerted: bool = False
    alerted_tags: list[str] = field(default_factory=list)
    is_update: bool = False
    silent_update: bool = False
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize without empty values, which keeps the state files small."""
        return {k: v for k, v in asdict(self).items() if v not in (None, "", [], False)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Item":
        known = {f.name for f in fields(cls)}
        values = {k: v for k, v in data.items() if k in known}
        values.setdefault("id", "")
        values.setdefault("source", "")
        values.setdefault("title", "")
        values.setdefault("url", "")
        return cls(**values)

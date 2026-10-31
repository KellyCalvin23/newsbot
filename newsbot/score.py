"""Stage 4, score: a pure function of an item's features and config.yaml."""
from __future__ import annotations


def score_item(item, cfg: dict) -> tuple[int, list[str]]:
    s = cfg["scoring"]
    if item.muted_hits:
        return 0, [f"muted: {item.muted_hits[0]}"]

    total = 0.0
    reasons: list[str] = []

    if "cisa_kev" in item.tags:
        total += s["cisa_kev"]
        reasons.append("new CISA KEV")
    elif "vulncheck_kev" in item.tags:
        total += s["vulncheck_kev"]
        reasons.append("new VulnCheck KEV")
    if "ransomware_known" in item.tags and {"cisa_kev", "vulncheck_kev"} & set(item.tags):
        total += s["kev_ransomware_bonus"]
        reasons.append("known ransomware use")

    if item.cvss is not None:
        if item.cvss >= s["cvss_critical_min"]:
            total += s["cvss_critical"]
            reasons.append(f"CVSS {item.cvss:.1f}")
        elif item.cvss >= s["cvss_high_min"]:
            total += s["cvss_high"]
            reasons.append(f"CVSS {item.cvss:.1f}")

    if item.epss is not None and item.epss >= s["epss_min"]:
        total += s["epss"]
        reasons.append(f"EPSS {item.epss:.2f}")

    if item.keyword_hits:
        total += s["keyword"]
        reasons.append(item.keyword_hits[0])

    if item.vendor_matches:
        best = item.vendor_matches[0]
        total += best["points"]
        label = best["vendor"]
        if best["term"].lower() != best["vendor"].lower():
            label = f"{best['vendor']} {best['term']}"
        reasons.append(f"matches {label} (Tier {best['tier']})")

    if item.topic_hits:
        total += s["extra_keyword"]
        reasons.append(f"topic: {item.topic_hits[0]}")

    if item.big_story_hits:
        total += s["big_story"]
        reasons.append(f"big story: {item.big_story_hits[0]}")

    if item.coverage_count >= s["coverage_min"]:
        total += s["coverage"]
        reasons.append(f"{item.coverage_count} sources")

    if item.weight:
        total += item.weight
        reasons.append(f"source weight {item.weight:+g}")

    # Hundreds of CVEs a day score CVSS 9+ with "unauthenticated" in the text, almost
    # all of them obscure plugins. Without a watchlist hit or real exploitation signal,
    # such a record may reach the digest but cannot ring the phone.
    cap = s.get("unmatched_vuln_cap")
    exploited = {"cisa_kev", "vulncheck_kev"} & set(item.tags) or (
        item.epss is not None and item.epss >= s["epss_min"]
    )
    if (
        cap is not None and item.source_type == "nvd"
        and not item.vendor_matches and not exploited and total > cap
    ):
        total = cap
        reasons.append("capped: not on watchlist")

    # VulnCheck lists far more than CISA: measured at ~10 entries a day that would alert,
    # mostly for products not on the watchlist. Worth knowing, but not worth waking up for.
    # High EPSS, a watchlist hit, or a CISA listing still lets it ring.
    vc_cap = s.get("unmatched_vulncheck_cap")
    if (
        vc_cap is not None and "vulncheck_kev" in item.tags and "cisa_kev" not in item.tags
        and not item.vendor_matches and not (item.epss is not None and item.epss >= s["epss_min"])
        and total > vc_cap
    ):
        total = vc_cap
        reasons.append("capped: not on watchlist")

    return max(0, min(int(total), s["max_score"])), reasons

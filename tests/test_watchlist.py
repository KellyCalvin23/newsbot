import pytest

from newsbot.watchlist import match_watchlist


def tier(text, matchers, **kw):
    m = match_watchlist(text, matchers, **kw)
    return (m[0]["vendor"], m[0]["tier"]) if m else None


@pytest.mark.parametrize("text,expected", [
    ("New FORTIGATE bug", ("Fortinet", 1)),
    ("fortigate bug", ("Fortinet", 1)),
    ("FortiOS-based appliances", ("Fortinet", 1)),
    ("PAN-OS advisory", ("Palo Alto Networks", 1)),
    ("Cisco IOS XE flaw", ("Cisco", 1)),
    ("NetScaler Gateway hit", ("Citrix", 1)),
    ("Exchange Server hacked", ("Microsoft", 2)),
    ("Windows zero-day", ("Microsoft", 2)),
    ("OpenSSH regression", ("Linux kernel", 2)),
    ("MOVEit breach", ("Progress MOVEit", 3)),
    ("ScreenConnect abused", ("ConnectWise", 3)),
    ("Ollama exposed", ("Ollama", 3)),
])
def test_vendor_and_product_matching(text, expected, matchers):
    assert tier(text, matchers) == expected


def test_highest_tier_wins_and_lower_tiers_are_absent(matchers):
    found = match_watchlist("Fortinet and Microsoft and GitLab all patched", matchers)
    assert {m["tier"] for m in found} == {1}


def test_same_tier_lists_all_vendors(matchers):
    found = match_watchlist("Fortinet and Cisco advisories", matchers)
    assert {m["vendor"] for m in found} == {"Fortinet", "Cisco"}


@pytest.mark.parametrize("text", [
    "The economic outlook remains weak",
    "A safari in Akagera national park",
    "Oval Office meeting on the edge of a deal",
    "Sapling grows quickly",           # must not match SAP
    "The ASA tournament begins",
    "Island of Java earthquake",
])
def test_everyday_words_do_not_match(text, matchers):
    assert match_watchlist(text, matchers) == []


def test_ambiguous_product_counts_with_vendor(matchers):
    found = match_watchlist("Apple Safari flaw", matchers)
    assert found[0]["vendor"] == "Apple" and found[0]["term"] == "Safari"


def test_platform_name_ignored_on_nvd_records_only(matchers):
    text = "The installer for Yamaha LAN Monitor for Windows loads DLLs"
    assert match_watchlist(text, matchers, cve_record=True) == []
    assert tier(text, matchers) == ("Microsoft", 2)


def test_extra_keyword_apt_is_case_sensitive(make_item):
    assert make_item("APT28 hits ministry").topic_hits
    assert make_item("APT group hits ministry").topic_hits
    assert not make_item("An apt description of the bug").topic_hits


def test_world_news_skips_watchlist_but_keeps_regional(make_item):
    item = make_item("Apache helicopter seen near Kigali", category="world", source="BBC")
    assert item.vendor_matches == []
    assert item.topic_hits == ["Kigali"]


@pytest.mark.parametrize("title,muted", [
    ("Sponsored: get our product", True),
    ("Join our webinar on XDR", True),
    ("Black Friday deal on routers", True),
    ("50% off VPNs", True),
    ("State-sponsored hackers breach ministry", False),
    ("State sponsored hackers breach ministry", False),
    ("Government-sponsored espionage campaign", False),
    ("Dealing with ransomware", False),
])
def test_muted_keywords(title, muted, make_item):
    assert bool(make_item(title).muted_hits) is muted


def test_mute_checks_title_only_and_never_kev(make_item):
    assert not make_item("Fortinet flaw", summary="how to deal with it").muted_hits
    assert not make_item("Webinar platform flaw", source_type="cisa_kev").muted_hits

from datetime import timedelta

from newsbot.normalize import (
    canonical_url, clean_url, extract_cves, extract_cvss, fingerprint, normalize_entries,
    normalize_entry, safe_url, strip_html, truncate, url_fingerprint,
)

SRC = {"name": "X", "type": "rss", "category": "security", "weight": 0}


def test_extract_cves_dedupes_and_uppercases():
    assert extract_cves("cve-2024-3400 and CVE-2024-3400, CVE-2021-44228") == ["CVE-2024-3400", "CVE-2021-44228"]


def test_extract_cves_supports_long_ids_and_rejects_short():
    assert extract_cves("CVE-2026-1234567") == ["CVE-2026-1234567"]
    assert extract_cves("CVE-2026-123") == []
    assert extract_cves(None) == []


def test_extract_cvss_from_prose():
    assert extract_cvss("CVSSv3 Score: 9.8 and more") == 9.8
    assert extract_cvss("CVSS 7.5") == 7.5
    assert extract_cvss("CVSS 99.9") is None
    assert extract_cvss("version 9.8") is None


def test_strip_html_removes_tags_scripts_and_double_encoding():
    assert strip_html("<p>Hello <b>world</b></p><script>evil()</script>") == "Hello world"
    assert strip_html("YARA&amp;#39;s &amp;amp; fix") == "YARA's & fix"
    assert strip_html(None) == ""


def test_truncate_cuts_on_word_boundary():
    out = truncate("word " * 100, 300)
    assert len(out) <= 301 and out.endswith("…") and not out.endswith(" …")


def test_canonical_url_ignores_tracking_case_scheme_and_slash():
    a = canonical_url("https://WWW.Example.com/a/?utm_source=x&utm_medium=y&id=1#frag")
    b = canonical_url("http://example.com/a?id=1&fbclid=abc")
    assert a == b == "example.com/a?id=1"


def test_canonical_url_keeps_meaningful_params():
    assert canonical_url("https://x.com/p?id=1") != canonical_url("https://x.com/p?id=2")


def test_known_feed_tracking_params_removed():
    assert canonical_url("https://bbc.co.uk/a?at_medium=RSS&at_campaign=rss") == "bbc.co.uk/a"
    assert clean_url("https://cisco.com/a?vs_f=x%26vs_cat=y") == "https://cisco.com/a"


def test_safe_url_only_allows_http():
    assert safe_url("https://a.com/x") == "https://a.com/x"
    assert safe_url("javascript:alert(1)") is None
    assert safe_url("file:///etc/passwd") is None
    assert safe_url("") is None
    assert safe_url("https://a.com/" + "x" * 2000) is None


def test_fingerprint_uses_cve_for_vulns_and_url_for_news():
    url = "https://a.com/x"
    assert fingerprint("nvd", "vulnerabilities", ["CVE-2026-0001"], url) == "CVE-2026-0001"
    assert fingerprint("rss", "vulnerabilities", ["CVE-2026-0001"], url) == "CVE-2026-0001"
    assert fingerprint("rss", "vulnerabilities", ["CVE-2026-1", "CVE-2026-2"], url) == url_fingerprint(url)
    assert fingerprint("rss", "security", ["CVE-2026-1"], url) == url_fingerprint(url)


def test_normalize_entry_builds_record():
    item = normalize_entry({
        "title": "A <b>title</b>", "url": "https://a.com/x?utm_source=r",
        "summary": "<p>See CVE-2026-1111. CVSS: 9.1</p>", "published": "2026-10-30T00:00:00Z",
    }, SRC)
    assert item.title == "A title"
    assert item.url == "https://a.com/x"
    assert item.cve_ids == ["CVE-2026-1111"]
    assert item.cvss == 9.1
    assert item.sources == ["X"]


def test_normalize_rejects_dangerous_link_and_empty_title():
    assert normalize_entry({"title": "t", "url": "javascript:alert(1)"}, SRC) is None
    assert normalize_entry({"title": "", "url": "https://a.com"}, SRC) is None


def test_age_filter_drops_old_but_keeps_undated_and_kev(now):
    entries = [
        {"title": "old", "url": "https://a.com/1", "published": "2020-01-01T00:00:00Z"},
        {"title": "new", "url": "https://a.com/2", "published": (now - timedelta(days=1)).isoformat()},
        {"title": "undated", "url": "https://a.com/3"},
    ]
    assert [i.title for i in normalize_entries(entries, SRC, now, 14)] == ["new", "undated"]
    kev = {**SRC, "type": "cisa_kev"}
    assert len(normalize_entries(entries, kev, now, 14)) == 3

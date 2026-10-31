"""Source adapters against saved fixtures. The fake session makes network calls impossible."""
import json
import logging
from datetime import date

import pytest
import requests

from conftest import FakeResponse
from newsbot.config import source_active
from newsbot.fetch import FetchResult, fetch_all, fetch_cisa_kev, fetch_hn, fetch_nvd, fetch_rss, fetch_source, fetch_vulncheck_kev
from newsbot.http import FetchError, HttpClient
from newsbot.enrich import enrich_epss
from newsbot.normalize import normalize_entries
from newsbot.security import RedactingFormatter, redact
from newsbot.suggest import count_candidates
from newsbot.telegram import TelegramClient, TelegramError, TelegramRejected


class Session:
    def __init__(self, routes=None, default=None):
        self.routes, self.default, self.calls = routes or {}, default, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        for key, resp in self.routes.items():
            if key in url:
                return resp
        if self.default is not None:
            return self.default
        raise AssertionError(f"unexpected request: {url}")


def client(session):
    return HttpClient(session=session, sleep=lambda _: None, retries=2, max_bytes=1_000_000)


def src(type_, url="https://x.example/feed", **kw):
    return {"name": "S", "type": type_, "category": "security", "url": url, **kw}


def test_rss_fixture(fixture_bytes, now):
    c = client(Session(default=FakeResponse(fixture_bytes("rss_news.xml"))))
    result = fetch_rss(src("rss"), c, {})
    assert len(result.entries) == 3
    items = normalize_entries(result.entries, src("rss"), now, 14)
    assert len(items) == 1  # the old item and the javascript: link are gone
    item = items[0]
    assert item.title == "Fortinet & friends: FortiGate zero-day exploited"
    assert item.url == "https://news.example.com/fortigate"
    assert item.cve_ids == ["CVE-2026-1234", "CVE-2026-55555"]
    assert item.cvss == 9.8
    assert "alert(1)" not in item.summary and "<" not in item.summary


def test_atom_fixture(fixture_bytes):
    c = client(Session(default=FakeResponse(fixture_bytes("atom.xml"))))
    entry = fetch_rss(src("rss"), c, {}).entries[0]
    assert entry["url"] == "https://atom.example.com/a" and entry["published"] == "2026-10-31T08:00:00Z"


def test_garbage_feed_is_a_source_failure_not_a_crash():
    c = client(Session(default=FakeResponse(b"<<<not a feed")))
    result = fetch_source(src("rss"), c, {})
    assert result.ok is False


def test_cisa_kev_fixture(fixture_bytes):
    c = client(Session(default=FakeResponse(fixture_bytes("cisa_kev.json"))))
    entries = fetch_cisa_kev(src("cisa_kev"), c, {}).entries
    assert entries[0]["cve_ids"] == ["CVE-2026-1000"]
    assert entries[0]["tags"] == ["cisa_kev", "ransomware_known"]
    assert entries[1]["tags"] == ["cisa_kev"]
    assert "Ivanti Connect Secure" in entries[0]["summary"]


def test_vulncheck_fixture_uses_bearer_token_and_no_redirects(fixture_bytes, monkeypatch):
    monkeypatch.setenv("VULNCHECK_API_TOKEN", "tok-123")
    s = Session(default=FakeResponse(fixture_bytes("vulncheck.json")))
    entries = fetch_vulncheck_kev(src("vulncheck_kev", requires_secret="VULNCHECK_API_TOKEN"), client(s), {}).entries
    assert len(entries) == 1 and entries[0]["tags"] == ["vulncheck_kev", "ransomware_known"]
    kwargs = s.calls[0][1]
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"
    assert kwargs["allow_redirects"] is False


def test_nvd_fixture_filters_old_and_rejected(fixture_bytes, now, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    s = Session(default=FakeResponse(fixture_bytes("nvd.json")))
    result = fetch_nvd(src("nvd"), client(s), {"now": now, "nvd_cursor": "2026-10-31T09:45:00Z"})
    assert [e["cve_ids"] for e in result.entries] == [["CVE-2026-2000"]]
    assert result.entries[0]["cvss"] == 9.8
    assert result.entries[0]["title"].startswith("CVE-2026-2000: Fortinet FortiWeb")
    assert result.meta["nvd_cursor"] == "2026-10-31T10:00:00Z"
    assert s.calls[0][1]["params"]["lastModStartDate"] == "2026-10-31T09:35:00.000Z"


def test_nvd_first_run_downloads_nothing(now):
    s = Session()
    result = fetch_nvd(src("nvd"), client(s), {"now": now})
    assert s.calls == [] and result.meta["nvd_cursor"]


def test_nvd_catches_up_one_day_at_a_time(fixture_bytes, now):
    s = Session(default=FakeResponse(fixture_bytes("nvd.json")))
    result = fetch_nvd(src("nvd"), client(s), {"now": now, "nvd_cursor": "2026-10-25T10:10:00Z", "max_item_age_days": 14})
    assert s.calls[0][1]["params"]["lastModEndDate"] == "2026-10-26T10:00:00.000Z"
    assert result.meta["nvd_cursor"] == "2026-10-26T10:00:00Z"


def test_nvd_sends_api_key_as_header_only(fixture_bytes, now, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "k-1")
    s = Session(default=FakeResponse(fixture_bytes("nvd.json")))
    fetch_nvd(src("nvd"), client(s), {"now": now, "nvd_cursor": "2026-10-31T09:00:00Z"})
    assert s.calls[0][1]["headers"]["apiKey"] == "k-1"
    assert "k-1" not in s.calls[0][0] and "k-1" not in json.dumps(s.calls[0][1]["params"])


def test_hn_fixture_applies_score_filter(fixture_bytes):
    s = Session({
        "topstories": FakeResponse(fixture_bytes("hn_top.json")),
        "item/101": FakeResponse(fixture_bytes("hn_101.json")),
        "item/102": FakeResponse(fixture_bytes("hn_102.json")),
    })
    entries = fetch_hn(src("hn", url="https://hn.example/v0/topstories.json", min_score=300), client(s), {}).entries
    assert [e["title"] for e in entries] == ["Big popular story"]


def test_epss_fixture_sets_probability(fixture_bytes, make_item):
    c = client(Session(default=FakeResponse(fixture_bytes("epss.json"))))
    item = make_item(cve_ids=["CVE-2026-2000"])
    other = make_item(cve_ids=["CVE-2026-4"])
    enrich_epss([item, other], c, "https://epss.example")
    assert item.epss == 0.94 and other.epss is None


def test_epss_outage_is_harmless(make_item):
    c = client(Session(default=FakeResponse(status=500)))
    item = make_item(cve_ids=["CVE-2026-2000"])
    enrich_epss([item], c, "https://epss.example")
    assert item.epss is None


def test_optional_source_without_secret_is_inactive():
    s = {"enabled": True, "requires_secret": "VULNCHECK_API_TOKEN"}
    assert source_active(s, {}) is False
    assert source_active(s, {"VULNCHECK_API_TOKEN": "x"}) is True
    assert source_active({"enabled": False}, {}) is False


# --- HTTP hardening ---------------------------------------------------------

def test_retries_then_succeeds():
    class Flaky(Session):
        def get(self, url, **kw):
            self.calls.append(url)
            return FakeResponse(status=503) if len(self.calls) < 3 else FakeResponse(b"ok")
    s = Flaky()
    assert client(s).get("https://x.example/") == b"ok" and len(s.calls) == 3


def test_gives_up_after_retries_without_leaking_query():
    s = Session(default=FakeResponse(status=503))
    with pytest.raises(FetchError) as err:
        client(s).get("https://x.example/?secret=abc")
    assert len(s.calls) == 3 and "abc" not in str(err.value)


def test_404_is_not_retried():
    s = Session(default=FakeResponse(status=404))
    with pytest.raises(FetchError):
        client(s).get("https://x.example/")
    assert len(s.calls) == 1


def test_response_size_is_capped():
    s = Session(default=FakeResponse(b"x" * 2_000_000))
    with pytest.raises(FetchError, match="exceeds"):
        client(s).get("https://x.example/")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x.example/a", "gopher://x"])
def test_non_http_schemes_refused(url):
    s = Session()
    with pytest.raises(FetchError):
        client(s).get(url)
    assert s.calls == []


def test_every_request_has_a_timeout():
    s = Session(default=FakeResponse(b"ok"))
    client(s).get("https://x.example/")
    assert s.calls[0][1]["timeout"] > 0


def test_connection_error_text_is_discarded():
    class Down(Session):
        def get(self, url, **kw):
            raise requests.ConnectionError(f"failed for {url}")
    with pytest.raises(FetchError) as err:
        client(Down()).get("https://x.example/path?key=abc")
    assert "abc" not in str(err.value) and "ConnectionError" in str(err.value)


def test_fetch_all_isolates_failures(fixture_bytes):
    class Mixed(Session):
        def get(self, url, **kw):
            if "bad" in url:
                raise requests.ConnectionError("x")
            return FakeResponse(fixture_bytes("atom.xml"))
    sources = [{**src("rss", "https://bad.example/"), "name": "bad"}, {**src("rss", "https://good.example/"), "name": "good"}]
    results = fetch_all(sources, client(Mixed()), {})
    assert [r.ok for r in results] == [False, True]


# --- secrets ----------------------------------------------------------------

TOKEN = "123456789:AAFakeTokenValue_abc-XYZ"


def test_redact_masks_token_url_and_env_values():
    assert TOKEN not in redact(f"GET https://api.telegram.org/bot{TOKEN}/sendMessage", {})
    assert "s3cret" not in redact("key s3cret here", {"NVD_API_KEY": "s3cret"})


def test_formatter_redacts_tracebacks(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", TOKEN)
    try:
        raise ValueError(f"boom {TOKEN}")
    except ValueError:
        import sys
        record = logging.LogRecord("x", logging.ERROR, "f", 1, "msg", None, sys.exc_info())
    assert TOKEN not in RedactingFormatter().format(record)


class TgSession:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json, timeout))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def tg(session, slept=None):
    return TelegramClient(TOKEN, "42", session=session, sleep=(slept.append if slept is not None else lambda _: None))


def test_send_payload_targets_only_configured_chat():
    s = TgSession(FakeResponse())
    tg(s).send("<b>hi</b>", silent=True)
    url, payload, timeout = s.calls[0]
    assert payload == {"chat_id": "42", "text": "<b>hi</b>", "parse_mode": "HTML",
                       "disable_web_page_preview": True, "disable_notification": True}
    assert timeout and url.endswith("/sendMessage")


def test_429_waits_retry_after_then_succeeds():
    slept = []
    s = TgSession(FakeResponse(status=429, json_body={"parameters": {"retry_after": 7}}), FakeResponse())
    tg(s, slept).send("x")
    assert slept == [7] and len(s.calls) == 2


def test_messages_are_paced():
    slept = []
    c = tg(TgSession(FakeResponse(), FakeResponse()), slept)
    c.send("a")
    c.send("b")
    assert slept == [1.1]


def test_network_error_never_exposes_token():
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    s = TgSession(*[requests.ConnectionError(f"failed {url}")] * 4)
    with pytest.raises(TelegramError) as err:
        tg(s).send("x")
    assert TOKEN not in str(err.value)


def test_bad_markup_is_rejected_but_bad_chat_is_a_real_failure():
    s = TgSession(FakeResponse(status=400, json_body={"description": "Bad Request: can't parse entities"}))
    with pytest.raises(TelegramRejected):
        tg(s).send("x")
    s = TgSession(FakeResponse(status=400, json_body={"description": "Bad Request: chat not found"}))
    with pytest.raises(TelegramError) as err:
        tg(s).send("x")
    assert not isinstance(err.value, TelegramRejected)


def test_no_hardcoded_secrets_in_source():
    from conftest import ROOT
    import re
    for path in [*ROOT.glob("newsbot/*.py"), ROOT / "config.yaml"]:
        assert not re.search(r"\b\d{8,}:[A-Za-z0-9_-]{30,}", path.read_text()), path


# --- suggest-watchlist ------------------------------------------------------

def kev(vendor, product="P", added="2026-06-01", ransom="Unknown"):
    return {"vendorProject": vendor, "product": product, "dateAdded": added, "knownRansomwareCampaignUse": ransom}


def test_suggest_counts_unwatched_vendors(matchers):
    entries = [
        kev("Acme", "Widget", ransom="Known"), kev("Acme", "Widget"), kev("Acme", "Gadget"),
        kev("Beta"), kev("Beta"),
        kev("Single"),                                  # below the minimum
        kev("Old", added="2020-01-01"), kev("Old", added="2020-01-01"),  # outside 12 months
        kev("Fortinet", "FortiOS"), kev("Fortinet", "FortiOS"),          # already watched
        kev("Bad", added="not-a-date"), kev("Bad", added="not-a-date"),
    ]
    rows = count_candidates(entries, matchers, date(2026, 10, 31))
    assert [r["vendor"] for r in rows] == ["Acme", "Beta"]
    assert rows[0]["count"] == 3 and rows[0]["ransomware"] == 1
    assert rows[0]["products"][0] == ("Widget", 2)


def test_suggest_never_touches_config(matchers):
    from conftest import ROOT
    before = (ROOT / "config.yaml").read_bytes()
    count_candidates([kev("Acme"), kev("Acme")], matchers, date(2026, 10, 31))
    assert (ROOT / "config.yaml").read_bytes() == before

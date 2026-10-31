"""End-to-end behaviour with canned fetch results and no network."""
import json

import pytest

import newsbot.pipeline as pl
from newsbot.fetch import FetchResult
from newsbot.storage import JsonStorage, MemoryStorage, State, StateError


class NoNet:
    def get_json(self, *a, **k):
        return {"data": []}

    def sleep(self, _):
        pass

    def expired(self):
        return False


def src(name, type="rss", category="security", weight=0):
    return {"name": name, "type": type, "category": category, "weight": weight, "enabled": True, "url": "https://x.example/"}


NEWS, NEWS2, NEWS3, KEV, NVD = src("News"), src("News2"), src("News3"), src("KEV", "cisa_kev", "vulnerabilities"), src("NVD", "nvd", "vulnerabilities")
ALL = [NEWS, NEWS2, NEWS3, KEV, NVD]


def entry(title, slug=None, **kw):
    return {"title": title, "url": f"https://x.example/{slug or title.replace(' ', '-')}", "published": "2026-10-31T08:00:00Z", **kw}


def kev(cve, title="Ivanti Connect Secure flaw"):
    return entry(f"{cve}: {title}", slug=cve, cve_ids=[cve], tags=["cisa_kev"], summary="Ivanti Connect Secure.")


@pytest.fixture
def run(monkeypatch, cfg, now, sender):
    cfg["sources"] = ALL

    def _run(state, results, when=now, sources=ALL):
        monkeypatch.setattr(pl, "fetch_all", lambda *a, **k: results)
        cfg["sources"] = sources
        monkeypatch.setattr(pl, "active_sources", lambda _c: sources)
        return pl.run_alerts(cfg, state, NoNet(), sender, when)
    return _run


def ok(source, *entries, meta=None):
    return FetchResult(source, entries=list(entries), meta=meta or {})


# --- seed mode --------------------------------------------------------------

def test_first_run_sends_only_the_init_message(run, state, sender):
    code = run(state, [ok(NEWS, entry("FortiGate zero-day under attack")), ok(KEV, kev("CVE-2026-0001"))])
    assert code == 0
    assert len(sender.sent) == 1
    assert sender.sent[0][0] == f"✅ Bot initialized, monitoring {len(ALL)} sources."
    assert state.digest_queue == [] and state.pending_alerts == []
    assert "CVE-2026-0001" in state.kev_known


def test_after_seed_known_items_stay_quiet_and_new_ones_alert(run, state, sender):
    seed = [ok(NEWS), ok(KEV, kev("CVE-2026-0001"))]
    run(state, seed)
    sender.sent.clear()
    run(state, [ok(NEWS), ok(KEV, kev("CVE-2026-0001"), kev("CVE-2026-0002"))])
    assert len(sender.sent) == 1 and "CVE-2026-0002" in sender.sent[0][0]


def test_first_run_with_total_outage_does_not_initialize(run, state, sender):
    code = run(state, [FetchResult(NEWS, ok=False, error="x")])
    assert code == 1 and sender.sent == [] and state.is_empty


def test_source_down_at_seed_does_not_flood_later(run, state, sender):
    run(state, [ok(NEWS), FetchResult(KEV, ok=False, error="down")])
    sender.sent.clear()
    run(state, [ok(NEWS), ok(KEV, *[kev(f"CVE-2026-{n}") for n in range(1000, 1050)])])
    assert sender.sent == []  # KEV's backlog is seeded silently on its first success


def test_newly_enabled_source_is_seeded_silently(run, state, sender):
    run(state, [ok(NEWS)])
    sender.sent.clear()
    run(state, [ok(NEWS), ok(NEWS2, entry("FortiGate zero-day CVSS 9.8", summary="CVSS: 9.8"))])
    assert sender.sent == [] and state.digest_queue == []


def test_kev_backlog_never_returns_after_pruning(run, state, sender, cfg, now):
    run(state, [ok(NEWS), ok(KEV, kev("CVE-2020-0001"))])
    sender.sent.clear()
    state.stories.clear()  # as if 30 days of pruning had passed
    run(state, [ok(NEWS), ok(KEV, kev("CVE-2020-0001"))])
    assert sender.sent == []


# --- routing ----------------------------------------------------------------

def seeded(run, state, sender, sources=ALL):
    run(state, [ok(s) for s in sources])
    sender.sent.clear()


def test_high_score_alerts_mid_goes_to_digest_low_drops(run, state, sender):
    seeded(run, state, sender)
    run(state, [ok(NEWS,
                   entry("FortiGate zero-day exploited CVSS", summary="CVSS: 9.8"),   # 3+3+4
                   entry("Ransomware hits a retailer"),                                 # 3
                   entry("A nice photo of a cat"))])                                    # 0
    assert len(sender.sent) == 1 and "FortiGate" in sender.sent[0][0]
    assert [q["title"] for q in state.digest_queue] == ["Ransomware hits a retailer"]
    routes = {s["title"]: s.get("route") for s in state.stories.values()}
    assert routes["A nice photo of a cat"] == "drop"


def test_repeated_feed_item_is_not_delivered_again(run, state, sender):
    seeded(run, state, sender)
    results = [ok(NEWS, entry("FortiGate zero-day exploited", summary="CVSS: 9.8"), entry("Ransomware hits a retailer"))]
    run(state, results)
    sender.sent.clear()
    run(state, results)
    assert sender.sent == [] and len(state.digest_queue) == 1


def test_news_about_alerted_cve_does_not_ring_again(run, state, sender):
    seeded(run, state, sender)
    run(state, [ok(KEV, kev("CVE-2026-0007"))])
    assert len(sender.sent) == 1
    sender.sent.clear()
    run(state, [ok(NEWS, entry("Ivanti zero-day CVE-2026-0007 exploited, CVSS: 9.8", summary="CVE-2026-0007"))])
    assert sender.sent == []


def test_separate_multi_cve_article_about_alerted_cve_does_not_alert(run, state, sender):
    seeded(run, state, sender)
    run(state, [ok(KEV, kev("CVE-2026-0007"))])
    sender.sent.clear()
    cves = " ".join(f"CVE-2026-{n:04d}" for n in (7, 8, 9, 10))
    run(state, [ok(NEWS, entry("FortiGate zero-day, patch now", summary=f"{cves} CVSS: 9.8"))])
    assert sender.sent == []
    assert len(state.digest_queue) == 1


def test_growing_coverage_promotes_story_from_digest_to_alert(run, state, sender):
    seeded(run, state, sender)
    a = "Critical FortiGate zero-day exploited in attacks on enterprise networks"
    b = "Critical FortiGate zero-day exploited in attacks on enterprise networks worldwide"
    c = "Critical FortiGate zero-day exploited in attacks on enterprise networks now"
    run(state, [ok(NEWS, entry(a))])
    assert sender.sent == [] and len(state.digest_queue) == 1
    run(state, [ok(NEWS2, entry(b))])
    assert sender.sent == []
    run(state, [ok(NEWS3, entry(c))])
    assert len(sender.sent) == 1 and "3 sources" in sender.sent[0][0]
    assert state.digest_queue == []  # moved, so it is not delivered twice


def test_cve_alerted_on_cvss_rings_again_when_added_to_kev(run, state, sender):
    seeded(run, state, sender)
    nvd = entry("CVE-2026-0009: FortiWeb flaw", slug="CVE-2026-0009", cve_ids=["CVE-2026-0009"], cvss=9.8, summary="FortiWeb remote code execution")
    run(state, [ok(NVD, nvd)])
    assert len(sender.sent) == 1
    sender.sent.clear()
    run(state, [ok(KEV, kev("CVE-2026-0009"))])
    assert len(sender.sent) == 1 and "Update" in sender.sent[0][0] and sender.sent[0][1] is False
    sender.sent.clear()
    run(state, [ok(KEV, kev("CVE-2026-0009"))])
    assert sender.sent == []


def test_unmatched_nvd_records_are_not_kept_in_state(run, state, sender):
    seeded(run, state, sender)
    nvd = entry("CVE-2026-0005: plugin flaw", slug="CVE-2026-0005", cve_ids=["CVE-2026-0005"], cvss=9.8)
    run(state, [ok(NVD, nvd)])
    assert "CVE-2026-0005" not in state.stories and sender.sent == []


def test_failed_source_does_not_stop_others(run, state, sender):
    seeded(run, state, sender)
    run(state, [FetchResult(NEWS, ok=False, error="boom"), ok(KEV, kev("CVE-2026-0011"))])
    assert len(sender.sent) == 1


def test_failed_alert_is_retried_next_run_once(run, state, sender, monkeypatch):
    from newsbot.telegram import TelegramError
    seeded(run, state, sender)
    real = sender.send
    def boom(*a, **k):
        raise TelegramError("down")
    sender.send = boom
    assert run(state, [ok(KEV, kev("CVE-2026-0012"))]) == 1
    assert len(state.pending_alerts) == 1
    sender.send = real
    assert run(state, [ok(KEV, kev("CVE-2026-0012"))]) == 0
    assert len(sender.sent) == 1 and state.pending_alerts == []


def test_nvd_cursor_only_advances_on_success(run, state, sender):
    seeded(run, state, sender)
    run(state, [ok(NVD, meta={"nvd_cursor": "2026-10-31T10:00:00Z"})])
    assert state.meta["nvd_cursor"] == "2026-10-31T10:00:00Z"
    run(state, [FetchResult(NVD, ok=False, error="x")])
    assert state.meta["nvd_cursor"] == "2026-10-31T10:00:00Z"


# --- digest -----------------------------------------------------------------

def test_digest_clears_queue_and_empty_queue_sends_nothing(state, cfg, sender, now):
    state.digest_queue = [{"id": "a", "source": "S", "title": "T", "url": "https://a.com", "score": 4, "category": "tech"}]
    assert pl.run_digest(cfg, state, sender, now) == 0
    assert state.digest_queue == [] and len(sender.sent) == 1
    sender.sent.clear()
    assert pl.run_digest(cfg, state, sender, now) == 0
    assert sender.sent == []


# --- storage ----------------------------------------------------------------

def test_json_storage_round_trip(tmp_path):
    st = State(JsonStorage(tmp_path))
    assert st.is_empty
    st.kev_known.add("CVE-2026-0001")
    st.digest_queue.append({"id": "x"})
    st.save()
    again = State(JsonStorage(tmp_path))
    assert again.kev_known == {"CVE-2026-0001"} and again.digest_queue == [{"id": "x"}]


def test_save_is_byte_stable_when_nothing_changed(tmp_path):
    st = State(JsonStorage(tmp_path))
    st.kev_known.update({"CVE-2026-0002", "CVE-2026-0001"})
    st.save()
    before = (tmp_path / "seen.json").stat().st_mtime_ns
    State(JsonStorage(tmp_path)).save()
    assert (tmp_path / "seen.json").stat().st_mtime_ns == before


def test_corrupt_state_stops_instead_of_reseeding(tmp_path):
    (tmp_path / "seen.json").write_text("{not json")
    with pytest.raises(StateError):
        State(JsonStorage(tmp_path))


def test_dry_run_leaves_state_files_alone(tmp_path, monkeypatch):
    from newsbot import cli
    monkeypatch.setattr(cli, "run_alerts", lambda cfg, state, *a, **k: (state.kev_known.add("X"), state.save(), 0)[2])
    monkeypatch.chdir(tmp_path.parent)
    from conftest import ROOT
    assert cli.main(["--config", str(ROOT / "config.yaml"), "run", "--mode", "alerts", "--dry-run", "--state-dir", str(tmp_path)]) == 0
    assert list(tmp_path.iterdir()) == []

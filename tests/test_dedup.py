from datetime import timedelta

from newsbot.dedup import ingest, prune, titles_match
from newsbot.timeutil import to_iso

LONG_A = "Critical FortiGate flaw exploited in attacks against enterprise networks"
LONG_B = "Critical FortiGate flaw exploited in attacks against enterprise networks worldwide"


def test_similar_titles_match():
    assert titles_match(LONG_A, LONG_B, 85)


def test_unrelated_titles_do_not_match():
    assert not titles_match(LONG_A, "New iPhone camera review shows impressive low light gains", 85)


def test_short_subset_title_does_not_match_everything():
    # token_set_ratio alone would score this 100.
    assert not titles_match("Ransomware attack", "Ransomware attack hits a large hospital in Germany today", 85)


def test_fuzzy_merge_counts_coverage(state, cfg, now, make_item):
    a = make_item(LONG_A, source="One", url="https://a.com/1", id="a")
    b = make_item(LONG_B, source="Two", url="https://b.com/2", id="b")
    ingest([a], state, cfg, now)
    changed = ingest([b], state, cfg, now)
    assert list(state.stories) == ["a"]
    assert changed["a"].coverage_count == 2
    assert changed["a"].sources == ["One", "Two"]


def test_fuzzy_ignored_outside_window(state, cfg, now, make_item):
    ingest([make_item(LONG_A, source="One", id="a")], state, cfg, now - timedelta(hours=49))
    ingest([make_item(LONG_B, source="Two", id="b")], state, cfg, now)
    assert set(state.stories) == {"a", "b"}


def test_same_source_titles_stay_separate(state, cfg, now, make_item):
    ingest([make_item(LONG_A, source="One", id="a")], state, cfg, now)
    ingest([make_item(LONG_B, source="One", id="b")], state, cfg, now)
    assert set(state.stories) == {"a", "b"}


def test_same_title_different_cves_stay_separate(state, cfg, now, make_item):
    ingest([make_item(LONG_A, source="One", id="a", cve_ids=["CVE-2026-1111"])], state, cfg, now)
    ingest([make_item(LONG_B, source="Two", id="b", cve_ids=["CVE-2026-2222"])], state, cfg, now)
    assert set(state.stories) == {"a", "b"}


def test_exact_repeat_changes_nothing(state, cfg, now, make_item):
    ingest([make_item(id="a")], state, cfg, now)
    assert ingest([make_item(id="a")], state, cfg, now) == {}


def test_article_joins_cve_story(state, cfg, now, make_item):
    ingest([make_item("CVE-2026-1111 record", source="NVD", id="CVE-2026-1111",
                      cve_ids=["CVE-2026-1111"], source_type="nvd")], state, cfg, now)
    changed = ingest([make_item("Article about the bug", source="News", id="n",
                                cve_ids=["CVE-2026-1111"])], state, cfg, now)
    assert "n" not in state.stories
    assert changed["CVE-2026-1111"].coverage_count == 2


def test_two_articles_sharing_a_cve_are_one_story(state, cfg, now, make_item):
    ingest([make_item("First take on it", source="A", id="a", cve_ids=["CVE-2026-1111"])], state, cfg, now)
    ingest([make_item("Totally different words", source="B", id="b", cve_ids=["CVE-2026-1111"])], state, cfg, now)
    assert list(state.stories) == ["a"]


def test_roundup_with_many_cves_stays_separate(state, cfg, now, make_item):
    ingest([make_item("Record", source="NVD", id="CVE-2026-0001", cve_ids=["CVE-2026-0001"], source_type="nvd")], state, cfg, now)
    many = [f"CVE-2026-{n:04d}" for n in range(1, 6)]
    ingest([make_item("Patch Tuesday roundup", source="News", id="r", cve_ids=many)], state, cfg, now)
    assert "r" in state.stories


def test_article_cannot_relabel_cve_vendor(state, cfg, now, make_item):
    ingest([make_item("CVE-2026-0001 GitLab flaw", source="KEV", id="CVE-2026-0001", cve_ids=["CVE-2026-0001"],
                      source_type="cisa_kev")], state, cfg, now)
    changed = ingest([make_item("Weekly recap of Cisco news", source="News", id="n",
                                cve_ids=["CVE-2026-0001"])], state, cfg, now)
    assert changed["CVE-2026-0001"].vendor_matches[0]["vendor"] == "GitLab"


def test_prune_removes_old_and_compacts_text(state, cfg, now):
    state.stories["old"] = {"last_seen": "2026-09-01", "first_seen": to_iso(now - timedelta(days=60))}
    state.stories["aging"] = {"last_seen": "2026-10-31", "first_seen": to_iso(now - timedelta(days=5)),
                              "title": "t", "url": "u", "route": "alert"}
    state.stories["fresh"] = {"last_seen": "2026-10-31", "first_seen": to_iso(now), "title": "t", "summary": "s"}
    prune(state, cfg, now)
    assert "old" not in state.stories
    assert state.stories["aging"] == {"last_seen": "2026-10-31", "first_seen": to_iso(now - timedelta(days=5)), "route": "alert"}
    assert state.stories["fresh"]["title"] == "t" and "summary" not in state.stories["fresh"]


def test_item_still_in_feed_survives_retention(state, cfg, now, make_item):
    ingest([make_item(id="a")], state, cfg, now - timedelta(days=40))
    ingest([make_item(id="a")], state, cfg, now)
    prune(state, cfg, now)
    assert "a" in state.stories

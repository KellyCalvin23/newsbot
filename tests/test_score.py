from newsbot.score import score_item


def test_new_cisa_kev_with_ransomware_and_tier1(cfg, make_item):
    item = make_item("Ivanti EPMM flaw", source_type="cisa_kev", tags=["cisa_kev", "ransomware_known"])
    score, reasons = score_item(item, cfg)
    assert score == 10  # 6 + 1 + 3
    assert "new CISA KEV" in reasons and "known ransomware use" in reasons
    assert any("Tier 1" in r for r in reasons)


def test_vulncheck_scores_five(cfg, make_item):
    assert score_item(make_item("Acme flaw", tags=["vulncheck_kev"]), cfg)[0] == 5


def test_cisa_and_vulncheck_do_not_stack(cfg, make_item):
    assert score_item(make_item("Acme flaw", tags=["cisa_kev", "vulncheck_kev"]), cfg)[0] == 6


def test_cvss_bands(cfg, make_item):
    assert score_item(make_item("Acme flaw", cvss=9.0), cfg)[0] == 4
    assert score_item(make_item("Acme flaw", cvss=8.9), cfg)[0] == 2
    assert score_item(make_item("Acme flaw", cvss=7.0), cfg)[0] == 2
    assert score_item(make_item("Acme flaw", cvss=6.9), cfg)[0] == 0


def test_epss_threshold(cfg, make_item):
    assert score_item(make_item("Acme flaw", epss=0.5), cfg)[0] == 2
    assert score_item(make_item("Acme flaw", epss=0.49), cfg)[0] == 0


def test_keywords_count_once(cfg, make_item):
    assert score_item(make_item("Zero-day RCE ransomware data breach"), cfg)[0] == 3


def test_watchlist_tier_points_do_not_stack(cfg, make_item):
    assert score_item(make_item("FortiGate story"), cfg)[0] == 3
    assert score_item(make_item("Microsoft story"), cfg)[0] == 2
    assert score_item(make_item("GitLab story"), cfg)[0] == 2
    assert score_item(make_item("FortiGate Microsoft GitLab story"), cfg)[0] == 3


def test_extra_and_regional_count_once(cfg, make_item):
    assert score_item(make_item("Botnet in Rwanda"), cfg)[0] == 2


def test_coverage_bonus(cfg, make_item):
    assert score_item(make_item("Acme", coverage_count=2), cfg)[0] == 0
    assert score_item(make_item("Acme", coverage_count=3), cfg)[0] == 2


def test_muted_is_zero_even_with_signals(cfg, make_item):
    score, reasons = score_item(make_item("FortiGate zero-day webinar", cvss=9.8), cfg)
    assert score == 0 and reasons[0].startswith("muted")


def test_capped_at_ten(cfg, make_item):
    item = make_item("FortiGate zero-day", cvss=9.8, epss=0.9, tags=["cisa_kev"], coverage_count=5)
    assert score_item(item, cfg)[0] == 10


def test_source_weight_is_added(cfg, make_item):
    assert score_item(make_item("Popular post", weight=3), cfg)[0] == 3


def test_obscure_nvd_record_is_capped(cfg, make_item):
    item = make_item("Plugin flaw unauthenticated", source="NVD", source_type="nvd", cvss=9.8)
    assert score_item(item, cfg)[0] == 2


def test_nvd_cap_lifts_on_watchlist_or_exploitation(cfg, make_item):
    watched = make_item("FortiWeb unauthenticated flaw", source="NVD", source_type="nvd", cvss=9.8)
    assert score_item(watched, cfg)[0] == 10
    hot = make_item("Plugin flaw", source="NVD", source_type="nvd", cvss=9.8, epss=0.9)
    assert score_item(hot, cfg)[0] == 6


def test_news_is_not_affected_by_nvd_cap(cfg, make_item):
    assert score_item(make_item("Plugin zero-day", cvss=9.8), cfg)[0] == 7


def test_unwatched_vulncheck_entry_goes_to_digest_not_alert(cfg, make_item):
    item = make_item("Obscure CMS unauthenticated flaw", source="VulnCheck KEV", source_type="vulncheck_kev",
                     tags=["vulncheck_kev"], cvss=9.8)
    score, reasons = score_item(item, cfg)
    assert score == 6 and "capped: not on watchlist" in reasons


def test_vulncheck_can_ring_with_watchlist_epss_or_cisa(cfg, make_item):
    common = dict(source="VulnCheck KEV", source_type="vulncheck_kev", cvss=9.8)
    assert score_item(make_item("FortiWeb flaw", tags=["vulncheck_kev"], **common), cfg)[0] >= 7
    assert score_item(make_item("Obscure CMS flaw", tags=["vulncheck_kev"], epss=0.9, **common), cfg)[0] >= 7
    assert score_item(make_item("Obscure CMS flaw", tags=["vulncheck_kev", "cisa_kev"], **common), cfg)[0] >= 7

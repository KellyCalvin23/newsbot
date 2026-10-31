from datetime import datetime, timezone

import pytest

from newsbot.deliver import (
    build_digest, deliver_alerts, deliver_digest, esc, format_alert, format_bundle, split_message,
)
from newsbot.models import Item
from newsbot.telegram import TelegramError, TelegramRejected
from newsbot.timeutil import in_quiet_hours

KIGALI = "Africa/Kigali"


def utc(hour, minute=0):
    return datetime(2026, 10, 31, hour, minute, tzinfo=timezone.utc)


def alert(i=1, score=8, **kw):
    return Item(id=f"id{i}", source="Src", title=f"Title {i}", url=f"https://a.com/{i}",
                score=score, reasons=["new CISA KEV"], published="2026-10-31T08:00:00Z", **kw).to_dict()


class FailingSender:
    def __init__(self, fail_on, exc=TelegramError("down")):
        self.fail_on, self.exc, self.sent = fail_on, exc, []

    def send(self, text, silent=False):
        if len(self.sent) + 1 == self.fail_on:
            self.fail_on = None
            self.sent.append("FAILED")
            raise self.exc
        self.sent.append(text)


# --- escaping ---------------------------------------------------------------

def test_feed_text_cannot_inject_markup():
    item = Item(id="x", source="<i>src</i>", title='<a href="http://evil">click</a> & <b>',
                url='https://a.com/?q="><script>', score=8, reasons=["<u>why</u>"], cve_ids=["CVE-2026-1"])
    out = format_alert(item, KIGALI)
    assert "<a href" not in out and "<script>" not in out and "<i>src" not in out and "<u>" not in out
    assert "&lt;a href=&quot;http://evil&quot;&gt;click&lt;/a&gt; &amp; &lt;b&gt;" in out


def test_href_attribute_cannot_be_broken_out_of():
    item = Item(id="x", source="s", title="t", url='https://a.com/"onclick="x', score=8)
    assert 'href="https://a.com/&quot;onclick=&quot;x"' in format_bundle([item])


def test_esc_handles_none():
    assert esc(None) == ""


def test_alert_format_matches_spec():
    item = Item.from_dict(alert(score=9, cve_ids=["CVE-2026-1"]))
    lines = format_alert(item, KIGALI).split("\n")
    assert lines[0] == "🔴 <b>[9/10] Title 1</b>"
    assert lines[1] == "Src · 31 Oct 10:00 CAT"  # 08:00 UTC is 10:00 in Kigali
    assert lines[2] == "Why: new CISA KEV"
    assert lines[3] == "CVE-2026-1"
    assert lines[4] == "https://a.com/1"


# --- splitting --------------------------------------------------------------

def test_short_message_not_split():
    assert split_message("hello") == ["hello"]


def test_split_respects_limit_and_keeps_all_lines():
    lines = [f"line number {i} " + "x" * 80 for i in range(200)]
    parts = split_message("\n".join(lines), 4096)
    assert len(parts) > 1 and all(len(p) <= 4096 for p in parts)
    assert "\n".join(parts).split("\n") == lines


def test_long_single_line_is_cut_within_limit():
    parts = split_message("word " * 2000, 4096)
    assert all(len(p) <= 4096 for p in parts) and len(parts) > 1


@pytest.mark.parametrize("line", ["a" * 95 + "&amp;" + "b" * 200, "a" * 95 + '<a href="x">' + "b" * 200])
def test_cut_never_splits_entity_or_tag(line):
    parts = split_message(line, 100)
    for part in parts:
        assert part.rfind("&") <= part.rfind(";") or "&" not in part
        assert part.rfind("<") <= part.rfind(">") or "<" not in part
    assert "".join(parts) == line


def test_digest_messages_respect_limit_and_track_every_id():
    items = [Item.from_dict({**alert(i, score=4), "category": "security"}) for i in range(100)]
    for it in items:
        it.title = "T" * 250
    msgs = build_digest(items, 200, "now")
    assert len(msgs) > 1 and all(len(t) <= 4096 for t, _ in msgs)
    assert sorted(i for _, ids in msgs for i in ids) == sorted(i.id for i in items)


# --- quiet hours ------------------------------------------------------------

@pytest.mark.parametrize("now,quiet", [
    (utc(20, 59), False),  # 22:59 Kigali
    (utc(21, 0), True),    # 23:00
    (utc(22), True),       # 00:00
    (utc(3, 59), True),    # 05:59
    (utc(4, 0), False),    # 06:00
    (utc(10), False),      # 12:00
])
def test_quiet_window_crosses_midnight(now, quiet):
    assert in_quiet_hours(now, "23:00", "06:00", KIGALI) is quiet


def test_same_day_window_and_empty_window():
    assert in_quiet_hours(utc(10), "09:00", "17:00", KIGALI)
    assert not in_quiet_hours(utc(10), "06:00", "06:00", KIGALI)


def test_quiet_hours_silences_below_nine(cfg, sender):
    deliver_alerts([alert(1, 8), alert(2, 9)], sender, cfg, utc(22))
    by_title = {("Title 2" in t): s for t, s in sender.sent}
    assert by_title[True] is False   # score 9 always rings
    assert by_title[False] is True   # score 8 is silent at night


def test_daytime_alerts_ring(cfg, sender):
    deliver_alerts([alert(1, 7)], sender, cfg, utc(10))
    assert sender.sent[0][1] is False


# --- anti-flood and failure handling ----------------------------------------

def test_flood_sends_top_five_then_one_bundle(cfg, sender):
    pending = [alert(i, score=7 + (i % 3)) for i in range(12)]
    left = deliver_alerts(pending, sender, cfg, utc(10))
    assert left == []
    assert len(sender.sent) == 6
    assert "7 more alerts" in sender.sent[5][0]
    top_scores = [int(t.split("[")[1].split("/")[0]) for t, _ in sender.sent[:5]]
    assert top_scores == sorted(top_scores, reverse=True) and top_scores[0] == 9


def test_exactly_five_has_no_bundle(cfg, sender):
    deliver_alerts([alert(i) for i in range(5)], sender, cfg, utc(10))
    assert len(sender.sent) == 5


def test_failed_alerts_are_kept_for_retry(cfg):
    s = FailingSender(2)
    left = deliver_alerts([alert(1, 9), alert(2, 8), alert(3, 7)], s, cfg, utc(10))
    assert [p["id"] for p in left] == ["id2", "id3"]


def test_message_telegram_rejects_does_not_block_the_rest(cfg):
    s = FailingSender(1, TelegramRejected("can't parse entities"))
    assert deliver_alerts([alert(1, 9), alert(2, 8)], s, cfg, utc(10)) == []
    assert len(s.sent) == 2


# --- digest -----------------------------------------------------------------

def test_digest_groups_sorts_and_is_silent(cfg, sender):
    queue = [
        {**alert(1, 3), "category": "world"},
        {**alert(2, 4), "category": "security"},
        {**alert(3, 6), "category": "security"},
        {**alert(4, 5), "category": "vulnerabilities"},
        {**alert(5, 3), "category": "tech"},
    ]
    assert deliver_digest(queue, sender, cfg, utc(5)) == []
    text = sender.sent[0][0]
    assert sender.sent[0][1] is True
    order = [text.index(h) for h in ("Vulnerabilities", "Security news", "Tech", "World")]
    assert order == sorted(order)
    assert text.index("Title 3") < text.index("Title 2")


def test_digest_overflow_is_counted_and_cleared(cfg, sender):
    cfg["settings"]["digest_max_per_category"] = 2
    queue = [{**alert(i, 3 + i % 3), "category": "security"} for i in range(5)]
    assert deliver_digest(queue, sender, cfg, utc(5)) == []
    assert "3 lower-scored items" in sender.sent[0][0]


def test_digest_failure_keeps_only_unsent(cfg):
    cfg["settings"]["digest_max_per_category"] = 500
    queue = [{**alert(i, 4), "category": "security", "title": "T" * 280} for i in range(60)]
    s = FailingSender(2)
    left = deliver_digest(queue, s, cfg, utc(5))
    assert 0 < len(left) < 60

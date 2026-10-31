from datetime import datetime, timezone
from pathlib import Path

import pytest

from newsbot.config import load_config
from newsbot.models import Item
from newsbot.storage import MemoryStorage, State
from newsbot.telegram import DryRunSender
from newsbot.watchlist import build_matchers, classify

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)  # 12:00 in Kigali


@pytest.fixture
def cfg():
    return load_config(ROOT / "config.yaml")


@pytest.fixture
def matchers(cfg):
    return build_matchers(cfg)


@pytest.fixture
def state():
    return State(MemoryStorage())


@pytest.fixture
def sender():
    return DryRunSender(lambda _text: None)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def fixture_bytes():
    return lambda name: (FIXTURES / name).read_bytes()


@pytest.fixture
def make_item(matchers):
    def _make(title="Some story headline for testing today", source="BleepingComputer", url=None,
              summary="", category="security", source_type="rss", id=None, **kw):
        item = Item(
            id=id or (url or title), source=source, title=title,
            url=url or "https://example.com/" + title.replace(" ", "-"),
            summary=summary, category=category, source_type=source_type, sources=[source], **kw,
        )
        classify(item, matchers)
        return item
    return _make


class FakeResponse:
    def __init__(self, body=b"", status=200, json_body=None, url="https://example.com/"):
        self.body, self.status_code, self._json, self.url = body, status, json_body, url

    def iter_content(self, _size):
        yield self.body

    def json(self):
        return self._json

    def close(self):
        pass

"""State persistence behind a small interface so SQLite can replace JSON later.

Only this file knows how state is stored. A SQLite backend needs to implement
`Storage.load`, `Storage.save`, and nothing else has to change.
"""
from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class StateError(Exception):
    pass


class Storage(ABC):
    @abstractmethod
    def load(self, name: str, default: Any) -> Any:
        """Return a stored document, or `default` if it has never been saved."""

    @abstractmethod
    def save(self, name: str, value: Any) -> None:
        """Durably replace a stored document."""


class JsonStorage(Storage):
    def __init__(self, directory: str | os.PathLike = "state") -> None:
        self.directory = Path(directory)

    def load(self, name: str, default: Any) -> Any:
        path = self.directory / f"{name}.json"
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            # Treating a corrupt file as empty would re-seed and silently lose
            # history, so stop and make a human look at it.
            raise StateError(f"{path} is corrupt: {exc}") from exc

    def save(self, name: str, value: Any) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{name}.json"
        # Sorted, indented output gives small diffs and unchanged bytes when nothing
        # changed, which is what lets the workflow skip empty commits.
        text = json.dumps(value, indent=0, sort_keys=True, ensure_ascii=False) + "\n"
        if path.exists() and path.read_text(encoding="utf-8") == text:
            return
        fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise


class MemoryStorage(Storage):
    """Used by tests and by dry runs, which must never change real state."""

    def __init__(self, seed: dict[str, Any] | None = None) -> None:
        self.docs = json.loads(json.dumps(seed or {}))

    def load(self, name: str, default: Any) -> Any:
        return json.loads(json.dumps(self.docs[name])) if name in self.docs else default

    def save(self, name: str, value: Any) -> None:
        self.docs[name] = json.loads(json.dumps(value))


class State:
    """Typed view of everything the bot remembers between runs."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        seen = storage.load("seen", {})
        self.stories: dict[str, dict] = seen.get("stories", {})
        # Every CISA KEV ID ever seen. Deliberately never pruned: the catalog always
        # holds its full history, so pruning would make old entries look new again.
        self.kev_known: set[str] = set(seen.get("kev_known", []))
        self.seeded_sources: set[str] = set(seen.get("seeded_sources", []))
        self.meta: dict[str, Any] = seen.get("meta", {})
        self.digest_queue: list[dict] = storage.load("digest_queue", [])
        self.pending_alerts: list[dict] = storage.load("pending_alerts", [])

    @property
    def is_empty(self) -> bool:
        return not (self.stories or self.kev_known or self.seeded_sources)

    def save(self) -> None:
        self.storage.save("seen", {
            "stories": self.stories,
            "kev_known": sorted(self.kev_known),
            "seeded_sources": sorted(self.seeded_sources),
            "meta": self.meta,
        })
        self.storage.save("digest_queue", self.digest_queue)
        self.storage.save("pending_alerts", self.pending_alerts)

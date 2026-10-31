"""Hardened HTTP GET: timeouts, size cap, http(s) only, retries with backoff."""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)

# Some publishers (The Verge among them) reject "python-requests" in the User-Agent.
USER_AGENT = "Mozilla/5.0 (compatible; newsbot/1.0; personal security news monitor)"
RETRY_STATUS = {429, 500, 502, 503, 504}


class FetchError(Exception):
    """Message holds only the host and a reason, never a query string or header."""


class HttpClient:
    def __init__(
        self,
        timeout: float = 20,
        retries: int = 2,
        backoff: float = 2,
        max_bytes: int = 10_000_000,
        session: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        deadline: float | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_bytes = max_bytes
        self.session = session or requests.Session()
        self.sleep = sleep
        self.deadline = deadline  # time.monotonic() value; no new attempts after this

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        retry_status: set[int] | None = None,
        secret_headers: bool = False,
    ) -> bytes:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise FetchError(f"refused non-http(s) scheme: {parts.scheme}")
        host = parts.netloc
        retryable = RETRY_STATUS | (retry_status or set())
        merged = {"User-Agent": USER_AGENT, **(headers or {})}
        last_error = "no attempt made"
        for attempt in range(self.retries + 1):
            if self.expired():
                raise FetchError(f"{host}: run time budget exhausted ({last_error})")
            if attempt:
                self.sleep(self.backoff * 2 ** (attempt - 1))
            try:
                return self._attempt(
                    url, params, merged, timeout or self.timeout,
                    max_bytes or self.max_bytes, retryable, secret_headers,
                )
            except _Retryable as exc:
                last_error = str(exc)
                log.debug("%s: attempt %d failed: %s", host, attempt + 1, last_error)
            except requests.RequestException as exc:
                # The exception text can embed the full URL; keep only its type.
                last_error = type(exc).__name__
        raise FetchError(f"{host}: {last_error}")

    def _attempt(self, url, params, headers, timeout, max_bytes, retryable, secret_headers) -> bytes:
        host = urlsplit(url).netloc
        # Never follow redirects with an API key attached: a redirect could leak it elsewhere.
        resp = self.session.get(
            url, params=params, headers=headers, timeout=timeout,
            stream=True, allow_redirects=not secret_headers,
        )
        try:
            final = getattr(resp, "url", url) or url
            if urlsplit(final).scheme not in ("http", "https"):
                raise FetchError(f"{host}: redirected to a non-http(s) URL")
            if resp.status_code in retryable:
                raise _Retryable(f"HTTP {resp.status_code}")
            if resp.status_code != 200:
                raise FetchError(f"{host}: HTTP {resp.status_code}")
            started = time.monotonic()
            chunks, total = [], 0
            for chunk in resp.iter_content(65536):
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"{host}: response exceeds {max_bytes} bytes")
                # `timeout` limits each read, so a slow-drip server needs a wall clock too.
                if time.monotonic() - started > timeout * 3:
                    raise _Retryable("body download too slow")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            resp.close()

    def get_json(self, url: str, **kwargs: Any) -> Any:
        body = self.get(url, **kwargs)
        try:
            return json.loads(body)
        except ValueError as exc:
            raise FetchError(f"{urlsplit(url).netloc}: invalid JSON") from exc


class _Retryable(Exception):
    pass

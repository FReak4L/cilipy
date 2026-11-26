"""Tier 1: Official Google Custom Search JSON API v1 Key Pool with 00:00 UTC quota reset."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from curl_cffi.requests import AsyncSession
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from core.exceptions import (
    EmptyResultError,
    EngineDegradedError,
    GoogleQuotaExhaustedError,
    TransportResetError,
)
from core.models import SearchResult
from engine.base import BaseSearchEngine
from plugins.google.common import (
    GOOGLE_CSE_QUOTA_REASONS,
    GoogleCSECredential,
    GoogleLocaleConfig,
    unwrap_google_url,
)
from transport.http_client import CurlError
from transport.token_bucket import TokenBucketRateLimiter

logger = logging.getLogger("hybrid_search.v3.plugins.google.cse")


def next_utc_midnight_timestamp() -> float:
    """Compute Unix timestamp for the next 00:00:05 UTC quota reset boundary."""
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=5, microsecond=0
    )
    return tomorrow.timestamp()


class GoogleCSEKeyPool:
    """
    Async-safe round-robin credential pool for Google Custom Search JSON API v1.
    Tracks daily quota per `(api_key, cx)` pair and synchronizes resets at 00:00 UTC.
    """

    def __init__(self, credentials: Sequence[GoogleCSECredential]) -> None:
        self._credentials: list[GoogleCSECredential] = [
            c.model_copy(
                update={
                    "quota_reset_utc": (
                        c.quota_reset_utc
                        if c.quota_reset_utc > 0.0
                        else next_utc_midnight_timestamp()
                    )
                }
            )
            for c in credentials
        ]
        self._rr_cursor: int = 0
        self._lock = asyncio.Lock()

    @property
    def size(self) -> int:
        return len(self._credentials)

    def _refresh_utc_resets(self) -> None:
        now = time.time()
        next_reset = next_utc_midnight_timestamp()
        for cred in self._credentials:
            if cred.quota_reset_utc > 0.0 and now >= cred.quota_reset_utc:
                cred.used_today = 0
                cred.quota_reset_utc = next_reset
                if now >= cred.cooldown_until:
                    cred.last_error = ""

    async def acquire(
        self, exclude_keys: set[str] | None = None
    ) -> GoogleCSECredential | None:
        excluded = exclude_keys or set()
        async with self._lock:
            self._refresh_utc_resets()
            n = len(self._credentials)
            if n == 0:
                return None

            for offset in range(n):
                idx = (self._rr_cursor + offset) % n
                cred = self._credentials[idx]
                if cred.is_available and cred.api_key not in excluded:
                    self._rr_cursor = (idx + 1) % n
                    cred.used_today += 1
                    return cred
            return None

    async def mark_quota_exhausted(
        self,
        api_key: str,
        reason: str = "dailyLimitExceeded",
    ) -> None:
        async with self._lock:
            reset_ts = next_utc_midnight_timestamp()
            for cred in self._credentials:
                if cred.api_key == api_key:
                    cred.used_today = cred.daily_quota_limit
                    cred.cooldown_until = reset_ts
                    cred.quota_reset_utc = reset_ts
                    cred.last_error = reason
                    logger.warning(
                        "[google_cse] Credential %s exhausted (%s); rotated until 00:00 UTC.",
                        cred.redacted_label,
                        reason,
                    )
                    return

    async def mark_transient_cooldown(
        self,
        api_key: str,
        seconds: float = 60.0,
        reason: str = "rateLimitExceeded",
    ) -> None:
        async with self._lock:
            until = time.time() + seconds
            for cred in self._credentials:
                if cred.api_key == api_key:
                    cred.cooldown_until = max(cred.cooldown_until, until)
                    cred.last_error = reason
                    return

    async def mark_invalid(self, api_key: str, reason: str) -> None:
        async with self._lock:
            for cred in self._credentials:
                if cred.api_key == api_key:
                    cred.disabled = True
                    cred.last_error = reason
                    logger.error(
                        "[google_cse] Disabling invalid credential %s: %s",
                        cred.redacted_label,
                        reason,
                    )
                    return

    async def total_remaining_quota(self) -> int:
        async with self._lock:
            self._refresh_utc_resets()
            return sum(c.remaining_quota for c in self._credentials if c.is_available)


class GoogleCSEPlugin(BaseSearchEngine):
    """Tier 1 Plugin: Official Google Custom Search JSON API v1 with round-robin pool."""

    name = "google_cse"
    engine_family = "google_cse"
    base_priority = 1
    API_ENDPOINT = "https://www.googleapis.com/customsearch/v1"
    MAX_RESULTS_PER_CALL = 10
    API_MAX_START_OFFSET = 91

    def __init__(
        self,
        key_pool: GoogleCSEKeyPool | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        locale: GoogleLocaleConfig | None = None,
        timeout: float = 12.0,
        max_retries: int = 3,
        base_priority: int = 1,
    ) -> None:
        self.key_pool = key_pool or GoogleCSEKeyPool([])
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.locale = locale or GoogleLocaleConfig()
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_priority = base_priority

    @staticmethod
    def _extract_api_error_reason(payload: Any) -> tuple[str, str]:
        if not isinstance(payload, dict):
            return "", ""
        err = payload.get("error")
        if not isinstance(err, dict):
            return "", ""
        message = str(err.get("message") or "")
        errors = err.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            return str(errors[0].get("reason") or ""), message
        return str(err.get("status") or ""), message

    async def _fetch_page(
        self,
        session: AsyncSession,
        query: str,
        start_index: int,
        num_items: int,
    ) -> list[SearchResult]:
        if self.key_pool.size == 0:
            raise GoogleQuotaExhaustedError("Google CSE pool has no configured credentials.")

        tried_keys: set[str] = set()

        while True:
            cred = await self.key_pool.acquire(exclude_keys=tried_keys)
            if cred is None:
                raise GoogleQuotaExhaustedError(
                    "All Google CSE API keys are exhausted or in cooldown; failing over."
                )

            params: dict[str, str] = {
                "key": cred.api_key,
                "cx": cred.cx,
                "q": query,
                "num": str(max(1, min(self.MAX_RESULTS_PER_CALL, num_items))),
                "start": str(start_index),
                "hl": self.locale.hl,
                "gl": self.locale.gl,
                "safe": self.locale.safe,
                "filter": self.locale.filter_duplicates,
            }

            async def _dispatch_once() -> Any:
                async with self.rate_limiter.throttle(self.engine_family):
                    try:
                        return await session.get(
                            self.API_ENDPOINT,
                            params=params,
                            headers={"Accept": "application/json"},
                        )
                    except (CurlError, TimeoutError, OSError) as exc:
                        raise TransportResetError(
                            f"Google CSE network error: {exc}"
                        ) from exc

            resp: Any = None
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_random_exponential(multiplier=0.8, max=6.0),
                retry=retry_if_exception_type((TransportResetError, EngineDegradedError)),
                reraise=True,
            ):
                with attempt:
                    resp = await _dispatch_once()
                    if resp.status_code >= 500:
                        raise EngineDegradedError(
                            f"Google CSE server error HTTP {resp.status_code}",
                            status_code=resp.status_code,
                        )

            assert resp is not None
            try:
                payload = resp.json()
            except ValueError as exc:
                raise EngineDegradedError(f"Google CSE invalid JSON: {exc}") from exc

            if resp.status_code == 200:
                raw_items = payload.get("items") or []
                parsed_results: list[SearchResult] = []
                for item in raw_items:
                    if not isinstance(item, dict):
                        continue
                    url = unwrap_google_url(str(item.get("link") or ""))
                    title = " ".join(str(item.get("title") or "").split())
                    snippet = " ".join(str(item.get("snippet") or "").split())
                    if url and title:
                        parsed_results.append(
                            SearchResult(
                                rank=len(parsed_results) + 1,
                                title=title[:500],
                                url=url[:2048],
                                snippet=snippet[:4000],
                                engine="google:cse",
                                query=query,
                            )
                        )
                return parsed_results

            reason, message = self._extract_api_error_reason(payload)
            tried_keys.add(cred.api_key)

            if resp.status_code == 429 or reason in GOOGLE_CSE_QUOTA_REASONS:
                if "rateLimit" in reason and "daily" not in reason.lower():
                    await self.key_pool.mark_transient_cooldown(
                        cred.api_key, seconds=60.0, reason=reason
                    )
                else:
                    await self.key_pool.mark_quota_exhausted(
                        cred.api_key, reason=reason or f"HTTP {resp.status_code}"
                    )
                continue

            if resp.status_code in (400, 403) and any(
                token in (reason + " " + message).lower()
                for token in ("keyinvalid", "api key not valid", "accessnotconfigured")
            ):
                await self.key_pool.mark_invalid(cred.api_key, reason=message or reason)
                continue

            raise EngineDegradedError(
                f"Google CSE error HTTP {resp.status_code} ({reason}): {message}",
                status_code=resp.status_code,
            )

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        if self.key_pool.size == 0:
            raise GoogleQuotaExhaustedError("Google CSE has 0 configured credentials.")

        collected: list[SearchResult] = []
        seen_urls: set[str] = set()
        pages_to_fetch = min(max(1, pagination_depth), 10)

        async with AsyncSession(timeout=self.timeout) as session:
            for page_idx in range(pages_to_fetch):
                start_index = 1 + (page_idx * self.MAX_RESULTS_PER_CALL)
                if start_index > self.API_MAX_START_OFFSET:
                    break

                remaining = max_results - len(collected)
                if remaining <= 0:
                    break

                page_items = await self._fetch_page(
                    session=session,
                    query=query,
                    start_index=start_index,
                    num_items=min(self.MAX_RESULTS_PER_CALL, remaining),
                )
                if not page_items:
                    break

                added = 0
                for item in page_items:
                    dedup_key = item.url.rstrip("/").lower()
                    if dedup_key in seen_urls:
                        continue
                    seen_urls.add(dedup_key)
                    collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                    added += 1
                    if len(collected) >= max_results:
                        return collected

                if added == 0 or len(page_items) < self.MAX_RESULTS_PER_CALL:
                    break

                await asyncio.sleep(random.uniform(0.35, 0.75))

        if not collected:
            raise EmptyResultError(f"Google CSE returned 0 results for '{query}'")
        return collected

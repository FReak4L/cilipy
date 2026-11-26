"""Persistent asynchronous SQLite query cache (aiosqlite + SHA-256 + TTL)."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Sequence
from pathlib import Path

import aiosqlite

from core.models import SEARCH_RESULT_LIST_ADAPTER, SearchResult

logger = logging.getLogger("hybrid_search.v3.cache")


class PipelineCacheManager:
    """
    Persistent SQLite cache backed by `aiosqlite` storing SHA-256 keyed query responses
    with configurable TTL to eliminate redundant upstream traffic.
    """

    def __init__(
        self,
        db_path: Path = Path("search_cache.db"),
        ttl_seconds: int = 86400,
        enabled: bool = True,
    ) -> None:
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled and ttl_seconds > 0
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    @staticmethod
    def compute_key(query: str, engine_scope: str = "global") -> str:
        normalized = " ".join(query.strip().lower().split())
        digest_input = f"{engine_scope.lower()}::{normalized}".encode("utf-8")
        return hashlib.sha256(digest_input).hexdigest()

    async def initialize(self) -> None:
        if not self.enabled:
            return
        self._conn = await aiosqlite.connect(str(self.db_path))
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS search_cache (
                query_hash TEXT PRIMARY KEY,
                normalized_query TEXT NOT NULL,
                engine_scope TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
            """
        )
        await self._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_search_cache_expires
            ON search_cache (expires_at)
            """
        )
        await self._conn.commit()
        await self.purge_expired()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def purge_expired(self) -> int:
        if not self.enabled or self._conn is None:
            return 0
        now = time.time()
        async with self._lock:
            cursor = await self._conn.execute(
                "DELETE FROM search_cache WHERE expires_at <= ?",
                (now,),
            )
            await self._conn.commit()
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    async def get(
        self,
        query: str,
        engine_scope: str = "global",
    ) -> list[SearchResult] | None:
        if not self.enabled or self._conn is None:
            return None

        key = self.compute_key(query, engine_scope)
        now = time.time()
        async with self._lock:
            cursor = await self._conn.execute(
                "SELECT payload_json, expires_at FROM search_cache WHERE query_hash = ?",
                (key,),
            )
            row = await cursor.fetchone()
            await cursor.close()

        if row is None:
            return None

        payload_json, expires_at = str(row[0]), float(row[1])
        if expires_at <= now:
            async with self._lock:
                await self._conn.execute(
                    "DELETE FROM search_cache WHERE query_hash = ?",
                    (key,),
                )
                await self._conn.commit()
            return None

        try:
            return SEARCH_RESULT_LIST_ADAPTER.validate_json(payload_json)
        except Exception as exc:
            logger.warning("[cache] Corrupt cache entry for key %s: %s", key[:12], exc)
            return None

    async def set(
        self,
        query: str,
        results: Sequence[SearchResult],
        engine_scope: str = "global",
    ) -> None:
        if not self.enabled or self._conn is None or not results:
            return

        key = self.compute_key(query, engine_scope)
        normalized = " ".join(query.strip().lower().split())
        now = time.time()
        expires_at = now + float(self.ttl_seconds)
        serialized = SEARCH_RESULT_LIST_ADAPTER.dump_json(list(results)).decode("utf-8")

        async with self._lock:
            await self._conn.execute(
                """
                INSERT OR REPLACE INTO search_cache
                (query_hash, normalized_query, engine_scope, payload_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key, normalized, engine_scope, serialized, now, expires_at),
            )
            await self._conn.commit()

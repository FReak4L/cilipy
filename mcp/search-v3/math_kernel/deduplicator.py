"""Formulation 4: 64-Bit SimHash (Hamming <= 3) & Token-Level Jaccard (J >= 0.85) Deduplicator."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from core.constants import DEFAULT_JACCARD_THRESHOLD, DEFAULT_SIMHASH_MAX_HAMMING
from core.models import DeduplicationStats

T = TypeVar("T")

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize_text(text: str) -> list[str]:
    """Deterministic lowercased alphanumeric tokenization with zero external NLP deps."""
    if not text:
        return []
    return _TOKEN_RE.findall(text.lower())


def _token_hash64(token: str) -> int:
    """Deterministic cross-process 64-bit token digest via BLAKE2b."""
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def compute_simhash64(text: str) -> int:
    """
    Compute the exact 64-bit SimHash fingerprint for document text:
        V_i = sum_{w in D} weight(w) * sign_hash_i(w),   i in 0..63
        SimHash(D) = sum_{i=0}^{63} [V_i > 0] * 2^i
    """
    tokens = tokenize_text(text)
    if not tokens:
        return 0

    weights = Counter(tokens)
    vector = [0] * 64
    for word, weight in weights.items():
        h = _token_hash64(word)
        for bit_idx in range(64):
            if (h >> bit_idx) & 1:
                vector[bit_idx] += weight
            else:
                vector[bit_idx] -= weight

    fingerprint = 0
    for bit_idx in range(64):
        if vector[bit_idx] > 0:
            fingerprint |= 1 << bit_idx
    return fingerprint


def hamming_distance64(hash_a: int, hash_b: int) -> int:
    """Exact Hamming distance between two 64-bit integer fingerprints."""
    mask = (1 << 64) - 1
    return ((hash_a & mask) ^ (hash_b & mask)).bit_count()


def jaccard_similarity(tokens_a: set[str] | frozenset[str], tokens_b: set[str] | frozenset[str]) -> float:
    """Exact token-level Jaccard overlap J(S1, S2) = |S1 ∩ S2| / |S1 ∪ S2|."""
    if not tokens_a and not tokens_b:
        return 0.0
    union_len = len(tokens_a | tokens_b)
    if union_len == 0:
        return 0.0
    return len(tokens_a & tokens_b) / union_len


@dataclass(frozen=True, slots=True)
class DeduplicationDecision:
    """Result of checking a candidate document against the deduplicator index."""

    is_duplicate: bool
    reason: Literal["unique", "url_exact", "simhash", "jaccard"]
    simhash: int
    min_hamming: int | None = None
    max_jaccard: float = 0.0


class SimHashJaccardDeduplicator:
    """
    Information-theoretic deduplicator combining:
      1. Canonical URL exact match
      2. 64-bit SimHash Hamming distance <= 3 over (title + snippet)
      3. Token-level Jaccard similarity J(S1, S2) >= 0.85
    """

    def __init__(
        self,
        *,
        max_hamming: int = DEFAULT_SIMHASH_MAX_HAMMING,
        jaccard_threshold: float = DEFAULT_JACCARD_THRESHOLD,
        min_tokens_for_fuzzy: int = 3,
    ) -> None:
        if not (0 <= max_hamming <= 64):
            raise ValueError("max_hamming must be between 0 and 64.")
        if not (0.0 <= jaccard_threshold <= 1.0):
            raise ValueError("jaccard_threshold must be between 0.0 and 1.0.")

        self.max_hamming = int(max_hamming)
        self.jaccard_threshold = float(jaccard_threshold)
        self.min_tokens_for_fuzzy = max(1, int(min_tokens_for_fuzzy))

        self._seen_urls: set[str] = set()
        self._fingerprints: list[int] = []
        self._token_sets: list[frozenset[str]] = []

    def reset(self) -> None:
        self._seen_urls.clear()
        self._fingerprints.clear()
        self._token_sets.clear()

    @staticmethod
    def _normalize_url_key(url: str) -> str:
        return url.strip().rstrip("/").lower()

    def check_and_add(
        self,
        *,
        title: str,
        snippet: str = "",
        url: str = "",
    ) -> DeduplicationDecision:
        """Evaluate whether a document duplicates any previously admitted document."""
        url_key = self._normalize_url_key(url) if url else ""
        combined_text = f"{title} {snippet}".strip()
        tokens = tokenize_text(combined_text)
        token_set = frozenset(tokens)
        fingerprint = compute_simhash64(combined_text)

        # 1. Exact canonical URL deduplication
        if url_key and url_key in self._seen_urls:
            return DeduplicationDecision(
                is_duplicate=True,
                reason="url_exact",
                simhash=fingerprint,
                min_hamming=0,
                max_jaccard=1.0,
            )

        # 2. Content-based 64-bit SimHash + Jaccard deduplication
        min_hamming: int | None = None
        max_jaccard = 0.0

        if len(token_set) >= self.min_tokens_for_fuzzy:
            for prev_fp, prev_tokens in zip(self._fingerprints, self._token_sets, strict=True):
                dist = hamming_distance64(fingerprint, prev_fp)
                if min_hamming is None or dist < min_hamming:
                    min_hamming = dist
                if dist <= self.max_hamming:
                    return DeduplicationDecision(
                        is_duplicate=True,
                        reason="simhash",
                        simhash=fingerprint,
                        min_hamming=dist,
                        max_jaccard=jaccard_similarity(token_set, prev_tokens),
                    )

                sim = jaccard_similarity(token_set, prev_tokens)
                if sim > max_jaccard:
                    max_jaccard = sim
                if sim >= self.jaccard_threshold:
                    return DeduplicationDecision(
                        is_duplicate=True,
                        reason="jaccard",
                        simhash=fingerprint,
                        min_hamming=dist,
                        max_jaccard=sim,
                    )

        # Unique: admit into index
        if url_key:
            self._seen_urls.add(url_key)
        if len(token_set) >= self.min_tokens_for_fuzzy:
            self._fingerprints.append(fingerprint)
            self._token_sets.append(token_set)

        return DeduplicationDecision(
            is_duplicate=False,
            reason="unique",
            simhash=fingerprint,
            min_hamming=min_hamming,
            max_jaccard=max_jaccard,
        )

    def deduplicate_results(
        self,
        results: Sequence[T],
    ) -> tuple[list[T], DeduplicationStats]:
        """Deduplicate a sequence of SearchResult-like objects and return (kept, stats)."""
        kept: list[T] = []
        dropped_url = 0
        dropped_simhash = 0
        dropped_jaccard = 0

        for item in results:
            title = str(getattr(item, "title", ""))
            snippet = str(getattr(item, "snippet", ""))
            url = str(getattr(item, "url", ""))

            decision = self.check_and_add(title=title, snippet=snippet, url=url)
            if not decision.is_duplicate:
                kept.append(item)
            elif decision.reason == "url_exact":
                dropped_url += 1
            elif decision.reason == "simhash":
                dropped_simhash += 1
            elif decision.reason == "jaccard":
                dropped_jaccard += 1

        stats = DeduplicationStats(
            input_count=len(results),
            kept_count=len(kept),
            dropped_url_exact=dropped_url,
            dropped_simhash=dropped_simhash,
            dropped_jaccard=dropped_jaccard,
        )
        return kept, stats

"""
Lean Pure-Mathematics & NLP Optimization Kernel (`math_nlp_kernel.py`).

Zero bloat, zero heuristic guessing, zero neural-network dependencies.
Unifies the four exact mathematical utilities:
  1. Thompson Sampling Beta(α, β) Multi-Armed Bandit Dispatching
  2. Poisson Inter-Arrival Pacing Exp(λ) with Rolling Dynamic Hazard Rate
  3. Deterministic Boolean AST Truth-Table Verification over B = {0, 1}
  4. 64-Bit SimHash (Hamming <= 3) & Token Jaccard (J >= 0.85) Deduplication
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TypeVar

from core.constants import (
    DEFAULT_JACCARD_THRESHOLD,
    DEFAULT_POISSON_MEAN_DELAY_SECONDS,
    DEFAULT_SIMHASH_MAX_HAMMING,
)
from core.models import DeduplicationStats
from math_kernel.ast_boolean import (
    BooleanASTParser,
    CompiledBooleanAST,
    compile_boolean_query,
)
from math_kernel.bandit_scheduler import BetaArmState, ThompsonSamplingScheduler
from math_kernel.deduplicator import (
    DeduplicationDecision,
    SimHashJaccardDeduplicator,
    compute_simhash64,
    hamming_distance64,
    jaccard_similarity,
)
from math_kernel.pacing_poisson import DynamicPoissonPacer

T = TypeVar("T")


class MathNLPKernel:
    """Compact unified facade wiring the four pure-math & NLP kernel primitives."""

    def __init__(
        self,
        *,
        arms: Iterable[str] = (),
        poisson_mean_delay: float = DEFAULT_POISSON_MEAN_DELAY_SECONDS,
        simhash_max_hamming: int = DEFAULT_SIMHASH_MAX_HAMMING,
        jaccard_threshold: float = DEFAULT_JACCARD_THRESHOLD,
        seed: int | None = None,
    ) -> None:
        self.bandit = ThompsonSamplingScheduler(arms=arms, seed=seed)
        self.pacer = DynamicPoissonPacer(mean_delay_seconds=poisson_mean_delay, seed=seed)
        self.ast_parser = BooleanASTParser()
        self.deduplicator = SimHashJaccardDeduplicator(
            max_hamming=simhash_max_hamming,
            jaccard_threshold=jaccard_threshold,
        )

    def compile_query(self, query: str) -> CompiledBooleanAST:
        return self.ast_parser.parse(query)

    def filter_strict(self, query: str, candidates: Sequence[T]) -> tuple[list[T], int]:
        ast = self.compile_query(query)
        return ast.filter_documents(candidates)

    def deduplicate(self, items: Sequence[T]) -> tuple[list[T], DeduplicationStats]:
        return self.deduplicator.deduplicate_results(items)


__all__ = [
    "BetaArmState",
    "BooleanASTParser",
    "CompiledBooleanAST",
    "DeduplicationDecision",
    "DynamicPoissonPacer",
    "MathNLPKernel",
    "SimHashJaccardDeduplicator",
    "ThompsonSamplingScheduler",
    "compile_boolean_query",
    "compute_simhash64",
    "hamming_distance64",
    "jaccard_similarity",
]

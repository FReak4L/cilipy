"""Formulation 1: Thompson Sampling over Beta(alpha, beta) for Multi-Armed Engine & Proxy Selection."""

from __future__ import annotations

import random
import threading
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(slots=True)
class BetaArmState:
    """Bernoulli arm posterior state θ_k ~ Beta(α_k, β_k) with uniform prior Beta(1, 1)."""

    arm_id: str
    alpha: float = 1.0
    beta: float = 1.0
    pulls: int = 0
    successes: int = 0
    rate_limits: int = 0
    network_drops: int = 0
    other_failures: int = 0

    @property
    def posterior_mean(self) -> float:
        """Expected success probability E[θ_k] = α / (α + β)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def posterior_variance(self) -> float:
        """Posterior variance Var[θ_k] = αβ / ((α + β)^2 (α + β + 1))."""
        total = self.alpha + self.beta
        return (self.alpha * self.beta) / (total * total * (total + 1.0))


class ThompsonSamplingScheduler:
    """
    Multi-Armed Bandit scheduler using exact Thompson Sampling over Beta(α_k, β_k):
      - Uniform prior: α_k = 1, β_k = 1.
      - Dispatch: sample θ̂_k ~ Beta(α_k, β_k), choose k* = argmax_k θ̂_k.
      - Update rules:
          * HTTP 200 and yield >= 1        -> α_k <- α_k + 1
          * HTTP 429 or network drop       -> β_k <- β_k + 2 (double penalty for fast backoff)
          * Empty yield / other failure    -> β_k <- β_k + 1
    """

    def __init__(
        self,
        arms: Iterable[str] = (),
        *,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        seed: int | None = None,
    ) -> None:
        if prior_alpha <= 0.0 or prior_beta <= 0.0:
            raise ValueError("Beta prior parameters alpha and beta must be strictly positive.")
        self._prior_alpha = float(prior_alpha)
        self._prior_beta = float(prior_beta)
        self._rng = random.Random(seed)
        self._lock = threading.RLock()
        self._arms: dict[str, BetaArmState] = {}
        for arm_id in arms:
            self.register_arm(arm_id)

    def register_arm(self, arm_id: str) -> BetaArmState:
        """Register an arm with Beta(prior_alpha, prior_beta) if not already tracked."""
        with self._lock:
            existing = self._arms.get(arm_id)
            if existing is not None:
                return existing
            state = BetaArmState(
                arm_id=arm_id,
                alpha=self._prior_alpha,
                beta=self._prior_beta,
            )
            self._arms[arm_id] = state
            return state

    def remove_arm(self, arm_id: str) -> None:
        with self._lock:
            self._arms.pop(arm_id, None)

    def set_arm_params(self, arm_id: str, alpha: float, beta: float) -> None:
        """Restore or seed Beta(alpha, beta) parameters for an arm in place."""
        with self._lock:
            state = self._arms.get(arm_id)
            if state is None:
                state = self.register_arm(arm_id)
            state.alpha = max(1.0, float(alpha))
            state.beta = max(1.0, float(beta))

    def get_arm(self, arm_id: str) -> BetaArmState:
        with self._lock:
            if arm_id not in self._arms:
                return self.register_arm(arm_id)
            state = self._arms[arm_id]
            return BetaArmState(
                arm_id=state.arm_id,
                alpha=state.alpha,
                beta=state.beta,
                pulls=state.pulls,
                successes=state.successes,
                rate_limits=state.rate_limits,
                network_drops=state.network_drops,
                other_failures=state.other_failures,
            )

    def snapshot(self) -> dict[str, BetaArmState]:
        """Return a thread-safe snapshot of all arm Beta posteriors."""
        with self._lock:
            return {arm_id: self.get_arm(arm_id) for arm_id in self._arms}

    def rank(
        self,
        available_arms: Iterable[str] | None = None,
        *,
        exclude: set[str] | None = None,
    ) -> list[tuple[str, float]]:
        """
        Sample θ̂_k ~ Beta(α_k, β_k) once per available arm and return arms ordered
        descending by sampled θ̂_k.
        """
        excluded = exclude or set()
        with self._lock:
            if available_arms is None:
                candidates = [k for k in self._arms if k not in excluded]
            else:
                candidates = []
                for arm_id in available_arms:
                    if arm_id in excluded:
                        continue
                    if arm_id not in self._arms:
                        self.register_arm(arm_id)
                    candidates.append(arm_id)

            if not candidates:
                return []

            sampled: list[tuple[str, float]] = [
                (
                    arm_id,
                    self._rng.betavariate(
                        self._arms[arm_id].alpha,
                        self._arms[arm_id].beta,
                    ),
                )
                for arm_id in candidates
            ]
            sampled.sort(key=lambda item: item[1], reverse=True)
            return sampled

    def select(
        self,
        available_arms: Iterable[str] | None = None,
        *,
        exclude: set[str] | None = None,
    ) -> str:
        """Select k* = argmax_k θ̂_k where θ̂_k ~ Beta(α_k, β_k)."""
        ranked = self.rank(available_arms=available_arms, exclude=exclude)
        if not ranked:
            raise ValueError("No available arms to select from.")
        return ranked[0][0]

    def update(
        self,
        arm_id: str,
        *,
        status_code: int | None = None,
        yield_count: int = 0,
        network_drop: bool = False,
    ) -> BetaArmState:
        """
        Apply the exact posterior update rule upon request completion:
          - status_code == 429 or network_drop -> β_k <- β_k + 2
          - status_code == 200 and yield >= 1  -> α_k <- α_k + 1
          - otherwise                          -> β_k <- β_k + 1
        """
        with self._lock:
            state = self._arms.get(arm_id)
            if state is None:
                state = self.register_arm(arm_id)

            state.pulls += 1
            if status_code == 429 or network_drop:
                state.beta += 2.0
                if status_code == 429:
                    state.rate_limits += 1
                if network_drop:
                    state.network_drops += 1
            elif status_code == 200 and yield_count >= 1:
                state.alpha += 1.0
                state.successes += 1
            else:
                state.beta += 1.0
                state.other_failures += 1

            return self.get_arm(arm_id)

    def record_success(self, arm_id: str, yield_count: int = 1) -> BetaArmState:
        return self.update(arm_id, status_code=200, yield_count=max(1, yield_count))

    def record_rate_limit(self, arm_id: str) -> BetaArmState:
        return self.update(arm_id, status_code=429, yield_count=0)

    def record_network_drop(self, arm_id: str) -> BetaArmState:
        return self.update(arm_id, status_code=None, yield_count=0, network_drop=True)

    def record_failure(self, arm_id: str) -> BetaArmState:
        return self.update(arm_id, status_code=500, yield_count=0, network_drop=False)

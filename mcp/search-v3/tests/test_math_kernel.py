"""Mathematical proof & unit tests for the Pure-Math & NLP Kernel (Formulations 1, 2, 4)."""

from __future__ import annotations

import math
import random
import unittest
from statistics import mean, stdev

from core.models import SearchResult
from math_kernel.bandit_scheduler import ThompsonSamplingScheduler
from math_kernel.deduplicator import (
    SimHashJaccardDeduplicator,
    compute_simhash64,
    hamming_distance64,
    jaccard_similarity,
    tokenize_text,
)
from math_kernel.math_nlp_kernel import MathNLPKernel
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.token_bucket import TokenBucketRateLimiter


class TestThompsonSamplingScheduler(unittest.TestCase):
    """Formulation 1: Thompson Sampling over Beta(α_k, β_k) proofs."""

    def test_uniform_prior_and_exact_update_rules(self) -> None:
        bandit = ThompsonSamplingScheduler(arms=["eng_a", "eng_b"], seed=123)
        arm_a = bandit.get_arm("eng_a")
        self.assertEqual(arm_a.alpha, 1.0)
        self.assertEqual(arm_a.beta, 1.0)
        self.assertAlmostEqual(arm_a.posterior_mean, 0.5, places=6)

        # HTTP 200 with yield >= 1 -> alpha += 1
        updated = bandit.update("eng_a", status_code=200, yield_count=5)
        self.assertEqual(updated.alpha, 2.0)
        self.assertEqual(updated.beta, 1.0)

        # HTTP 429 -> beta += 2 (double rate-limit penalty)
        updated_429 = bandit.update("eng_b", status_code=429, yield_count=0)
        self.assertEqual(updated_429.alpha, 1.0)
        self.assertEqual(updated_429.beta, 3.0)
        self.assertEqual(updated_429.rate_limits, 1)

        # Network drop -> beta += 2
        updated_drop = bandit.update("eng_b", status_code=None, yield_count=0, network_drop=True)
        self.assertEqual(updated_drop.beta, 5.0)
        self.assertEqual(updated_drop.network_drops, 1)

        # HTTP 200 with yield == 0 -> beta += 1
        updated_empty = bandit.update("eng_a", status_code=200, yield_count=0)
        self.assertEqual(updated_empty.alpha, 2.0)
        self.assertEqual(updated_empty.beta, 2.0)

    def test_multi_armed_bandit_convergence(self) -> None:
        """Verify Thompson Sampling converges onto the highest-yielding arm and avoids 429 arm."""
        rng = random.Random(2026)
        bandit = ThompsonSamplingScheduler(arms=["fast_ok", "mediocre", "rate_limited"], seed=99)
        true_probs = {"fast_ok": 0.85, "mediocre": 0.40, "rate_limited": 0.10}

        second_half_picks: dict[str, int] = {"fast_ok": 0, "mediocre": 0, "rate_limited": 0}
        total_rounds = 1000
        for step in range(total_rounds):
            chosen = bandit.select()
            if step >= total_rounds // 2:
                second_half_picks[chosen] += 1

            success = rng.random() < true_probs[chosen]
            if success:
                bandit.update(chosen, status_code=200, yield_count=3)
            elif chosen == "rate_limited":
                bandit.update(chosen, status_code=429, yield_count=0)
            else:
                bandit.update(chosen, status_code=200, yield_count=0)

        # Optimal arm must dominate the second half of dispatches (> 85%)
        self.assertGreater(second_half_picks["fast_ok"], 425)
        self.assertLess(second_half_picks["rate_limited"], 20)

        snap = bandit.snapshot()
        self.assertGreater(snap["fast_ok"].posterior_mean, 0.78)
        # Double 429 penalty suppresses the arm so fast it often stops after just 2-3 pulls (E[θ] <= 1/6)
        self.assertLessEqual(snap["rate_limited"].posterior_mean, 0.25)
        self.assertLess(snap["rate_limited"].pulls, 25)


class TestDynamicPoissonPacer(unittest.TestCase):
    """Formulation 2: Poisson inter-arrival Exp(λ) and dynamic hazard rate λ = λ_0 / (1 + 3φ)."""

    def test_exact_dynamic_hazard_rate_formula(self) -> None:
        pacer = DynamicPoissonPacer(mean_delay_seconds=2.0, seed=7)
        self.assertAlmostEqual(pacer.base_hazard_rate, 0.5, places=9)
        self.assertAlmostEqual(pacer.hazard_rate("g"), 0.5, places=9)

        # 2 failures out of 10 -> phi = 0.2 (not > 0.2) => lambda remains lambda_0 = 0.5
        for _ in range(8):
            pacer.record_success("g")
        for _ in range(2):
            pacer.record_failure("g")
        self.assertAlmostEqual(pacer.failure_rate("g"), 0.2, places=9)
        self.assertAlmostEqual(pacer.hazard_rate("g"), 0.5, places=9)

        # Push 1 more failure -> window of last 10 now has 3 failures => phi = 0.3 > 0.2
        pacer.record_failure("g")
        self.assertAlmostEqual(pacer.failure_rate("g"), 0.3, places=9)
        expected_lambda = 0.5 / (1.0 + 3.0 * 0.3)
        self.assertAlmostEqual(pacer.hazard_rate("g"), expected_lambda, places=9)
        self.assertAlmostEqual(pacer.expected_delay("g"), 1.0 / expected_lambda, places=9)

        # 5 failures / 5 successes in rolling window -> phi = 0.5 => lambda = 0.5 / 2.5 = 0.2, E[Δt] = 5.0s
        pacer2 = DynamicPoissonPacer(mean_delay_seconds=2.0, seed=7)
        for _ in range(5):
            pacer2.record_success("k")
            pacer2.record_failure("k")
        self.assertAlmostEqual(pacer2.failure_rate("k"), 0.5, places=9)
        self.assertAlmostEqual(pacer2.hazard_rate("k"), 0.2, places=9)
        self.assertAlmostEqual(pacer2.expected_delay("k"), 5.0, places=9)

    def test_exponential_distribution_goodness_of_fit(self) -> None:
        """Empirical mean, std, and CDF of 10,000 samples must match Exp(λ) closely."""
        pacer = DynamicPoissonPacer(mean_delay_seconds=2.0, seed=42)
        n = 10_000
        samples = [pacer.sample_delay("healthy") for _ in range(n)]

        # Theoretical mean = 1/λ = 2.0, std = 1/λ = 2.0
        self.assertTrue(all(s >= 0.0 for s in samples))
        self.assertAlmostEqual(mean(samples), 2.0, delta=0.06)
        self.assertAlmostEqual(stdev(samples), 2.0, delta=0.08)

        # Kolmogorov-Smirnov check against exact CDF F(x) = 1 - exp(-λx)
        lam = 0.5
        sorted_samples = sorted(samples)
        max_ks = 0.0
        for idx, x in enumerate(sorted_samples, start=1):
            empirical_cdf = idx / n
            theoretical_cdf = 1.0 - math.exp(-lam * x)
            max_ks = max(max_ks, abs(empirical_cdf - theoretical_cdf))
        self.assertLess(max_ks, 0.025)

        # Under degraded hazard (phi = 0.5 => λ = 0.2 => E[Δt] = 5.0)
        for _ in range(5):
            pacer.record_success("degraded")
            pacer.record_failure("degraded")
        degraded_samples = [pacer.sample_delay("degraded") for _ in range(5_000)]
        self.assertAlmostEqual(mean(degraded_samples), 5.0, delta=0.20)


class TestSimHashAndJaccardDeduplicator(unittest.TestCase):
    """Formulation 4: 64-bit SimHash (Hamming <= 3) & Token Jaccard (J >= 0.85) proofs."""

    def test_simhash_determinism_and_identical_detection(self) -> None:
        text = "Donate to Community Support using Braintree Hosted Fields Checkout"
        h1 = compute_simhash64(text)
        h2 = compute_simhash64(text)
        self.assertEqual(h1, h2)
        self.assertEqual(hamming_distance64(h1, h2), 0)
        self.assertGreater(h1, 0)
        self.assertLess(h1, 1 << 64)

    def test_jaccard_exact_formula_and_threshold(self) -> None:
        # 17 shared tokens out of 20 union tokens => J = 17/20 = 0.85 exact
        s1 = frozenset(f"w{i}" for i in range(20))
        s2 = frozenset(f"w{i}" for i in range(17))
        self.assertAlmostEqual(jaccard_similarity(s1, s2), 0.85, places=9)

        # 16 shared tokens out of 20 union => J = 0.80 < 0.85
        s3 = frozenset(f"w{i}" for i in range(16))
        self.assertAlmostEqual(jaccard_similarity(s1, s3), 0.80, places=9)

    def test_deduplicator_catches_exact_near_duplicate_and_keeps_distinct(self) -> None:
        deduper = SimHashJaccardDeduplicator(max_hamming=3, jaccard_threshold=0.85)

        r1 = SearchResult(
            rank=1,
            title="Braintree Developer Documentation Hosted Fields Guide",
            url="https://developer.paypal.com/braintree/docs/guides/hosted-fields",
            snippet="Configure Braintree hosted fields client token and secure payment inputs for web apps.",
            engine="searxng:brave",
            query="braintree hosted fields",
        )
        # Exact same URL with trailing slash
        r2_url_dup = r1.model_copy(
            update={"rank": 2, "url": "https://developer.paypal.com/braintree/docs/guides/hosted-fields/"}
        )
        # Different mirror URL, virtually identical title + snippet (1 token difference out of 20)
        r3_content_dup = SearchResult(
            rank=3,
            title="Braintree Developer Documentation Hosted Fields Guide",
            url="https://mirror.example.org/braintree/hosted-fields-guide",
            snippet="Configure Braintree hosted fields client token and secure payment inputs for modern web apps.",
            engine="curl_cffi:ddg_html",
            query="braintree hosted fields",
        )
        # Completely distinct content and URL
        r4_unique = SearchResult(
            rank=4,
            title="Python AsyncIO Event Loop Architecture and Coroutines",
            url="https://docs.python.org/3/library/asyncio.html",
            snippet="High-level asynchronous I/O primitives for concurrent network programming in Python.",
            engine="searxng:wikipedia",
            query="python asyncio",
        )

        kept, stats = deduper.deduplicate_results([r1, r2_url_dup, r3_content_dup, r4_unique])
        self.assertEqual(len(kept), 2)
        self.assertEqual([r.url for r in kept], [r1.url, r4_unique.url])
        self.assertEqual(stats.input_count, 4)
        self.assertEqual(stats.kept_count, 2)
        self.assertEqual(stats.dropped_url_exact, 1)
        self.assertEqual(stats.dropped_simhash + stats.dropped_jaccard, 1)

        # Also check tokenizer cleanliness
        self.assertEqual(tokenize_text("Hello, World! 123"), ["hello", "world", "123"])


class TestMathKernelFacadeAndTokenBucket(unittest.IsolatedAsyncioTestCase):
    async def test_math_nlp_kernel_facade_and_microsecond_bucket(self) -> None:
        kernel = MathNLPKernel(arms=["a", "b"], seed=11)
        self.assertIn(kernel.bandit.select(), ("a", "b"))
        self.assertAlmostEqual(kernel.pacer.base_hazard_rate, 0.5)

        limiter = TokenBucketRateLimiter(
            max_concurrency=2,
            tokens_per_second=1000.0,
            burst_capacity=2.0,
        )
        # First two burst acquisitions require 0 wait
        w1 = await limiter.acquire("fast")
        limiter.release()
        w2 = await limiter.acquire("fast")
        limiter.release()
        self.assertEqual(w1, 0.0)
        self.assertEqual(w2, 0.0)


if __name__ == "__main__":
    unittest.main()

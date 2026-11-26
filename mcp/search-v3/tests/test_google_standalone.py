"""Independent unit tests for the Standalone Google Search Federation Suite (all 4 tiers)."""

from __future__ import annotations

import time
import unittest

from core.exceptions import (
    CaptchaTriggeredError,
    EngineDegradedError,
    GoogleChallengeTriggeredError,
    GoogleDOMStructureChangedError,
    GoogleQuotaExhaustedError,
    GoogleRateLimitedError,
    GoogleSearchError,
    RateLimitedError,
)
from core.models import SearchResult
from engine.base import BaseSearchEngine
from engine.registry import EngineRegistry
from plugins.google import (
    GoogleBasicHtmlPlugin,
    GoogleCSECredential,
    GoogleCSEKeyPool,
    GoogleCSEPlugin,
    GoogleMobileDirectPlugin,
    GoogleMultiTierPlugin,
    GoogleSuiteConfig,
    GoogleWebDirectPlugin,
    build_chrome_headers,
    build_google_plugins,
    detect_google_block,
    unwrap_google_url,
)


class TestGoogleExceptionIdentityAndBlockClassifier(unittest.IsolatedAsyncioTestCase):
    """Verify the v2 split-identity bug is eliminated and RFC 6585 headers are honored."""

    async def test_single_canonical_exception_identity_with_registry(self) -> None:
        self.assertTrue(issubclass(GoogleRateLimitedError, GoogleSearchError))
        self.assertTrue(issubclass(GoogleRateLimitedError, RateLimitedError))
        self.assertTrue(issubclass(GoogleChallengeTriggeredError, GoogleSearchError))
        self.assertTrue(issubclass(GoogleChallengeTriggeredError, CaptchaTriggeredError))
        self.assertTrue(issubclass(GoogleQuotaExhaustedError, RateLimitedError))
        self.assertTrue(issubclass(GoogleDOMStructureChangedError, EngineDegradedError))

        registry = EngineRegistry(
            park_bot_threshold=2,
            park_rate_limit_threshold=2,
            park_seconds=60.0,
        )
        web_tier = GoogleWebDirectPlugin()
        mobile_tier = GoogleMobileDirectPlugin()
        registry.register(web_tier)
        registry.register(mobile_tier)

        # Simulate 2 HTTP 429s on web_tier -> must record rate_limits=2, beta=1+4=5.0, and park!
        await registry.record_failure(
            web_tier.name,
            GoogleRateLimitedError("HTTP 429", status_code=429, retry_after=30.0),
            latency_ms=120.0,
        )
        await registry.record_failure(
            web_tier.name,
            GoogleRateLimitedError("HTTP 429", status_code=429, retry_after=30.0),
            latency_ms=130.0,
        )

        # Simulate 2 /sorry/ challenges on mobile_tier -> must record bot_gates=2 and park!
        await registry.record_failure(
            mobile_tier.name,
            GoogleChallengeTriggeredError("sorry redirect"),
            latency_ms=80.0,
        )
        await registry.record_failure(
            mobile_tier.name,
            GoogleChallengeTriggeredError("sorry redirect"),
            latency_ms=90.0,
        )

        metrics_by_name = {m.engine: m for m in registry.snapshot_metrics()}
        self.assertEqual(metrics_by_name[web_tier.name].rate_limits, 2)
        self.assertEqual(metrics_by_name[web_tier.name].bandit_beta, 5.0)
        self.assertTrue(metrics_by_name[web_tier.name].parked)

        self.assertEqual(metrics_by_name[mobile_tier.name].bot_gates, 2)
        self.assertEqual(metrics_by_name[mobile_tier.name].bandit_beta, 5.0)
        self.assertTrue(metrics_by_name[mobile_tier.name].parked)

    def test_detect_google_block_rfc6585_and_false_positive_safety(self) -> None:
        # Valid full-size SERP with noscript enablejs boilerplate must pass
        valid_serp = (
            "<html><head><noscript>"
            '<meta http-equiv="refresh" content="0;url=/httpservice/retry/enablejs">'
            "</noscript></head><body>"
            + ("<!-- pad -->" * 450)
            + '<div class="MjjYud"><div class="tF2Cxc"><div class="yuRUbf">'
            '<a href="https://peps.python.org/pep-0492/"><h3>PEP 492 Coroutines</h3></a>'
            '</div><div class="VwiC3b">Native async coroutines in Python.</div>'
            "</div></div></body></html>"
        )
        detect_google_block(200, "https://www.google.com/search?q=pep+492", valid_serp)

        # HTTP 429 with RFC 6585 Retry-After header
        with self.assertRaises(GoogleRateLimitedError) as ctx:
            detect_google_block(
                429,
                "https://www.google.com/search?q=test",
                "",
                headers={"Retry-After": "45"},
            )
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.retry_after, 45.0)

        # /sorry/ challenge
        with self.assertRaises(GoogleChallengeTriggeredError):
            detect_google_block(
                200,
                "https://www.google.com/sorry/index?continue=https://www.google.com/",
                "unusual traffic",
            )

        # Small JS-interstitial stub
        with self.assertRaises(GoogleDOMStructureChangedError):
            detect_google_block(
                200,
                "https://www.google.com/search?q=test",
                '<meta http-equiv="refresh" content="0;url=/httpservice/retry/enablejs">',
            )


class TestGoogleFourTiersStandalone(unittest.IsolatedAsyncioTestCase):
    """Verify all 4 Google tiers instantiate, parse, rotate quotas, and failover independently."""

    async def test_all_four_tiers_instantiate_independently(self) -> None:
        cfg = GoogleSuiteConfig(
            cse_credentials=[
                GoogleCSECredential(api_key="AIzaSyTestKey0001", cx="cx_0001", daily_quota_limit=5)
            ]
        )
        tiers = build_google_plugins(config=cfg)
        self.assertEqual(
            [t.name for t in tiers],
            ["google_cse", "google_web_udm14", "google_mobile_web", "google_basic_html"],
        )
        self.assertIsInstance(tiers[0], GoogleCSEPlugin)
        self.assertIsInstance(tiers[1], GoogleWebDirectPlugin)
        self.assertIsInstance(tiers[2], GoogleMobileDirectPlugin)
        self.assertIsInstance(tiers[3], GoogleBasicHtmlPlugin)

    async def test_tier1_cse_key_pool_round_robin_and_utc_reset(self) -> None:
        past_ts = time.time() - 10.0
        pool = GoogleCSEKeyPool(
            [
                GoogleCSECredential(
                    api_key="AIzaSyKeyOne0001",
                    cx="cx_alpha_001",
                    daily_quota_limit=1,
                    used_today=1,
                    quota_reset_utc=past_ts,  # Expired boundary -> must reset to 0 on acquire
                ),
                GoogleCSECredential(
                    api_key="AIzaSyKeyTwo0002",
                    cx="cx_beta_002",
                    daily_quota_limit=1,
                ),
            ]
        )
        c1 = await pool.acquire()
        c2 = await pool.acquire()
        self.assertIsNotNone(c1)
        self.assertIsNotNone(c2)
        assert c1 is not None and c2 is not None
        self.assertNotEqual(c1.api_key, c2.api_key)
        self.assertIsNone(await pool.acquire())
        self.assertEqual(await pool.total_remaining_quota(), 0)

    def test_tier2_tier3_tier4_html_parsers_and_client_hints(self) -> None:
        # Tier 2: Desktop udm=14
        desktop_html = """
        <html><body>
          <div class="MjjYud"><div class="tF2Cxc">
            <div class="yuRUbf">
              <a href="https://docs.pydantic.dev/latest/"><h3>Pydantic v2 Documentation</h3></a>
            </div>
            <div class="VwiC3b">Data validation using Python type hints.</div>
          </div></div>
        </body></html>
        """
        r_web = GoogleWebDirectPlugin.parse_udm14_html(desktop_html, query="pydantic v2")
        self.assertEqual(len(r_web), 1)
        self.assertEqual(r_web[0].url, "https://docs.pydantic.dev/latest/")
        self.assertEqual(r_web[0].engine, "google:web_udm14")

        # Tier 3: Mobile Client-Hints & DOM parser
        mobile_headers = build_chrome_headers(mobile=True)
        self.assertEqual(mobile_headers["sec-ch-ua-mobile"], "?1")
        self.assertEqual(mobile_headers["sec-ch-ua-platform"], '"Android"')

        mobile_html = """
        <html><body>
          <div class="xpd">
            <a class="cz3goc" href="/url?q=https://fastapi.tiangolo.com/&amp;sa=U">
              <div role="heading">FastAPI Framework</div>
            </a>
            <div class="VwiC3b">Modern high-performance web framework for Python.</div>
          </div>
        </body></html>
        """
        r_mob = GoogleMobileDirectPlugin.parse_mobile_html(mobile_html, query="fastapi")
        self.assertEqual(len(r_mob), 1)
        self.assertEqual(r_mob[0].url, "https://fastapi.tiangolo.com/")
        self.assertEqual(r_mob[0].engine, "google:mobile_web")

        # Tier 4: Basic HTML gbv=1/gbv=2
        basic_html = """
        <html><body>
          <div class="Gx5Zad">
            <div class="egMi0">
              <a href="/url?q=https://www.python.org/downloads/&amp;sa=U">
                <div class="BNeawe vvjwJb">Download Python 3.12</div>
              </a>
            </div>
            <div class="BNeawe s3v9rd AP7Wnd">Official Python releases and source code.</div>
          </div>
        </body></html>
        """
        r_basic = GoogleBasicHtmlPlugin.parse_basic_html(basic_html, query="python 3.12", gbv_mode="1")
        self.assertEqual(len(r_basic), 1)
        self.assertEqual(r_basic[0].url, "https://www.python.org/downloads/")
        self.assertEqual(r_basic[0].engine, "google:basic_gbv1")

        # URL unwrapper check
        self.assertEqual(
            unwrap_google_url("/url?q=https://example.org/docs&sa=U"),
            "https://example.org/docs",
        )

    async def test_suite_facade_circuit_breaker_cascade(self) -> None:
        sample_result = SearchResult(
            rank=1,
            title="Python Official",
            url="https://www.python.org/",
            snippet="Welcome to Python.org",
            engine="google:mobile_web",
            query="python",
        )

        class _QuotaTier(BaseSearchEngine):
            name = "tier1_cse"
            engine_family = "cse"
            base_priority = 1

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                raise GoogleQuotaExhaustedError("daily quota reached")

        class _ChallengeTier(BaseSearchEngine):
            name = "tier2_web"
            engine_family = "web"
            base_priority = 2

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                raise GoogleChallengeTriggeredError("sorry challenge")

        class _HealthyTier(BaseSearchEngine):
            name = "tier3_mobile"
            engine_family = "mobile"
            base_priority = 3

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                return [sample_result]

        facade = GoogleMultiTierPlugin(
            [_HealthyTier(), _ChallengeTier(), _QuotaTier()],
            cooldown_seconds=60.0,
            use_thompson_sampling=False,
        )
        out = await facade.search("python")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].url, "https://www.python.org/")
        self.assertTrue(await facade.is_parked("tier1_cse"))
        self.assertTrue(await facade.is_parked("tier2_web"))
        self.assertFalse(await facade.is_parked("tier3_mobile"))


if __name__ == "__main__":
    unittest.main()

"""Shared Google Federation helpers: URL unwrapping, RFC 6585 block detection, Client-Hints & Domain Rotator."""

from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal
from urllib.parse import parse_qs, unquote, urlparse

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html
from pydantic import BaseModel, ConfigDict, Field, computed_field

from core.constants import (
    DEFAULT_GOOGLE_REGIONAL_DOMAINS,
    DESKTOP_CLIENT_PROFILES,
    GOOGLE_EXCLUDED_HOSTS,
    MOBILE_CLIENT_PROFILES,
)
from core.exceptions import (
    EmptyResultError,
    GoogleChallengeTriggeredError,
    GoogleDOMStructureChangedError,
    GoogleRateLimitedError,
)
from core.models import SearchResult
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.http_client import classify_http_response, parse_retry_after

logger = logging.getLogger("hybrid_search.v3.plugins.google")

DEFAULT_GOOGLE_CONSENT_COOKIES: dict[str, str] = {
    "SOCS": "CAESHAgBEhIaAB",
    "CONSENT": "PENDING+999",
}

TRUST_COOKIE_NAMES: frozenset[str] = frozenset({"AEC", "NID", "1P_JAR", "SOCS"})

GOOGLE_SORRY_SIGNATURES: tuple[str, ...] = (
    "sorry.google.com",
    "/sorry/index",
    "unusual traffic from your computer network",
    "our systems have detected unusual traffic",
    "to continue, please type the characters below",
    "g-recaptcha",
    'form id="captcha-form"',
)

GOOGLE_JS_GATE_SIGNATURES: tuple[str, ...] = (
    "/httpservice/retry/enablejs",
    'href="/httpservice/retry/enablejs',
    "if you're having trouble accessing google search",
    "sg_ss",
)

GOOGLE_NO_RESULTS_SIGNATURES: tuple[str, ...] = (
    "did not match any documents",
    "no results found for",
    "your search -",
    "suggestions:",
)

JS_INTERSTITIAL_MAX_BYTES: int = 5000

GOOGLE_CSE_QUOTA_REASONS: frozenset[str] = frozenset(
    {
        "dailyLimitExceeded",
        "quotaExceeded",
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "dailyLimitExceededUnreg",
    }
)

_GOOGLE_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>\s]+)',
    re.IGNORECASE,
)

_ORGANIC_HTML_MARKER_RE = re.compile(
    r'<h3\b|role=["\']heading["\']|class=["\'][^"\']*\b(?:MjjYud|tF2Cxc|Gx5Zad|xpd|ZINbbc|ezO2md|g)\b',
    re.IGNORECASE,
)

_ORGANIC_CSS_SELECTORS: tuple[str, ...] = (
    "div.MjjYud",
    "div.tF2Cxc",
    "div.g",
    "div.Gx5Zad",
    "div.xpd",
    'div[role="heading"]',
    "h3",
)

_CHROME_OMNIBOX_AQS_TEMPLATES: tuple[str, ...] = (
    "chrome..69i57j0i512l4j69i60l3.1842j0j7",
    "chrome..69i57j35i39j0i512l5j69i60.2134j0j7",
    "chrome..69i57j0i131i433i512j0i512l6.1520j0j4",
)


def is_google_host(host: str) -> bool:
    clean = host.lower().strip(".")
    if clean in GOOGLE_EXCLUDED_HOSTS:
        return True
    return bool(re.match(r"^(?:[a-z0-9-]+\.)?google\.[a-z]{2,3}(?:\.[a-z]{2})?$", clean))


def unwrap_google_url(raw_href: str) -> str:
    """Unwrap `/url?q=...`, `/url?url=...`, and `/interstitial?url=...` redirectors."""
    if not raw_href:
        return ""
    cleaned = raw_href.strip()

    if cleaned.startswith("/url?") or cleaned.startswith("/interstitial?"):
        cleaned = "https://www.google.com" + cleaned
    elif cleaned.startswith("//"):
        cleaned = "https:" + cleaned

    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()

    if is_google_host(host) and parsed.path in ("/url", "/interstitial", "/imgres"):
        qs = parse_qs(parsed.query)
        for param_key in ("q", "url", "imgrefurl"):
            vals = qs.get(param_key)
            if vals and vals[0].startswith(("http://", "https://")):
                return unquote(vals[0]).strip()
        return ""

    return cleaned


def is_valid_organic_url(
    url: str,
    excluded_hosts: frozenset[str] = GOOGLE_EXCLUDED_HOSTS,
) -> bool:
    """Verify URL is an absolute external HTTP/HTTPS target outside Google internal hosts."""
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname.lower().strip(".")
    if host in excluded_hosts or is_google_host(host):
        return False
    for blocked in excluded_hosts:
        if host.endswith(f".{blocked}"):
            return False
    return True


def has_organic_serp_dom(body: str) -> bool:
    """Return True if HTML contains standard Google organic containers or headings."""
    if not body:
        return False
    if _ORGANIC_HTML_MARKER_RE.search(body):
        return True
    try:
        parser = lxml_html.HTMLParser(recover=True, remove_comments=True)
        tree = lxml_html.fromstring(body, parser=parser)
    except Exception:
        return False

    for selector in _ORGANIC_CSS_SELECTORS:
        try:
            if tree.cssselect(selector):
                return True
        except Exception:
            continue
    return False


def is_explicit_no_results_page(body: str) -> bool:
    """Detect legitimate Google zero-match pages to distinguish from DOM drift."""
    sample = body[:65536].lower()
    return any(sig in sample for sig in GOOGLE_NO_RESULTS_SIGNATURES)


def _url_host_matches(raw_url: str, expected_host: str) -> bool:
    """Return True iff `raw_url`'s parsed hostname equals or is a subdomain of `expected_host`."""
    try:
        host = (urlparse(raw_url.strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return host == expected_host or host.endswith(f".{expected_host}")


def _is_google_sorry_url(raw_url: str) -> bool:
    """Detect Google `/sorry/` or `sorry.google.com` verification redirects without substring spoofing."""
    try:
        parsed = urlparse(raw_url.strip())
    except ValueError:
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if host == "sorry.google.com" or host.endswith(".sorry.google.com"):
        return True
    path = (parsed.path or "").lower()
    is_google_or_rel = not host or host == "google.com" or host.endswith(".google.com")
    return is_google_or_rel and path.startswith("/sorry")


def detect_google_block(
    status_code: int,
    final_url: str,
    body: str,
    headers: Mapping[str, Any] | None = None,
) -> None:
    """
    False-positive-safe, RFC 6585-compliant Google HTTP/DOM response classifier:
      1. HTTP 429 -> GoogleRateLimitedError (with parsed Retry-After)
      2. `/sorry/` or CAPTCHA signatures -> GoogleChallengeTriggeredError
      3. Small (<5KB) JS-interstitial stub lacking organic DOM -> GoogleDOMStructureChangedError
      4. Valid SERPs containing `<noscript>` enablejs boilerplate pass cleanly.
    """
    if status_code == 429:
        retry_after = parse_retry_after(headers)
        raise GoogleRateLimitedError(
            "Google rate-limited request (HTTP 429)",
            status_code=429,
            retry_after=retry_after,
        )

    if _is_google_sorry_url(final_url):
        raise GoogleChallengeTriggeredError(
            f"Google /sorry/ verification redirect: {final_url}",
            status_code=status_code,
        )

    if _url_host_matches(final_url, "consent.google.com"):
        raise GoogleDOMStructureChangedError(
            f"Google redirected to regional consent wall ({final_url}); check SOCS/CONSENT cookies.",
            status_code=status_code,
        )

    sample = body[:40960].lower()
    for sig in GOOGLE_SORRY_SIGNATURES:
        if sig in sample:
            raise GoogleChallengeTriggeredError(
                f"Google verification challenge detected ('{sig}')",
                status_code=status_code,
            )

    body_len = len(body)
    if body_len < JS_INTERSTITIAL_MAX_BYTES:
        if not has_organic_serp_dom(body):
            refresh_match = _GOOGLE_META_REFRESH_RE.search(body)
            if refresh_match:
                target = refresh_match.group(1).strip()
                if _is_google_sorry_url(target):
                    raise GoogleChallengeTriggeredError(
                        f"Google meta-refresh to verification page: {target}",
                        status_code=status_code,
                    )
                if "enablejs" in target.lower():
                    raise GoogleDOMStructureChangedError(
                        f"Google JS-interstitial stub ({body_len}B, redirect={target}).",
                        status_code=status_code,
                    )

            for js_sig in GOOGLE_JS_GATE_SIGNATURES:
                if js_sig in sample:
                    raise GoogleDOMStructureChangedError(
                        f"Google JS-interstitial stub ({body_len}B, '{js_sig}').",
                        status_code=status_code,
                    )
    elif "/httpservice/retry/enablejs" in sample:
        logger.debug(
            "[google:detector] Ignoring noscript enablejs boilerplate on valid %dB SERP.",
            body_len,
        )

    classify_http_response(status_code, final_url, body, headers=headers)


def build_chrome_headers(
    *,
    hl: str = "en",
    gl: str = "us",
    mobile: bool = False,
    referer: str | None = None,
    profile_index: int | None = None,
) -> dict[str, str]:
    """Build coherent Chrome 130+ Client-Hints and navigation headers."""
    pool = MOBILE_CLIENT_PROFILES if mobile else DESKTOP_CLIENT_PROFILES
    idx = (
        profile_index % len(pool)
        if profile_index is not None
        else random.randrange(len(pool))
    )
    selected = pool[idx]

    lang_tag = (
        f"{hl}-{gl.upper()},{hl};q=0.9"
        if hl.lower() != "en" or gl.lower() != "us"
        else "en-US,en;q=0.9"
    )

    headers: dict[str, str] = {
        "sec-ch-ua": selected["sec-ch-ua"],
        "sec-ch-ua-mobile": selected["sec-ch-ua-mobile"],
        "sec-ch-ua-platform": selected["sec-ch-ua-platform"],
        "sec-ch-ua-platform-version": selected["sec-ch-ua-platform-version"],
        "sec-ch-ua-model": selected["sec-ch-ua-model"],
        "sec-ch-ua-arch": selected["sec-ch-ua-arch"],
        "upgrade-insecure-requests": "1",
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "sec-fetch-site": "same-origin" if referer else "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-language": lang_tag,
    }

    if mobile:
        headers["user-agent"] = selected["user-agent"]
    else:
        headers["sec-ch-ua-bitness"] = selected["sec-ch-ua-bitness"]
        headers["sec-ch-ua-full-version-list"] = selected["sec-ch-ua-full-version-list"]

    if referer:
        headers["referer"] = referer
    return headers


class GoogleLocaleConfig(BaseModel):
    """Locale, ranking neutrality, and consent negotiation parameters."""

    model_config = ConfigDict(extra="forbid")

    hl: str = Field(default="en", min_length=2, max_length=16)
    gl: str = Field(default="us", min_length=2, max_length=8)
    pws: Literal["0", "1"] = Field(default="0")
    safe: Literal["off", "active"] = Field(default="off")
    filter_duplicates: Literal["0", "1"] = Field(default="0")
    nfpr: Literal["0", "1"] = Field(default="1")
    socs_cookie: str = Field(default=DEFAULT_GOOGLE_CONSENT_COOKIES["SOCS"])
    consent_cookie: str = Field(default=DEFAULT_GOOGLE_CONSENT_COOKIES["CONSENT"])

    def build_consent_cookies(self) -> dict[str, str]:
        return {"SOCS": self.socs_cookie, "CONSENT": self.consent_cookie}

    def build_base_params(self) -> dict[str, str]:
        return {
            "hl": self.hl,
            "gl": self.gl,
            "pws": self.pws,
            "ie": "UTF-8",
            "oe": "UTF-8",
            "safe": self.safe,
            "filter": self.filter_duplicates,
            "nfpr": self.nfpr,
        }


class GoogleCSECredential(BaseModel):
    """Single Google Programmable Search Engine (CSE) API key + Search Engine ID (cx)."""

    model_config = ConfigDict(extra="forbid")

    api_key: str = Field(min_length=8)
    cx: str = Field(min_length=4)
    daily_quota_limit: int = Field(default=100, ge=1)
    used_today: int = Field(default=0, ge=0)
    quota_reset_utc: float = Field(default=0.0, ge=0.0)
    cooldown_until: float = Field(default=0.0, ge=0.0)
    last_error: str = ""
    disabled: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remaining_quota(self) -> int:
        if self.disabled:
            return 0
        if self.quota_reset_utc > 0.0 and time.time() >= self.quota_reset_utc:
            return self.daily_quota_limit
        return max(0, self.daily_quota_limit - self.used_today)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_available(self) -> bool:
        now = time.time()
        if self.disabled or now < self.cooldown_until:
            return False
        if self.quota_reset_utc > 0.0 and now >= self.quota_reset_utc:
            return True
        return self.used_today < self.daily_quota_limit

    @property
    def redacted_label(self) -> str:
        return f"key={self.api_key[:6]}...{self.api_key[-4:]},cx={self.cx[:8]}..."


class GoogleSuiteConfig(BaseModel):
    """Unified configuration for all four standalone Google Search Federation tiers."""

    model_config = ConfigDict(extra="forbid")

    cse_credentials: list[GoogleCSECredential] = Field(default_factory=list)
    locale: GoogleLocaleConfig = Field(default_factory=GoogleLocaleConfig)
    regional_domains: list[str] = Field(
        default_factory=lambda: list(DEFAULT_GOOGLE_REGIONAL_DOMAINS)
    )
    domain_cooldown_seconds: float = Field(default=120.0, ge=10.0)
    tier_cooldown_seconds: float = Field(default=180.0, ge=10.0)
    tier_failure_threshold: int = Field(default=3, ge=1)
    cse_priority: int = Field(default=1, ge=1)
    web_udm14_priority: int = Field(default=2, ge=1)
    mobile_web_priority: int = Field(default=3, ge=1)
    basic_html_priority: int = Field(default=4, ge=1)
    enable_warmup: bool = Field(default=True)
    pacer_mean_delay: float = Field(default=2.0, gt=0.0)
    pacer_min_delay: float = Field(default=0.5, ge=0.0)
    pacer_max_delay: float = Field(default=8.0, ge=0.2)
    max_retries: int = Field(default=3, ge=1, le=6)
    cse_timeout: float = Field(default=12.0, ge=2.0)

    @classmethod
    def from_env(cls) -> "GoogleSuiteConfig":
        creds: list[GoogleCSECredential] = []
        raw_pairs = os.getenv("GOOGLE_CSE_CREDENTIALS", "").strip()
        if raw_pairs:
            for entry in raw_pairs.split(","):
                item = entry.strip()
                if ":" not in item:
                    continue
                key_part, cx_part = item.split(":", 1)
                if key_part.strip() and cx_part.strip():
                    creds.append(
                        GoogleCSECredential(api_key=key_part.strip(), cx=cx_part.strip())
                    )
        else:
            single_key = os.getenv("GOOGLE_CSE_API_KEY", "").strip()
            single_cx = os.getenv("GOOGLE_CSE_CX", "").strip()
            if single_key and single_cx:
                creds.append(GoogleCSECredential(api_key=single_key, cx=single_cx))

        return cls(cse_credentials=creds)


def build_omnibox_params(
    *,
    query: str,
    locale: GoogleLocaleConfig,
    page_idx: int = 0,
    udm: str | None = "14",
    gbv: str | None = None,
    mobile: bool = False,
) -> dict[str, str]:
    """Synthesize Chrome omnibox navigation parameters on page 1 and `start=` on page 2+."""
    params = locale.build_base_params()
    params["q"] = query

    if udm is not None:
        params["udm"] = udm
    if gbv is not None:
        params["gbv"] = gbv

    if page_idx == 0:
        params["oq"] = query
        params["sourceid"] = "chrome-mobile" if mobile else "chrome"
        if not mobile and gbv is None:
            params["aqs"] = random.choice(_CHROME_OMNIBOX_AQS_TEMPLATES)
        params["num"] = "10"
    else:
        params["start"] = str(page_idx * 10)
        params["sa"] = "N"
        params["num"] = "10"
        if not mobile:
            params["biw"] = "1440"
            params["bih"] = "900"

    return params


class GoogleDomainRotator:
    """Rotates regional Google domains with per-domain circuit-breaker cooldowns."""

    def __init__(
        self,
        domains: Sequence[str] = DEFAULT_GOOGLE_REGIONAL_DOMAINS,
        cooldown_seconds: float = 120.0,
    ) -> None:
        cleaned = [d.strip().lower() for d in domains if d.strip()]
        self._domains: list[str] = cleaned or list(DEFAULT_GOOGLE_REGIONAL_DOMAINS)
        self._cooldown_seconds = cooldown_seconds
        self._cooldowns: dict[str, float] = {d: 0.0 for d in self._domains}
        self._cursor: int = 0
        self._lock = asyncio.Lock()

    async def select(self, exclude: set[str] | None = None) -> str:
        excluded = exclude or set()
        async with self._lock:
            now = time.monotonic()
            healthy = [
                d
                for d in self._domains
                if d not in excluded and self._cooldowns.get(d, 0.0) <= now
            ]
            if healthy:
                chosen = healthy[self._cursor % len(healthy)]
                self._cursor += 1
                return chosen

            fallback_pool = [d for d in self._domains if d not in excluded] or self._domains
            fallback_pool.sort(key=lambda d: self._cooldowns.get(d, 0.0))
            return fallback_pool[0]

    async def mark_challenged(self, domain: str, reason: str = "") -> None:
        async with self._lock:
            if domain in self._cooldowns:
                self._cooldowns[domain] = time.monotonic() + self._cooldown_seconds
                logger.warning(
                    "[google:domains] Cooling down %s for %.0fs (%s)",
                    domain,
                    self._cooldown_seconds,
                    reason or "edge challenge",
                )

    async def mark_healthy(self, domain: str) -> None:
        async with self._lock:
            if domain in self._cooldowns:
                self._cooldowns[domain] = 0.0


class GoogleDirectHTMLMixin:
    """Shared root cookie bootstrapping, dynamic Poisson pacing, and URL canonicalization."""

    locale: GoogleLocaleConfig
    domain_rotator: GoogleDomainRotator
    pacer: DynamicPoissonPacer | None
    enable_warmup: bool
    transport: Any

    @staticmethod
    def _cookie_domain_for(host: str) -> str:
        clean = host.lower().strip(".")
        if clean.startswith("www."):
            return "." + clean[4:]
        return "." + clean

    def _seed_consent_cookies_if_missing(
        self,
        session: AsyncSession,
        domain: str,
    ) -> None:
        cookie_domain = self._cookie_domain_for(domain)
        existing_names = set(session.cookies.keys())
        for name, value in self.locale.build_consent_cookies().items():
            if name not in existing_names:
                session.cookies.set(name, value, domain=cookie_domain, path="/")

    async def _bootstrap_session_cookies(
        self,
        session: AsyncSession,
        domain: str,
        on_h1: Callable[[], None],
        *,
        mobile: bool = False,
        profile_index: int = 0,
    ) -> str:
        root_url = f"https://{domain}/?hl={self.locale.hl}"
        self._seed_consent_cookies_if_missing(session, domain)

        if not self.enable_warmup:
            return f"https://{domain}/"

        headers = build_chrome_headers(
            hl=self.locale.hl,
            gl=self.locale.gl,
            mobile=mobile,
            referer=None,
            profile_index=profile_index,
        )
        resp = await self.transport.request(
            session,
            "GET",
            root_url,
            headers=headers,
            on_http1_fallback=on_h1,
        )
        self._seed_consent_cookies_if_missing(session, domain)

        if resp.status_code in (403, 429, 451):
            await self.domain_rotator.mark_challenged(domain, f"warmup HTTP {resp.status_code}")
            detect_google_block(
                resp.status_code,
                str(resp.url),
                resp.text,
                headers=getattr(resp, "headers", None),
            )

        await asyncio.sleep(random.uniform(0.3, 0.7))
        return f"https://{domain}/"

    @staticmethod
    def _post_process_google_results(
        raw_results: Sequence[SearchResult],
        engine_label: str,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        cleaned: list[SearchResult] = []
        seen: set[str] = set()
        for item in raw_results:
            unwrapped = unwrap_google_url(item.url)
            if not is_valid_organic_url(unwrapped, GOOGLE_EXCLUDED_HOSTS):
                continue
            dedup_key = unwrapped.rstrip("/").lower()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            cleaned.append(
                item.model_copy(
                    update={
                        "rank": len(cleaned) + 1,
                        "url": unwrapped[:2048],
                        "title": item.title[:500],
                        "snippet": item.snippet[:4000],
                        "engine": engine_label,
                        "query": query,
                    }
                )
            )
            if len(cleaned) >= max_results:
                break
        return cleaned

    @staticmethod
    def _classify_zero_extraction(
        body: str,
        domain: str,
        engine_label: str,
        query: str,
    ) -> None:
        if is_explicit_no_results_page(body):
            raise EmptyResultError(
                f"{engine_label} ({domain}) returned 0 matches for '{query}'"
            )
        if len(body) >= JS_INTERSTITIAL_MAX_BYTES and not has_organic_serp_dom(body):
            raise GoogleDOMStructureChangedError(
                f"{engine_label} ({domain}) returned {len(body)}B HTML without expected "
                f"organic containers for '{query}'"
            )
        raise EmptyResultError(
            f"{engine_label} ({domain}) parsed 0 organic results for '{query}'"
        )

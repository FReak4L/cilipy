"""curl_cffi AsyncSession BoringSSL HTTP transport, RFC 6585 classifier, and AdaptiveDOMExtractor."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import parse_qs, unquote, urlparse

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html

from core.constants import (
    BLOCK_SIGNATURES,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    H2_TRANSPORT_ERROR_SIGNATURES,
    IGNORED_ENGINE_DOMAINS,
)
from core.exceptions import (
    CaptchaTriggeredError,
    EngineDegradedError,
    RateLimitedError,
    TransportResetError,
)
from core.models import SearchResult

# Resolve CurlError and HTTP/1.1 version enum cleanly across curl_cffi releases
try:
    from curl_cffi.requests.errors import RequestsError as CurlError
except ImportError:
    try:
        from curl_cffi.curl import CurlError as CurlError  # type: ignore[no-redef]
    except ImportError:
        CurlError = OSError  # type: ignore[misc,assignment]

try:
    from curl_cffi.const import CurlHttpVersion

    HTTP_VERSION_1_1: Any = CurlHttpVersion.V1_1
except ImportError:
    HTTP_VERSION_1_1 = 2  # libcurl CURL_HTTP_VERSION_1_1

logger = logging.getLogger("hybrid_search.v3.transport")


def parse_retry_after(headers: Mapping[str, Any] | None) -> float | None:
    """
    RFC 6585 / RFC 7231 `Retry-After` header parser supporting both integer seconds
    and HTTP-date timestamps. Returns positive wait seconds or None.
    """
    if not headers:
        return None
    raw_val: Any = None
    for k, v in headers.items():
        if str(k).lower() == "retry-after":
            raw_val = v
            break
    if raw_val is None:
        return None

    text = str(raw_val).strip()
    if not text:
        return None
    try:
        seconds = float(text)
        return max(0.0, seconds)
    except ValueError:
        pass
    try:
        target_dt = parsedate_to_datetime(text)
        if target_dt.tzinfo is None:
            target_dt = target_dt.replace(tzinfo=timezone.utc)
        delta = (target_dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


def is_valid_http_url(url: str) -> bool:
    """Return True iff `url` is a well-formed absolute HTTP/HTTPS URL with a valid hostname."""
    if not url:
        return False
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").strip(".")
    return bool(host) and "." in host


def canonicalize_url(raw_url: str) -> str:
    """Normalize protocol-relative links, reject hostless redirectors, and unwrap DDG/Yahoo."""
    if not raw_url:
        return ""
    cleaned = raw_url.strip()
    if cleaned.startswith("//"):
        cleaned = "https:" + cleaned

    parsed = urlparse(cleaned)

    if "uddg" in parsed.query:
        uddg_values = parse_qs(parsed.query).get("uddg")
        if uddg_values:
            unwrapped = unquote(uddg_values[0]).strip()
            return unwrapped if is_valid_http_url(unwrapped) else ""

    if "r.search.yahoo.com" in parsed.netloc and "/RU=" in parsed.path:
        try:
            ru_segment = parsed.path.split("/RU=", 1)[1].split("/RK=", 1)[0]
            decoded = unquote(ru_segment).strip()
            if is_valid_http_url(decoded):
                return decoded
        except IndexError:
            pass

    if not is_valid_http_url(cleaned):
        return ""
    return cleaned


def extract_root_domain(url: str) -> str:
    """Extract normalized root domain (e.g., `docs.python.org` -> `python.org`)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    second_level_tlds = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(parts[-1]) == 2 and parts[-2] in second_level_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def detect_soft_block(status_code: int, final_url: str, body: str) -> str | None:
    """Inspect HTTP status, redirect URL, and HTML body for WAF/CAPTCHA/geo-block signals."""
    if status_code in (202, 403, 429, 451):
        return f"HTTP {status_code}"

    url_lower = final_url.lower()
    if any(token in url_lower for token in ("/sp/captcha", "/sorry/", "sorry.google.com")):
        return f"Challenge redirect ({final_url})"

    sample = body[:32768].lower()
    for signature in BLOCK_SIGNATURES:
        if signature in sample:
            return f"Matched block signature '{signature}'"

    return None


def classify_http_response(
    status_code: int,
    final_url: str,
    body: str,
    headers: Mapping[str, Any] | None = None,
) -> None:
    """
    RFC 6585-compliant HTTP response classifier:
      - 202 / 429 -> RateLimitedError (carries parsed Retry-After header when present)
      - 403 / 451 / challenge redirect / block signature -> CaptchaTriggeredError
      - 5xx or != 200 -> EngineDegradedError
    """
    if status_code in (202, 429):
        retry_after = parse_retry_after(headers)
        raise RateLimitedError(
            f"Application throttling (HTTP {status_code})",
            status_code=status_code,
            retry_after=retry_after,
        )

    if status_code in (403, 451):
        raise CaptchaTriggeredError(
            f"WAF or geo-restriction gate (HTTP {status_code})",
            status_code=status_code,
        )

    url_lower = final_url.lower()
    if any(token in url_lower for token in ("/sp/captcha", "/sorry/", "sorry.google.com")):
        raise CaptchaTriggeredError(f"Challenge redirect ({final_url})", status_code=status_code)

    sample = body[:32768].lower()
    for signature in BLOCK_SIGNATURES:
        if signature in sample:
            raise CaptchaTriggeredError(
                f"Matched block signature '{signature}'",
                status_code=status_code,
            )

    if status_code >= 500 or status_code != 200:
        raise EngineDegradedError(
            f"Unexpected upstream status HTTP {status_code}",
            status_code=status_code,
        )


def is_h2_or_transport_reset(exc: BaseException) -> bool:
    """Detect HTTP/2 stream resets, TLS drops, and proxy tunnel terminations."""
    msg = str(exc).lower()
    return any(sig in msg for sig in H2_TRANSPORT_ERROR_SIGNATURES)


class AdaptiveHttpTransport:
    """
    Wraps `curl_cffi.AsyncSession` with BoringSSL Chrome impersonation and dynamic
    HTTP/2 -> HTTP/1.1 fallback on proxy/tunnel stream resets.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        enable_http1_fallback: bool = True,
    ) -> None:
        self.timeout = float(timeout)
        self.enable_http1_fallback = bool(enable_http1_fallback)

    def create_session(
        self,
        *,
        impersonate: str = "chrome",
        proxy_url: str | None = None,
        allow_redirects: bool = True,
    ) -> AsyncSession:
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        return AsyncSession(
            impersonate=impersonate,
            proxies=proxies,
            timeout=self.timeout,
            allow_redirects=allow_redirects,
        )

    @staticmethod
    def build_nav_headers(
        referer: str | None = None,
        origin: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Site": "same-origin" if referer else "none",
        }
        if referer:
            headers["Referer"] = referer
        if origin:
            headers["Origin"] = origin
        return headers

    async def request(
        self,
        session: AsyncSession,
        method: Literal["GET", "POST"],
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        on_http1_fallback: Callable[[], None] | None = None,
    ) -> Any:
        """Execute an HTTP request over HTTP/2 first; fall back to HTTP/1.1 on tunnel resets."""
        kwargs: dict[str, Any] = {}
        if params is not None:
            kwargs["params"] = params
        if data is not None:
            kwargs["data"] = data
        if headers is not None:
            kwargs["headers"] = headers

        try:
            if method == "GET":
                return await session.get(url, **kwargs)
            return await session.post(url, **kwargs)
        except (CurlError, TimeoutError, OSError) as exc:
            if not self.enable_http1_fallback or not is_h2_or_transport_reset(exc):
                raise TransportResetError(f"Transport failure on {url}: {exc}") from exc

            logger.warning(
                "[transport] HTTP/2 reset/drop on %s (%s); retrying over HTTP/1.1",
                url,
                exc,
            )
            if on_http1_fallback is not None:
                on_http1_fallback()

            try:
                kwargs["http_version"] = HTTP_VERSION_1_1
                if method == "GET":
                    return await session.get(url, **kwargs)
                return await session.post(url, **kwargs)
            except (CurlError, TimeoutError, OSError) as h1_exc:
                raise TransportResetError(
                    f"HTTP/1.1 fallback also failed on {url}: {h1_exc}"
                ) from h1_exc


class AdaptiveDOMExtractor:
    """
    Fault-tolerant, multi-heuristic HTML extractor for organic search results shared
    across all direct HTML plugins without code duplication.
    """

    @staticmethod
    def safe_parse(raw_html: str) -> Any | None:
        if not raw_html or not raw_html.strip():
            return None
        try:
            parser = lxml_html.HTMLParser(recover=True, remove_comments=True)
            return lxml_html.fromstring(raw_html, parser=parser)
        except Exception:
            return None

    @staticmethod
    def is_valid_external_url(url: str, excluded_hosts: frozenset[str]) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        host = parsed.hostname.lower().strip(".")
        if host in excluded_hosts:
            return False
        for blocked in excluded_hosts:
            if host.endswith(f".{blocked}"):
                return False
        return True

    @staticmethod
    def clean_text(text: str, max_len: int = 380) -> str:
        collapsed = " ".join(text.split())
        if len(collapsed) > max_len:
            return collapsed[: max_len - 3].rstrip() + "..."
        return collapsed

    @classmethod
    def extract_results(
        cls,
        raw_html: str,
        query: str,
        engine_label: str,
        *,
        max_results: int = 20,
        container_hints: Sequence[str] = (),
        link_hints: Sequence[str] = (),
        snippet_hints: Sequence[str] = (),
        excluded_hosts: frozenset[str] = IGNORED_ENGINE_DOMAINS,
        url_unwrapper: Callable[[str], str] = canonicalize_url,
    ) -> list[SearchResult]:
        tree = cls.safe_parse(raw_html)
        if tree is None:
            return []

        results: list[SearchResult] = []
        seen_urls: set[str] = set()

        def _append_candidate(raw_href: str, raw_title: str, raw_snippet: str) -> bool:
            url = url_unwrapper(raw_href)
            if not cls.is_valid_external_url(url, excluded_hosts):
                return False
            title = cls.clean_text(raw_title, max_len=480)
            if len(title) < 3:
                return False
            dedup_key = url.rstrip("/").lower()
            if dedup_key in seen_urls:
                return False
            seen_urls.add(dedup_key)
            snippet = cls.clean_text(raw_snippet, max_len=1500)
            if snippet == title:
                snippet = ""
            results.append(
                SearchResult(
                    rank=len(results) + 1,
                    title=title,
                    url=url[:2048],
                    snippet=snippet,
                    engine=engine_label,
                    query=query,
                )
            )
            return len(results) >= max_results

        # Heuristic 1: Guided container extraction
        if container_hints:
            for container_sel in container_hints:
                try:
                    cards = tree.cssselect(container_sel)
                except Exception:
                    continue
                for card in cards:
                    link_el: Any | None = None
                    for l_sel in link_hints:
                        try:
                            matches = card.cssselect(l_sel)
                        except Exception:
                            matches = []
                        if matches:
                            link_el = matches[0]
                            break
                    if link_el is None:
                        anchors = card.xpath(".//a[@href]")
                        link_el = anchors[0] if anchors else None
                    if link_el is None:
                        continue

                    raw_href = str(link_el.get("href") or "")
                    h3_nodes = link_el.xpath(".//h3 | ./ancestor::*[1]//h3")
                    raw_title = (
                        str(h3_nodes[0].text_content() or "")
                        if h3_nodes
                        else str(link_el.text_content() or "")
                    )

                    raw_snippet = ""
                    for s_sel in snippet_hints:
                        try:
                            s_matches = card.cssselect(s_sel)
                        except Exception:
                            s_matches = []
                        if s_matches:
                            raw_snippet = str(s_matches[0].text_content() or "")
                            if raw_snippet.strip():
                                break
                    if not raw_snippet:
                        full_text = cls.clean_text(str(card.text_content() or ""))
                        raw_snippet = full_text.replace(cls.clean_text(raw_title), "", 1)

                    if _append_candidate(raw_href, raw_title, raw_snippet):
                        return results
                if results:
                    return results

        # Heuristic 2: Semantic heading/container scan
        semantic_containers = tree.xpath(
            "//article[.//a[@href]] | //li[.//a[@href] and (.//h2 or .//h3 or .//h4 or .//p)] "
            "| //div[(.//h2//a[@href] or .//h3//a[@href]) and count(.//a[@href]) <= 12]"
        )
        for node in semantic_containers:
            heading_links = node.xpath(".//h2//a[@href] | .//h3//a[@href] | .//h4//a[@href]")
            link_el = heading_links[0] if heading_links else None
            if link_el is None:
                all_links = node.xpath(".//a[@href]")
                link_el = all_links[0] if all_links else None
            if link_el is None:
                continue

            raw_href = str(link_el.get("href") or "")
            raw_title = str(link_el.text_content() or "")
            para_nodes = node.xpath(".//p | .//span[string-length(normalize-space(.)) > 35]")
            raw_snippet = (
                str(para_nodes[0].text_content() or "")
                if para_nodes
                else str(node.text_content() or "").replace(raw_title, "", 1)
            )
            if _append_candidate(raw_href, raw_title, raw_snippet):
                return results

        if results:
            return results

        # Heuristic 3: Anchor-cluster fallback across external links
        for anchor in tree.xpath("//a[@href]"):
            raw_href = str(anchor.get("href") or "")
            raw_title = str(anchor.text_content() or "")
            if len(raw_title.strip()) < 6:
                continue
            parent = anchor.getparent()
            grandparent = parent.getparent() if parent is not None else None
            context_node = grandparent if grandparent is not None else parent
            raw_snippet = ""
            if context_node is not None:
                context_text = cls.clean_text(str(context_node.text_content() or ""))
                raw_snippet = context_text.replace(cls.clean_text(raw_title), "", 1)

            if _append_candidate(raw_href, raw_title, raw_snippet):
                return results

        return results

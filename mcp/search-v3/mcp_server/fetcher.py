"""SSRF-safe BoringSSL (curl_cffi) web page fetcher & lxml HTML-to-Markdown reader."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html

from core.constants import H2_TRANSPORT_ERROR_SIGNATURES
from transport.http_client import HTTP_VERSION_1_1, is_valid_http_url

MAX_DOWNLOAD_BYTES = 2_500_000

_GITHUB_REPO_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

_STRIP_TAGS = {
    "script",
    "style",
    "noscript",
    "svg",
    "iframe",
    "canvas",
    "template",
    "object",
    "embed",
    "audio",
    "video",
}

_CHROME_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}


class FetchError(RuntimeError):
    """Raised when URL validation, SSRF protection, or HTTP fetching fails."""


@dataclass(slots=True)
class FetchedDocument:
    url: str
    final_url: str
    status_code: int
    content_type: str
    title: str
    markdown: str
    headings: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    total_chars: int = 0
    returned_chars: int = 0
    start_char: int = 0
    truncated: bool = False
    next_start_char: int | None = None


def _is_forbidden_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def validate_public_url(url: str) -> str:
    """Validate HTTP(S) URL syntax and block SSRF to private/loopback/link-local hosts."""
    cleaned = url.strip()
    if not is_valid_http_url(cleaned):
        raise FetchError(f"Invalid or unsupported URL (only public http/https allowed): {url!r}")
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").strip().lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local") or host.endswith(".internal"):
        raise FetchError(f"Blocked internal/local hostname: {host!r}")

    # Direct IP literal check
    try:
        ipaddress.ip_address(host)
        if _is_forbidden_ip(host):
            raise FetchError(f"Blocked non-public IP address: {host}")
        return cleaned
    except ValueError:
        pass

    # DNS resolution check against private / metadata ranges
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise FetchError(f"DNS lookup failed for {host!r}: {exc}") from exc

    resolved_ips = {info[4][0] for info in infos if info[4]}
    if not resolved_ips:
        raise FetchError(f"No IP addresses resolved for {host!r}")
    for ip_str in resolved_ips:
        if _is_forbidden_ip(ip_str):
            raise FetchError(f"Blocked SSRF target {host!r} -> non-public IP {ip_str}")
    return cleaned


def _collapse_ws(text: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", text).strip()


def _node_to_markdown(node: Any, base_url: str, *, depth: int = 0) -> str:
    """Lightweight, clean lxml DOM -> Markdown renderer."""
    tag = str(getattr(node, "tag", "") or "").lower()
    if not isinstance(node.tag, str) or tag in _STRIP_TAGS:
        return ""

    if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
        level = int(tag[1])
        txt = _collapse_ws("".join(node.itertext()))
        return f"\n\n{'#' * level} {txt}\n\n" if txt else ""

    if tag == "pre":
        code_text = "".join(node.itertext()).strip("\n")
        if not code_text.strip():
            return ""
        return f"\n\n```\n{code_text}\n```\n\n"

    if tag == "code":
        txt = "".join(node.itertext()).strip()
        return f"`{txt}`" if txt else ""

    if tag == "br":
        return "\n"

    if tag == "hr":
        return "\n\n---\n\n"

    if tag == "a":
        txt = _collapse_ws("".join(node.itertext()))
        href = str(node.get("href") or "").strip()
        if not txt:
            return ""
        if href and not href.startswith(("javascript:", "mailto:", "#")):
            abs_href = urljoin(base_url, href)
            return f"[{txt}]({abs_href})"
        return txt

    if tag in ("ul", "ol"):
        items: list[str] = []
        idx = 1
        for child in node:
            if str(getattr(child, "tag", "")).lower() == "li":
                body = _collapse_ws(_children_to_md(child, base_url, depth=depth + 1))
                if body:
                    prefix = f"{idx}. " if tag == "ol" else "- "
                    items.append(f"{'  ' * min(depth, 3)}{prefix}{body}")
                    idx += 1
        return ("\n" + "\n".join(items) + "\n\n") if items else ""

    if tag == "blockquote":
        inner = _children_to_md(node, base_url, depth=depth + 1).strip()
        if not inner:
            return ""
        quoted = "\n".join(f"> {line}" for line in inner.splitlines() if line.strip())
        return f"\n\n{quoted}\n\n"

    if tag == "tr":
        cells = [
            _collapse_ws("".join(c.itertext())).replace("|", "\\|")
            for c in node
            if str(getattr(c, "tag", "")).lower() in ("th", "td")
        ]
        if not any(cells):
            return ""
        return "| " + " | ".join(cells) + " |\n"

    if tag in ("p", "div", "section", "article", "main", "header", "dl", "dt", "dd", "table", "tbody", "thead"):
        inner = _children_to_md(node, base_url, depth=depth)
        if tag in ("p", "section", "article", "table"):
            stripped = inner.strip()
            return f"\n\n{stripped}\n\n" if stripped else ""
        return inner

    return _children_to_md(node, base_url, depth=depth)


def _children_to_md(node: Any, base_url: str, *, depth: int = 0) -> str:
    parts: list[str] = []
    if node.text:
        parts.append(node.text)
    for child in node:
        parts.append(_node_to_markdown(child, base_url, depth=depth))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def html_to_markdown_and_meta(
    raw_html: str,
    base_url: str,
    *,
    include_links: bool = False,
) -> tuple[str, str, list[dict[str, Any]], list[str]]:
    """Convert raw HTML into (title, clean_markdown, headings, extracted_links)."""
    if not raw_html.strip():
        return "", "", [], []
    tree = lxml_html.fromstring(raw_html)

    title_nodes = tree.xpath("//title/text()")
    title = _collapse_ws(str(title_nodes[0])) if title_nodes else ""

    # Remove script/style/noise elements before content extraction
    for bad in tree.xpath(
        "//script|//style|//noscript|//svg|//iframe|//template|//canvas"
    ):
        parent = bad.getparent()
        if parent is not None:
            parent.remove(bad)

    # Prefer main semantic container when substantial
    root = tree
    for selector in ("main", "article", '[role="main"]', "#content", ".content", "body"):
        try:
            matches = tree.cssselect(selector)
        except Exception:
            matches = []
        if matches:
            cand = matches[0]
            if len(" ".join(cand.itertext()).strip()) >= 120 or selector == "body":
                root = cand
                break

    # Remove nav/footer/aside clutter only inside body fallback
    if str(getattr(root, "tag", "")).lower() == "body":
        for clutter in root.xpath(".//nav|.//footer|.//aside"):
            parent = clutter.getparent()
            if parent is not None:
                parent.remove(clutter)

    headings: list[dict[str, Any]] = []
    for h in root.xpath(".//h1|.//h2|.//h3|.//h4|.//h5|.//h6"):
        txt = _collapse_ws("".join(h.itertext()))
        if txt:
            headings.append({"level": int(str(h.tag)[1]), "text": txt})

    links: list[str] = []
    if include_links:
        seen_links: set[str] = set()
        for a_el in root.xpath(".//a[@href]"):
            href = str(a_el.get("href") or "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            resolved = urljoin(base_url, href)
            if is_valid_http_url(resolved) and resolved not in seen_links:
                seen_links.add(resolved)
                links.append(resolved)
                if len(links) >= 60:
                    break

    raw_md = _node_to_markdown(root, base_url)
    # Normalize excessive blank lines and spaces
    cleaned_lines = [line.rstrip() for line in raw_md.splitlines()]
    md = "\n".join(cleaned_lines)
    md = re.sub(r"\n{3,}", "\n\n", md).strip()
    return title, md, headings, links


def _extract_section(markdown: str, section_query: str) -> str:
    """Return content under the first heading matching `section_query` (case-insensitive)."""
    needle = section_query.strip().lower()
    if not needle:
        return markdown
    lines = markdown.splitlines()
    start_idx: int | None = None
    start_level = 7
    heading_re = re.compile(r"^(#{1,6})\s+(.*)$")

    for i, line in enumerate(lines):
        m = heading_re.match(line.strip())
        if m:
            lvl = len(m.group(1))
            htext = m.group(2).strip().lower()
            if start_idx is None:
                if needle in htext:
                    start_idx = i
                    start_level = lvl
            else:
                if lvl <= start_level:
                    return "\n".join(lines[start_idx:i]).strip()

    if start_idx is not None:
        return "\n".join(lines[start_idx:]).strip()
    return f"[Section {section_query!r} not found. Use headings_only=true to list available sections.]"


async def _curl_get(url: str, *, timeout: float) -> Any:
    """GET via BoringSSL curl_cffi with automatic HTTP/2 -> HTTP/1.1 fallback."""
    async with AsyncSession(
        impersonate="chrome124",
        timeout=timeout,
        allow_redirects=True,
        max_redirects=6,
    ) as session:
        try:
            return await session.get(url, headers=_CHROME_HEADERS)
        except Exception as exc:
            err_msg = str(exc).lower()
            if any(sig in err_msg for sig in H2_TRANSPORT_ERROR_SIGNATURES):
                return await session.get(
                    url,
                    headers=_CHROME_HEADERS,
                    http_version=HTTP_VERSION_1_1,
                )
            raise


async def fetch_url_content(
    url: str,
    *,
    max_chars: int = 18_000,
    start_char: int = 0,
    headings_only: bool = False,
    section: str | None = None,
    include_links: bool = False,
    prefer_github_readme: bool = True,
    timeout: float = 15.0,
) -> FetchedDocument:
    """Fetch a public HTTP(S) URL cleanly with SSRF guard, BoringSSL TLS, and Markdown extraction."""
    safe_url = await validate_public_url(url)
    max_chars = max(500, min(int(max_chars), 100_000))
    start_char = max(0, int(start_char))
    timeout = max(2.0, min(float(timeout), 60.0))

    # Optional clean fast-path for GitHub repository root URLs -> raw README.md
    if prefer_github_readme:
        gh_match = _GITHUB_REPO_RE.match(safe_url)
        if gh_match:
            owner, repo = gh_match.group(1), gh_match.group(2)
            for candidate in (
                f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/README.md",
                f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md",
                f"https://raw.githubusercontent.com/{owner}/{repo}/master/README.md",
            ):
                try:
                    resp = await _curl_get(candidate, timeout=timeout)
                    if resp.status_code == 200 and resp.text.strip():
                        full_md = resp.text.strip()
                        return _paginate_doc(
                            url=safe_url,
                            final_url=str(resp.url),
                            status_code=resp.status_code,
                            content_type="text/markdown",
                            title=f"{owner}/{repo} README",
                            body=full_md,
                            headings=_extract_md_headings(full_md),
                            links=[],
                            start_char=start_char,
                            max_chars=max_chars,
                            headings_only=headings_only,
                            section=section,
                        )
                except Exception:
                    continue

    try:
        resp = await _curl_get(safe_url, timeout=timeout)
    except Exception as exc:
        raise FetchError(f"HTTP fetch failed for {safe_url}: {exc}") from exc

    final_url = str(resp.url or safe_url)
    if final_url != safe_url:
        await validate_public_url(final_url)

    status_code = int(resp.status_code)
    content_type = str(resp.headers.get("content-type", "application/octet-stream")).split(";")[0].strip().lower()
    raw_bytes = resp.content or b""
    if len(raw_bytes) > MAX_DOWNLOAD_BYTES:
        raw_bytes = raw_bytes[:MAX_DOWNLOAD_BYTES]

    if status_code >= 400:
        raise FetchError(f"HTTP {status_code} returned for {final_url} ({content_type})")

    if "html" in content_type or "xhtml" in content_type:
        html_text = raw_bytes.decode("utf-8", errors="replace")
        title, md, headings, links = html_to_markdown_and_meta(
            html_text, final_url, include_links=include_links
        )
        return _paginate_doc(
            url=safe_url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type,
            title=title,
            body=md,
            headings=headings,
            links=links,
            start_char=start_char,
            max_chars=max_chars,
            headings_only=headings_only,
            section=section,
        )

    if "json" in content_type:
        text = raw_bytes.decode("utf-8", errors="replace")
        try:
            pretty = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except Exception:
            pretty = text
        return _paginate_doc(
            url=safe_url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type,
            title=urlparse(final_url).path.rsplit("/", 1)[-1] or "JSON Document",
            body=f"```json\n{pretty}\n```",
            headings=[],
            links=[],
            start_char=start_char,
            max_chars=max_chars,
            headings_only=False,
            section=None,
        )

    if content_type.startswith("text/") or any(
        tok in content_type for tok in ("xml", "yaml", "toml", "javascript", "ecmascript")
    ):
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        headings = _extract_md_headings(text) if "markdown" in content_type or final_url.endswith(".md") else []
        return _paginate_doc(
            url=safe_url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type,
            title=urlparse(final_url).path.rsplit("/", 1)[-1] or final_url,
            body=text,
            headings=headings,
            links=[],
            start_char=start_char,
            max_chars=max_chars,
            headings_only=headings_only,
            section=section,
        )

    raise FetchError(
        f"Unsupported binary/non-text content type {content_type!r} ({len(raw_bytes)} bytes) at {final_url}"
    )


def _extract_md_headings(markdown: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in markdown.splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
        if m:
            out.append({"level": len(m.group(1)), "text": m.group(2).strip()})
    return out


def _paginate_doc(
    *,
    url: str,
    final_url: str,
    status_code: int,
    content_type: str,
    title: str,
    body: str,
    headings: list[dict[str, Any]],
    links: list[str],
    start_char: int,
    max_chars: int,
    headings_only: bool,
    section: str | None,
) -> FetchedDocument:
    if headings_only:
        toc_lines = [
            f"{'  ' * (h['level'] - 1)}- {'#' * h['level']} {h['text']}"
            for h in headings
        ]
        rendered = "\n".join(toc_lines) if toc_lines else "(No headings found on page)"
        return FetchedDocument(
            url=url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type,
            title=title,
            markdown=rendered,
            headings=headings,
            links=links,
            total_chars=len(rendered),
            returned_chars=len(rendered),
            start_char=0,
            truncated=False,
            next_start_char=None,
        )

    working = _extract_section(body, section) if section else body
    total = len(working)
    sliced = working[start_char : start_char + max_chars]
    truncated = (start_char + len(sliced)) < total
    next_start = (start_char + len(sliced)) if truncated else None
    return FetchedDocument(
        url=url,
        final_url=final_url,
        status_code=status_code,
        content_type=content_type,
        title=title,
        markdown=sliced,
        headings=headings,
        links=links,
        total_chars=total,
        returned_chars=len(sliced),
        start_char=start_char,
        truncated=truncated,
        next_start_char=next_start,
    )

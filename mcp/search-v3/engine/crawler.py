"""Tier 4 Katana deep crawler and HTML structural schema extractor."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html

from core.constants import AUTH_FIELD_HINTS
from core.models import CrawlResult, FormInputField, FormMetadata, PageMetadata

logger = logging.getLogger("hybrid_search.v3.crawler")


class StructuralSchemaExtractor:
    """
    Extracts structured web page schemas from raw HTML:
      - Forms: action endpoints, HTTP methods (GET/POST), input tags, and auth field flags.
      - Metadata: OpenGraph (`og:*`) properties, canonical links, and static asset endpoints.
    """

    @staticmethod
    def extract_from_html(
        base_url: str,
        raw_html: str,
    ) -> tuple[list[FormMetadata], PageMetadata]:
        if not raw_html.strip():
            return [], PageMetadata()

        try:
            tree = lxml_html.fromstring(raw_html)
        except Exception:
            return [], PageMetadata()

        forms: list[FormMetadata] = []
        for form_el in tree.cssselect("form"):
            raw_action = str(form_el.get("action") or "").strip()
            resolved_action = urljoin(base_url, raw_action) if raw_action else base_url
            method = str(form_el.get("method") or "GET").strip().upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                method = "GET"

            inputs: list[FormInputField] = []
            has_auth = False
            for control in form_el.cssselect("input, select, textarea"):
                name = str(control.get("name") or control.get("id") or "").strip()
                input_type = str(
                    control.get("type")
                    or (control.tag if isinstance(control.tag, str) else "text")
                ).strip().lower()
                required = control.get("required") is not None

                if input_type == "password" or any(
                    hint in name.lower() for hint in AUTH_FIELD_HINTS
                ):
                    has_auth = True

                inputs.append(
                    FormInputField(
                        name=name,
                        input_type=input_type,
                        required=required,
                    )
                )

            forms.append(
                FormMetadata(
                    action=resolved_action,
                    method=method,
                    inputs=inputs,
                    has_auth_fields=has_auth,
                )
            )

        canonical_url: str | None = None
        canonical_nodes = tree.cssselect('link[rel="canonical"][href]')
        if canonical_nodes:
            href = str(canonical_nodes[0].get("href") or "").strip()
            if href:
                canonical_url = urljoin(base_url, href)

        open_graph: dict[str, str] = {}
        for meta_el in tree.cssselect('meta[property^="og:"], meta[name^="og:"]'):
            prop = str(meta_el.get("property") or meta_el.get("name") or "").strip()
            content = str(meta_el.get("content") or "").strip()
            if prop and content:
                open_graph[prop] = content

        assets_seen: set[str] = set()
        asset_endpoints: list[str] = []
        for css_sel, attr in (
            ("script[src]", "src"),
            ('link[rel="stylesheet"][href]', "href"),
            ("img[src]", "src"),
        ):
            for el in tree.cssselect(css_sel):
                raw_ref = str(el.get(attr) or "").strip()
                if not raw_ref or raw_ref.startswith("data:"):
                    continue
                resolved = urljoin(base_url, raw_ref)
                if resolved not in assets_seen:
                    assets_seen.add(resolved)
                    asset_endpoints.append(resolved)

        metadata = PageMetadata(
            canonical_url=canonical_url,
            open_graph=open_graph,
            asset_endpoints=asset_endpoints,
        )
        return forms, metadata

    @staticmethod
    def parse_katana_forms(
        base_url: str,
        raw_forms: Sequence[Any],
    ) -> list[FormMetadata]:
        parsed_forms: list[FormMetadata] = []
        for item in raw_forms:
            if not isinstance(item, dict):
                continue
            action_raw = str(item.get("action") or "")
            action = urljoin(base_url, action_raw) if action_raw else base_url
            method = str(item.get("method") or "GET").upper()

            inputs: list[FormInputField] = []
            has_auth = False
            raw_params = item.get("parameters") or item.get("inputs") or []
            if isinstance(raw_params, list):
                for param in raw_params:
                    if isinstance(param, dict):
                        name = str(param.get("name") or "")
                        input_type = str(param.get("type") or "text").lower()
                    else:
                        name = str(param)
                        input_type = "text"
                    if input_type == "password" or any(
                        hint in name.lower() for hint in AUTH_FIELD_HINTS
                    ):
                        has_auth = True
                    inputs.append(FormInputField(name=name, input_type=input_type))

            parsed_forms.append(
                FormMetadata(
                    action=action,
                    method=method,
                    inputs=inputs,
                    has_auth_fields=has_auth,
                )
            )
        return parsed_forms


class KatanaPipeline:
    """
    Tier 4 Site-Mapping & Structural Schema Pipeline:
      - Executes ProjectDiscovery's `katana` safely via `create_subprocess_exec`
      - Falls back cleanly to direct HTML schema extraction when `katana` is absent.
    """

    def __init__(
        self,
        binary_path: str | None = None,
        depth: int = 2,
        rate_limit_rps: int = 10,
        concurrency: int = 5,
        timeout_seconds: int = 90,
        allowed_domains: Sequence[str] | None = None,
        enrich_metadata: bool = True,
    ) -> None:
        self.binary_path = binary_path or shutil.which("katana")
        self.depth = depth
        self.rate_limit_rps = rate_limit_rps
        self.concurrency = concurrency
        self.timeout_seconds = timeout_seconds
        self.enrich_metadata = enrich_metadata
        self.allowed_domains = {
            d.strip().lower().lstrip(".") for d in (allowed_domains or []) if d.strip()
        }

    def _filter_in_scope(self, urls: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        scoped: list[str] = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                continue
            host = parsed.hostname.lower()
            if self.allowed_domains and not any(
                host == allowed or host.endswith(f".{allowed}")
                for allowed in self.allowed_domains
            ):
                continue
            if url not in seen:
                seen.add(url)
                scoped.append(url)
        return scoped

    async def _enrich_page_schema(
        self,
        record: CrawlResult,
        proxy_url: str | None,
        sem: asyncio.Semaphore,
    ) -> None:
        if record.metadata.canonical_url or record.metadata.open_graph or record.forms:
            return
        async with sem:
            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
            try:
                async with AsyncSession(
                    impersonate="chrome",
                    proxies=proxies,
                    timeout=10.0,
                    allow_redirects=True,
                ) as session:
                    resp = await session.get(record.endpoint)
                    if resp.status_code != 200:
                        return
                    content_type = str(resp.headers.get("content-type", "")).lower()
                    if "html" not in content_type:
                        return
                    forms, metadata = StructuralSchemaExtractor.extract_from_html(
                        str(resp.url), resp.text
                    )
                    if forms:
                        record.forms = forms
                    record.metadata = metadata
                    if record.status_code is None:
                        record.status_code = resp.status_code
            except Exception:
                return

    async def crawl(
        self,
        seed_urls: Sequence[str],
        proxy_url: str | None = None,
    ) -> list[CrawlResult]:
        scoped_urls = self._filter_in_scope(seed_urls)
        if not scoped_urls:
            return []

        records: list[CrawlResult] = []
        if self.binary_path:
            cmd: list[str] = [
                self.binary_path,
                "-silent",
                "-jsonl",
                "-tlsi",
                "-jc",
                "-fx",
                "-d",
                str(self.depth),
                "-rl",
                str(self.rate_limit_rps),
                "-c",
                str(self.concurrency),
            ]
            if proxy_url:
                cmd.extend(["-proxy", proxy_url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin_payload = ("\n".join(scoped_urls) + "\n").encode("utf-8")
            try:
                stdout_bytes, _ = await asyncio.wait_for(
                    proc.communicate(input=stdin_payload),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                stdout_bytes = b""

            for raw_line in stdout_bytes.decode("utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue

                req_obj = obj.get("request") if isinstance(obj.get("request"), dict) else {}
                resp_obj = (
                    obj.get("response") if isinstance(obj.get("response"), dict) else {}
                )
                endpoint = str(req_obj.get("endpoint") or obj.get("endpoint") or "")
                if not endpoint:
                    continue

                raw_body = str(resp_obj.get("body") or "")
                raw_forms = resp_obj.get("forms") or obj.get("forms") or []
                forms = (
                    StructuralSchemaExtractor.parse_katana_forms(endpoint, raw_forms)
                    if isinstance(raw_forms, list)
                    else []
                )
                metadata = PageMetadata()
                if raw_body:
                    html_forms, metadata = StructuralSchemaExtractor.extract_from_html(
                        endpoint, raw_body
                    )
                    if not forms:
                        forms = html_forms

                status_raw = resp_obj.get("status_code")
                status_code = int(status_raw) if isinstance(status_raw, int) else None

                records.append(
                    CrawlResult(
                        endpoint=endpoint,
                        source=str(req_obj.get("source") or "katana"),
                        method=str(req_obj.get("method") or "GET").upper(),
                        status_code=status_code,
                        forms=forms,
                        metadata=metadata,
                    )
                )
        else:
            logger.warning(
                "[tier-4:katana] Binary not in PATH; performing direct schema extraction on seeds."
            )
            for seed in scoped_urls:
                records.append(CrawlResult(endpoint=seed, source="direct_schema"))

        if self.enrich_metadata and records:
            sem = asyncio.Semaphore(max(1, self.concurrency))
            await asyncio.gather(
                *(self._enrich_page_schema(rec, proxy_url, sem) for rec in records[:50])
            )

        return records

    @staticmethod
    def export_results(results: Sequence[CrawlResult], output_path: Path) -> None:
        if output_path.suffix.lower() == ".jsonl":
            lines = [item.model_dump_json() for item in results]
            output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        else:
            payload = [item.model_dump() for item in results]
            output_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

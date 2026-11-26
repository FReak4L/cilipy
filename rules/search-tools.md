---
trigger: always_on
description: Web search, URL reading and library docs
---

# Search and library docs

- Web: built-in `search_web` / `read_url_content` first. In parallel, or as fallback when empty or failing, use the `search-v3` MCP: `search_web_v3` (profiles `hybrid|direct|api|fast|all`), `search_all_engines`, `batch_search` (`workspace/dorks/`), `fetch_url`, `parse_dork_ast` (strict Boolean dorks), `crawl_urls` (requires `allowed_domains`), `export_links_txt`, `search_status`.
- Before coding against a third-party library: context7 `resolve-library-id` → `query-docs`. Never invent APIs.
- Code in this workspace: gortex/graphify, not web search. Never send secrets to search engines or `fetch_url`.

---
trigger: always_on
description: Web search, URL reading and library docs
---

# Search and library docs

- Web: built-in `search_web` / `read_url_content` first. In parallel or fallback, use `search-v3` MCP (`search_web_v3`, `fetch_url`, `search_all_engines`, `batch_search`, `parse_dork_ast`, `crawl_urls` with `allowed_domains`, `search_status`).
- Precision vs recall in `search_web_v3`: use `strict_ast:false, allow_relax:true` (or `engines:["searxng","ddg_html"]` for <1s fast queries) on broad research; enable `strict_ast:true` only for exact Boolean dorks (`inurl:`, `filetype:`, `intitle:`).
- Third-party libraries: context7 `resolve-library-id` → `query-docs` before coding. Never invent APIs.
- Workspace code: `gortex` / `openhands` discovery, never web search. Never send secrets to search engines or `fetch_url`.

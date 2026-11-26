---
trigger: always_on
description: AI-native routing for web search, URL fetch and library docs
---

<search_router>
WEB_SEARCH:
  PRIMARY: built-in search_web | read_url_content
  PARALLEL_OR_FALLBACK: search-v3 MCP (search_web_v3, fetch_url, search_all_engines, batch_search, parse_dork_ast, crawl_urls[allowed_domains], search_status)
  PARAMS:
    broad_research -> strict_ast=false, allow_relax=true (fast <1s: engines=["searxng","ddg_html"])
    exact_dork(inurl:|filetype:|intitle:) -> strict_ast=true

LIB_DOCS: before coding against 3rd-party lib -> context7.resolve-library-id -> query-docs. NEVER invent APIs.
WORKSPACE_CODE: use gortex/openhands, NEVER web search. NEVER send secrets to search/fetch_url.
</search_router>

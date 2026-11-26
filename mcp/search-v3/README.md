# Hybrid Search Pipeline v3 — Standalone Architecture & Pure-Math/NLP Kernel

Production-grade, decoupled Python 3.12+ federated search architecture with a zero-bloat pure-mathematics & NLP optimization kernel.

## Architecture (Acyclic Dependency DAG)

```
core/           # Pydantic v2 schemas, canonical RFC 6585 exception tree, constants
math_kernel/    # Pure-stdlib optimization kernel (zero external ML/math deps)
  ├── bandit_scheduler.py   # Formulation 1: Thompson Sampling Beta(α, β)
  ├── pacing_poisson.py     # Formulation 2: Dynamic Poisson Exp(λ) with rolling failure hazard
  ├── ast_boolean.py        # Formulation 3: Recursive-descent Boolean AST over B = {0, 1}
  ├── deduplicator.py       # Formulation 4: 64-bit SimHash (Hamming ≤ 3) & Jaccard (J ≥ 0.85)
  └── math_nlp_kernel.py    # Unified facade
transport/      # BoringSSL curl_cffi HTTP/2→HTTP/1.1 client, ns Token Bucket, Proxy Bandit, SQLite cache
engine/         # BaseSearchEngine contract, Thompson EngineRegistry, SearchOrchestrator, KatanaPipeline
plugins/        # Independently importable providers: google (4 tiers + facade), yahoo, duckduckgo, searxng
cli/            # Standalone CLI (`search-v3`) + embedded Pure-ANSI & jq TUI (`tui_*.py`)
mcp_server/     # Zero-dependency Async Stdio MCP Server (`search-v3-mcp`, 8 tools, SSRF-safe reader)
tests/          # Mathematical proofs, AST strictness, standalone Google tiers, TUI, MCP & E2E integration
workspace/      # Organized runtime taxonomy: dorks/, proxies/, configs/, cache/, logs/, exports/{links,json,reports,crawl}
```

## Quick Usage

```bash
# Launch the embedded Pure-ANSI + jq Interactive TUI (3 profiles: Fast / Medium / Advanced)
/root/ntest/direct_search_env/bin/search-v3
# or explicitly:
/root/ntest/direct_search_env/bin/search-v3 --tui

# Check live / recent run status (jq tables, stale PID detection)
/root/ntest/direct_search_env/bin/search-v3 --status

# Run full unit & integration test suite (strict RuntimeWarning check)
/root/ntest/direct_search_env/bin/python -W error::RuntimeWarning \
  -m unittest discover -s /root/ntest/v3/tests -v

# Execute standalone CLI + export ONLY unique links (1 URL per line via jq)
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:docs.python.org inurl:library "asyncio"' \
  --engines searxng,ddg_html,yahoo_direct \
  --no-relax --max-results 10 \
  --links-txt /root/ntest/v3/workspace/exports/links/results.txt
```

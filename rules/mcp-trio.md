---
trigger: always_on
description: When to use gortex, graphify and ai-memory
---

# MCP trio

- **Code structure → gortex** (live index): `search` (symbols/files/text) before reading; `relations` (callers/references/usages/dependents); `change` `impact` before editing a shared symbol, `detect`/`tests` after; `trace` for flows; `analyze` for communities. Unsure of arguments → call `capabilities` once. Unindexed repo → `gortex track <path>`.
- **Whole-graph → graphify** (`graphify-out/graph.json`; other repo: pass `project_path`): `god_nodes`, `shortest_path`, `get_community`, `query_graph` (depth 2–3), PR tools. Stale or missing → `graphify update <repo>`. If it disagrees with gortex, trust gortex and the file.
- **Durable knowledge → ai-memory**: one `memory_search` (limit 5) at session start. Store only decisions, root causes, preferences and environment facts, one per memory, after checking for duplicates. `memory_store` needs `content` with `title` + `summary` (≤200 chars; the only embedded fields), plus `type`, `source`, `confidence`, `tags`. Never store secrets or code the graph can re-derive.
- Make the fewest targeted calls, cap results at 5–10, and read files only at the lines the graph points to.

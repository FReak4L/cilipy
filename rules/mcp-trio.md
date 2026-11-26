---
trigger: always_on
description: When to use gortex, graphify and ai-memory
---

# MCP trio

- **Code structure → gortex** (live index): `search` before reading; `relations` (callers/usages/dependents); `change` `impact` before editing shared symbols, `detect`/`tests` after; `trace` for flows; `analyze` for communities. Unindexed repo → `gortex track <path>`.
- **Whole-graph → graphify** (`graphify-out/graph.json`; other repo: pass `project_path`): `god_nodes`, `shortest_path`, `get_community`, `query_graph` (depth 2–3), PR tools. Refresh stale graphs via `graphify update <repo>`; if it disagrees with gortex, trust gortex and the file.
- **Durable knowledge → ai-memory**: at most **one** `memory_search` (limit 5) at session start (for Telegram handoffs pass `tags:["tg-<user_id>"]` ONLY; skip on trivial Q&A). Store only decisions, root causes, preferences and environment facts (`content:{title, summary≤200 chars}`, `type`, `source`, `confidence`, `tags`). Never store secrets or code the graph can re-derive.
- Cap results at 5–10 and read files only at the lines the graph points to.

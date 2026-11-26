---
trigger: always_on
description: AI-native routing for gortex, graphify and ai-memory MCP servers
---

<mcp_trio>
GORTEX (live code index):
  search(before_read) | relations(callers/usages/deps) | change.impact(before_shared_edit) | change.detect/tests(after) | trace(flows) | analyze(communities)
  IF unindexed_repo -> gortex track <path>

GRAPHIFY (whole-graph: graphify-out/graph.json; other_repo -> project_path):
  god_nodes | shortest_path | get_community | query_graph(depth=2..3) | PR_tools
  IF stale|missing -> graphify update <repo>; IF conflict_with_gortex -> trust gortex + disk file

AI_MEMORY (durable cross-session facts):
  READ: <=1 memory_search(limit=5) at session start; skip on trivial 1-turn Q&A; for Telegram handoffs MUST pass tags:["tg-<uid>"] ONLY.
  WRITE: decisions|root_causes|preferences|env_facts ONLY; content:{title, summary<=200c}, type, source, confidence, tags.
  FORBID: secrets, credentials, code derivable from graph.

BUDGET: cap results 5..10; read only exact graph-pointed line ranges.
</mcp_trio>

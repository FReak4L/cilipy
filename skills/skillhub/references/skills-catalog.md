# Skill Hub Ecosystem Catalog

Grounded directory of the 10 synced repositories under `/var/lib/agy-telegram/skillhub/repos/`.
Use `skillhub_catalog(source="...", kind="...")` or `skillhub_search(...)` for live filtered queries, and `skillhub_get(id="...")` to read any document.

---

## 1. Superpowers (`source:superpowers`, `obra/superpowers`)

### Core Skills (15)
| Name | Purpose | ID |
|------|---------|----|
| `using-superpowers` | Conversation start — skill discovery & invocation discipline | `superpowers:skills/using-superpowers/SKILL.md` |
| `brainstorming` | Explore user intent, requirements & design before creative/feature work | `superpowers:skills/brainstorming/SKILL.md` |
| `writing-plans` | Turn spec/requirements into step-by-step implementation plans | `superpowers:skills/writing-plans/SKILL.md` |
| `executing-plans` | Execute an implementation plan inline in the current session | `superpowers:skills/executing-plans/SKILL.md` |
| `subagent-driven-development` | Dispatch subagents per independent task with spec & quality reviews | `superpowers:skills/subagent-driven-development/SKILL.md` |
| `dispatching-parallel-agents` | Run 2+ independent tasks concurrently with clean ownership | `superpowers:skills/dispatching-parallel-agents/SKILL.md` |
| `test-driven-development` | Red-green-refactor discipline before writing implementation code | `superpowers:skills/test-driven-development/SKILL.md` |
| `systematic-debugging` | Root-cause investigation before proposing fixes on any bug/failure | `superpowers:skills/systematic-debugging/SKILL.md` |
| `verification-before-completion` | Fresh command verification before any done/fixed/passing claim | `superpowers:skills/verification-before-completion/SKILL.md` |
| `requesting-code-review` | Verify completed work/features against requirements before merge | `superpowers:skills/requesting-code-review/SKILL.md` |
| `receiving-code-review` | Evaluate code review feedback rigorously before applying changes | `superpowers:skills/receiving-code-review/SKILL.md` |
| `using-git-worktrees` | Create isolated git worktrees before feature/plan execution | `superpowers:skills/using-git-worktrees/SKILL.md` |
| `finishing-a-development-branch` | Decide merge / PR / cleanup once implementation & tests pass | `superpowers:skills/finishing-a-development-branch/SKILL.md` |
| `writing-skills` | Author, test, and verify new skills before deployment | `superpowers:skills/writing-skills/SKILL.md` |
| `diagnosing-superpowers` | Post-mortem for stalled/costly superpowers sessions | `superpowers:skills/diagnosing-superpowers/SKILL.md` |

### Companion Prompts & Techniques
- `superpowers:skills/brainstorming/builder-check-prompt.md`, `visual-companion.md`
- `superpowers:skills/requesting-code-review/code-reviewer.md`
- `superpowers:skills/subagent-driven-development/implementer-prompt.md`, `task-reviewer-prompt.md`, `re-review-prompt.md`
- `superpowers:skills/systematic-debugging/root-cause-tracing.md`, `defense-in-depth.md`, `condition-based-waiting.md`
- `superpowers:skills/test-driven-development/writing-good-tests.md`

---

## 2. Anthropic Official Skills (`source:anthropic-skills`, `anthropics/skills`)

20 official skills (`anthropic-skills:skills/<name>/SKILL.md`, `template-skill` at `anthropic-skills:template/SKILL.md`):
- **API, MCP & Web**: `claude-api`, `mcp-builder`, `skill-creator`, `webapp-testing`, `web-artifacts-builder`, `frontend-design`
- **Documents & Communication**: `docx`, `pdf`, `pptx`, `xlsx`, `doc-coauthoring`, `internal-comms`
- **Design & Creative**: `algorithmic-art`, `canvas-design`, `brand-guidelines`, `theme-factory`, `slack-gif-creator`
- **Guidance & Templates**: `academy-guide`, `discernment-nudge`, `template-skill`

---

## 3. Matt Pocock Skills (`source:mattpocock-skills`, `mattpocock/skills`)

39 practical engineering & productivity skills:
- **Engineering (20)**: `ask-matt`, `code-review`, `codebase-design`, `diagnosing-bugs`, `domain-modeling`, `grill-with-docs`, `implement`, `implement-spec`, `improve-codebase-architecture`, `pr`, `prototype`, `research`, `retro`, `setup-matt-pocock-skills`, `tdd`, `to-spec`, `to-tickets`, `triage`, `wayfinder`, `wizard`
- **Productivity (7)**: `grill-me`, `grilling`, `handoff`, `teach`, `to-questionnaire`, `wait-what`, `writing-for-agents`
- **In-Progress / Experimental (8)**: `chief-of-staff`, `claude-handoff`, `loop-me`, `setup-ts-deep-modules`, `software-factory`, `writing-beats`, `writing-fragments`, `writing-shape`
- **Misc / Tooling (4)**: `git-guardrails-claude-code`, `migrate-to-shoehorn`, `scaffold-exercises`, `setup-pre-commit`

---

## 4. Everything Claude Code / ECC (`source:ecc`, `affaan-m/ECC`)

328 canonical skills under `skills/`, plus modular rules under `rules/` and commands:
- **Testing & TDD**: `tdd-workflow`, `e2e-testing`, `eval-harness`, `ai-regression-testing`, `browser-qa`, `test-collaboration`, `verification-loop`, `python-testing`, `golang-testing`, `rust-testing`, `cpp-testing`, `csharp-testing`, `fsharp-testing`, `kotlin-testing`, `perl-testing`, `react-testing`, `django-tdd`, `laravel-tdd`, `quarkus-tdd`, `springboot-tdd`, `swift-protocol-di-testing`
- **Security & Audits**: `security-review`, `security-scan`, `security-bounty-hunter`, `agent-security-hardening`, `web-perimeter-owasp-2025-audit`, `defi-amm-security`, `llm-trading-agent-security`, `django-security`, `laravel-security`, `perl-security`, `quarkus-security`, `rails-security`, `springboot-security`, `mcp-dependency-review`, `gateguard`
- **Backend, Systems & Databases**: `backend-patterns`, `api-design`, `database-migrations`, `postgres-patterns`, `redis-patterns`, `clickhouse-io`, `mysql-patterns`, `prisma-patterns`, `golang-patterns`, `rust-patterns`, `python-patterns`, `fastapi-patterns`, `django-patterns`, `django-celery`, `nestjs-patterns`, `laravel-patterns`, `springboot-patterns`, `quarkus-patterns`, `rails-patterns`, `dotnet-patterns`, `hexagonal-architecture`, `latency-critical-systems`
- **Frontend, Mobile & Design**: `frontend-patterns`, `frontend-a11y`, `frontend-design-direction`, `frontend-slides`, `react-patterns`, `react-performance`, `react-native-patterns`, `nextjs-turbopack`, `nuxt4-patterns`, `vue-patterns`, `angular-developer`, `dart-flutter-patterns`, `swiftui-patterns`, `compose-multiplatform-patterns`, `design-system`, `ui-canvas`, `liquid-glass-design`
- **AI, Agents & MCP**: `agentic-engineering`, `autonomous-agent-harness`, `autonomous-loops`, `continuous-agent-loop`, `continuous-learning`, `continuous-learning-v2`, `mcp-server-patterns`, `prompt-optimizer`, `prompt-caching-strategy`, `cost-aware-llm-pipeline`, `context-budget`, `strategic-compact`, `unified-memory`, `team-agent-orchestration`, `team-builder`, `council`, `council-multi-model`, `agent-eval`
- **DevOps, Git & Ops**: `deployment-patterns`, `docker-patterns`, `kubernetes-patterns`, `terraform-patterns`, `git-workflow`, `github-ops`, `canary-watch`, `production-audit`, `homelab-wireguard-vpn`
- **Rules (`kind:rule source:ecc`)**: `common` + language-specific rules for `cpp`, `csharp`, `elixir`, `golang`, `java`, `kotlin`, `perl`, `php`, `python`, `react`, `react-native`, `ruby`, `rust`, `swift`, `typescript`, `vue`, `web`.

---

## 5. VoltAgent Subagents (`source:voltagent-subagents`)

166 specialized subagent definitions across 10 categories (`kind:agent source:voltagent-subagents`):
- `01-core-development` (13): `api-designer`, `auth-integration-engineer`, `backend-developer`, `frontend-developer`, `fullstack-developer`, `graphql-architect`, `microservices-architect`, …
- `02-language-specialists` (30): `rust-engineer`, `python-pro`, `typescript-pro`, `golang-pro`, `cpp-pro`, `java-architect`, `kotlin-specialist`, `swift-expert`, …
- `03-infrastructure` (16): `cloud-architect`, `database-administrator`, `deployment-engineer`, `devops-engineer`, `docker-expert`, `kubernetes-specialist`, `terraform-engineer`, …
- `04-quality-security` (19): `architect-reviewer`, `chaos-engineer`, `code-reviewer`, `compliance-auditor`, `debugger`, `penetration-tester`, `security-auditor`, …
- `05-data-ai` (13): `ai-engineer`, `data-analyst`, `data-engineer`, `data-scientist`, `database-optimizer`, `llm-architect`, `machine-learning-engineer`, …
- `06-developer-experience` (16): `build-engineer`, `cli-developer`, `dependency-manager`, `documentation-engineer`, `dx-optimizer`, `git-workflow-manager`, `legacy-modernizer`, …
- `07-specialized-domains` (17): `api-documenter`, `blockchain-developer`, `embedded-systems`, `fintech-engineer`, `game-developer`, `hipaa-compliance`, …
- `08-business-product` (19): `assumption-mapping`, `backlog-grooming`, `business-analyst`, `content-marketer`, `growth-loops`, …
- `09-meta-orchestration` (12): `agent-installer`, `agent-organizer`, `codebase-orchestrator`, `context-manager`, `error-coordinator`, `knowledge-synthesizer`, `memory-curator`, …
- `10-research-analysis` (11): `ab-test-analysis`, `competitive-analyst`, `data-researcher`, `first-principles-thinking`, `market-researcher`, `research-analyst`, …

---

## 6. wshobson Agents & Plugins (`source:wshobson-agents`)

91 plugins (`path:plugins/<plugin>/...`, `kind:agent|command|skill`):
- **Architecture & Review**: `c4-architecture`, `comprehensive-review`, `code-refactoring`, `codebase-cleanup`, `review-agent-governance`, `before-you-build`
- **Orchestration & Teams**: `agent-orchestration`, `agent-teams`, `conductor`, `full-stack-orchestration`, `team-collaboration`, `context-management`
- **Testing & Debugging**: `tdd-workflows`, `unit-testing`, `api-testing-observability`, `performance-testing-review`, `debugging-toolkit`, `distributed-debugging`, `error-debugging`, `error-diagnostics`
- **Security & Compliance**: `backend-api-security`, `frontend-mobile-security`, `protect-mcp`, `security-compliance`, `security-scanning`, `signed-audit-trails`, `accessibility-compliance`
- **Infra, CI/CD & Data**: `cicd-automation`, `cloud-infrastructure`, `deployment-strategies`, `deployment-validation`, `kubernetes-operations`, `database-design`, `database-migrations`, `database-cloud-optimization`, `observability-monitoring`, `incident-response`
- **Languages & AI**: `python-development`, `javascript-typescript`, `systems-programming`, `jvm-languages`, `dotnet-contribution`, `julia-development`, `llm-application-dev`, `llm-finetuning`, `machine-learning-ops`

---

## 7. Composio Skills, System Prompts & Claude Code Docs

- **`composio-skills`** (891 docs): 28 standalone workflow skills (`artifacts-builder`, `changelog-generator`, `content-research-writer`, `file-organizer`, `invoice-organizer`, `lead-research-assistant`, `mcp-builder`, `webapp-testing`, etc.) + 836 SaaS integration automation skills (`composio-skills/<app>-automation`). Query via `source:composio-skills <app_or_task>`.
- **`cc-system-prompts`** (1,295 docs, `kind:prompt`): Claude Code's internal system prompt, tool prompt, and sub-agent prompt fragments (`system-prompt-*`, `tool-description-*`, `agent-prompt-*`). Query via `source:cc-system-prompts kind:prompt <tool_or_topic>`.
- **`claude-code`** (21 docs) & **`awesome-claude-code`** (6 docs): Official Claude Code gateway/settings/mods docs and ecosystem directory.

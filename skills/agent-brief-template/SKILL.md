---
name: agent-brief-template
description: >-
  Template and checklist for writing a self-contained brief (task handoff) for a subagent, swarm
  worker or another session, so it can work without the parent's context. Use every time you
  delegate work to another agent, start an Antigravity swarm worker, or hand off a session.
metadata:
  skillport:
    category: multi-agent
    tags: [multi-agent, delegation, brief, handoff, subagent]
---
# Agent brief template

A worker starts with **zero context**: it has not seen the conversation, the user, or what you
read. The brief is everything it gets. Missing context gets invented.

```
ROLE: <coder | tester | researcher | reviewer | …> — name: <job-name>
GOAL: <one sentence outcome, tied to the user's real goal>
CONTEXT: <verified facts it needs and cannot cheaply find: paths, versions, decisions,
          ai-memory ids, relevant gortex/graphify findings, links>
OWNS: <files / dirs / resources it may change>        MUST NOT TOUCH: <everything else that matters>
CONSTRAINTS: <style, deps allowed, no secrets in output, no destructive ops, time/budget>
STEPS / HINTS (optional): <known approach or skill to load, e.g. skillport: systematic-debugging>
DONE WHEN: <observable checks: command + expected result>
REPORT: post `[done]` with: summary · files changed · commands run + key output ·
        assumptions made · open issues/risks. If blocked: `[blocked]` + what you need.
SHARED STATE: read ai-memory for <topic> first; store final decisions with title+summary.
```

Checklist before sending
- Could a competent stranger do this with only the brief? If not, add the missing fact.
- Is ownership disjoint from every other worker's? Is "done" testable?
- No secrets in the brief (swarm briefs are public on the board). Point to a file path instead.
- One task per brief. If you wrote "and also", consider a second worker.
- Ask for evidence, not reassurance.

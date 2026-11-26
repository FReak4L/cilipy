# 09 · Parallel mode

A user can turn on **Parallel** (Settings → Parallel: Off / 2 / 3 agents, or `/parallel 2|3|off`;
one-off: `/parallel N <task>`). The bridge then runs a request
in three phases. Rules for you: `~/.gemini/config/rules/parallel-agents.md`.

1. **Plan** (`[parallel-plan run=… max=N]`, in the user's lead conversation). Decide whether
   splitting is worth it. If not, just answer. If yes, reply with only the JSON plan:
   `subtasks[]` with `id`, `title`, `brief`, `owns` (paths/globs it may modify), `readonly`,
   `depends_on`, `needs_worktree`, plus `merge_instructions`.
2. **Mothers** (`[parallel-worker k/N run=…]`): one agy process per subtask, each in a new
   conversation, run as the project agent **`tg-mother`**
   (`/root/agy-workspace/.agents/agents/tg-mother/agent.md`). A mother never starts `/swarm`.
   It ends with a JSON line `{"status": "done|partial|blocked", "summary": "…", …}`.
3. **Merge** (`[parallel-merge run=…]`, back in the lead conversation): combine results, merge
   worktree branches, verify, answer once.

## How the bridge schedules mothers
- **Distinct accounts:** each mother prefers an account no other running mother holds. Accounts
  are shared (least-loaded) only when there are more mothers than healthy accounts. Failover per
  mother works like a normal job.
- **Width** is capped by healthy accounts × per-account concurrency and by free RAM.
- `depends_on` is honoured. Writers whose `owns` overlap run **one after another**, unless they
  are isolated in worktrees (below).
- Shared run dir: `/root/agy-workspace/.parallel/<run>/` (`board.md`, `agents/<k>/result.md`).
  Status message with per-agent Stop buttons and Stop all.

## Worktrees (overlapping writers)
When the workspace is a git repo and two writers' `owns` overlap (or `needs_worktree: true`),
each gets its own git worktree `.parallel/<run>/wt/<k>` on branch `par/<run>/<k>`, based on the
current tree (tracked changes included; untracked files are not copied). The mother edits only
there and commits on its branch. Uncommitted leftovers are auto-committed by the bridge. The
merge prompt lists the branches (`git merge --no-ff par/<run>/<k>`). Afterwards worktrees are
removed. Merged branches are deleted. Unmerged branches are kept and reported to the user.
`.parallel/` and the copied agent file are added to the repo-local `.git/info/exclude`.

Workspace trust: worktrees live under `/root`, which is in `trustedWorkspaces`. A stuck run is
still killed by the bridge hard timeout.

## Ownership check (shared tree)
For mothers in the shared tree the bridge snapshots `git status` (with content hashes) at start
and end. Any changed file that neither this mother nor another writer owns (or any change by a
read-only mother) is an **ownership conflict**. It shows on the status board, goes into the merge
prompt, and is listed in the final answer's notes.

---
name: ultra-quota-advisor
description: Zero-ban-risk Antigravity / Grok / Gemini Web quota advisor and multi-pool routing procedure for agy-telegram (adapted from IMYin/google-ultra-maximizer).
---

# Ultra Quota Advisor (`agy-telegram`)

## Purpose
Maximize sustained throughput across Antigravity accounts (`AccountStore`), Grok OAuth, Grok Bot, Venice Uncensored, and Gemini Manager while strictly preserving the **1% weekly reserve**, **fail-closed sticky proxies**, and **zero ban risk**.

## Hard Safety Rules
1. **Local telemetry only:** Read quota/burn state exclusively from `/quota`, the built-in `telemetry` widget, `accounts.json` 5h/7d token counters, and read-only local SQLite activity (`conversation_summaries.db`).
2. **Never scrape unofficial Google OAuth endpoints** or extract browser cookies.
3. **Never disable fail-closed sticky proxies** or bypass the weekly 1% reserve (`weekly_reserve_pct`).
4. **Mask all identities:** Never print raw emails, OAuth tokens, proxy credentials, or owner UIDs in reports.

## Routing Decision Matrix
| Mode | Condition | Recommended Action |
|---|---|---|
| `dual_ready` | >= 2 healthy AGY accounts < 70% weekly | Run deep engineering tasks on AGY; let least-loaded spread 2 owners automatically |
| `harvest_5h` | 5h window resets in <= 60m & weekly <= 60% | Front-load heavy coding / review turns now before the 5h bucket resets |
| `protect_weekly` | Primary AGY >= 85% weekly or 0 AGY slots ready | Shift chat, research, and overflow turns to **Grok OAuth** (`/grok`) or **Gemini Web** (`/gemini`) |
| `conserve` | All pools constrained / cooling down | Use local fast-path, `/effort low`, compact turns, and inspect `/accounts` + `/proxies` |

## Multi-Owner Playbook
- When 2 owners run concurrently on 1 active AGY account, the peer-busy card shows who holds the slot, elapsed time, queue position `#N`, and instant one-tap switch buttons (`⚡ Grok`, `💎 Gemini Web`).
- Use `/limits` to tune `Global Jobs`, `User Queue`, and `AI Burst` live without restarting the daemon.
- Use `/quota` (or `/widget telemetry`) for a live zero-token cockpit snapshot and deterministic burn advice.

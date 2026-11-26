//! RBAC policy engine, Anti-Ban AI quota/concurrency guard, and runaway Loop Circuit Breaker.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::AuthenticatedPrincipal;
use crate::config::{GatewayConfigStore, GatewayMode, RiskAction, SectionId};
use crate::sanitize::find_forbidden_arg_path;

/// Classification of a tool's side-effect risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRisk {
    ReadOnly,
    Write,
    HighRiskExec,
    AiModelRun,
    OwnerAdmin,
}

/// Decision returned by [`PolicyEngine::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireHitl { reason: String },
    Deny { reason: String },
}

fn day_bucket_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

fn call_signature(principal_id: &str, tool: &str, args: &Value) -> String {
    let mut h = Sha256::new();
    h.update(principal_id.as_bytes());
    h.update(b"|");
    h.update(tool.as_bytes());
    h.update(b"|");
    let raw = serde_json::to_string(args).unwrap_or_default();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Runtime enforcement engine protecting accounts, workspace, and server stability.
pub struct PolicyEngine {
    cfg_store: Arc<GatewayConfigStore>,
    /// Identical-call timestamps within a 30s sliding window for runaway agent loop detection.
    loop_window: DashMap<String, VecDeque<Instant>>,
    /// Per-principal daily AI call counters: `(day_bucket, count)`.
    daily_ai_counts: DashMap<String, (u64, u32)>,
    /// Dedicated semaphore capping concurrent MCP AI model executions (anti-ban protection).
    ai_sem: Arc<Semaphore>,
}

impl PolicyEngine {
    pub fn new(cfg_store: Arc<GatewayConfigStore>) -> Self {
        let cap = cfg_store.snapshot().limits.max_mcp_ai_concurrency;
        Self {
            cfg_store,
            loop_window: DashMap::new(),
            daily_ai_counts: DashMap::new(),
            ai_sem: Arc::new(Semaphore::new(cap)),
        }
    }

    /// Evaluate whether `principal` is allowed to invoke `tool` in `section`.
    pub fn evaluate(
        &self,
        principal: &AuthenticatedPrincipal,
        section: SectionId,
        tool: &str,
        risk: ToolRisk,
        args: &Value,
    ) -> PolicyDecision {
        let cfg = self.cfg_store.snapshot();

        // 1. Global Kill Switch / ReadOnly mode
        match cfg.mode {
            GatewayMode::Disabled => {
                return PolicyDecision::Deny {
                    reason: "MCP gateway is currently disabled by owner kill switch".to_string(),
                };
            }
            GatewayMode::ReadOnly if risk != ToolRisk::ReadOnly => {
                return PolicyDecision::Deny {
                    reason: "MCP gateway is in Read-Only maintenance mode".to_string(),
                };
            }
            _ => {}
        }

        // 2. Global section toggle & principal section scope
        if !cfg.is_section_enabled(section) {
            return PolicyDecision::Deny {
                reason: format!("Section '{}' is disabled by owner", section.slug()),
            };
        }
        if !principal.is_owner && !principal.has_section(section) {
            return PolicyDecision::Deny {
                reason: format!(
                    "Key '{}' lacks scope for section '{}'",
                    principal.label,
                    section.slug()
                ),
            };
        }

        // 3. Hard secret path deny-list (even Owner remote keys cannot exfiltrate tokens!)
        if let Some(bad) = find_forbidden_arg_path(args) {
            return PolicyDecision::Deny {
                reason: format!("Access to protected credential path is forbidden: {bad}"),
            };
        }

        // 4. Capability checks by risk level
        match risk {
            ToolRisk::ReadOnly => {}
            ToolRisk::Write => {
                if !principal.allow_write {
                    return PolicyDecision::Deny {
                        reason: format!("Tool '{tool}' requires write scope"),
                    };
                }
            }
            ToolRisk::HighRiskExec => {
                if !principal.allow_exec {
                    return PolicyDecision::Deny {
                        reason: format!("Tool '{tool}' requires exec scope"),
                    };
                }
            }
            ToolRisk::AiModelRun => {
                if !principal.allow_models_run {
                    return PolicyDecision::Deny {
                        reason: format!("Tool '{tool}' requires models:run scope"),
                    };
                }
            }
            ToolRisk::OwnerAdmin => {
                if !principal.is_owner {
                    return PolicyDecision::Deny {
                        reason: format!("Tool '{tool}' is restricted to Owner keys"),
                    };
                }
            }
        }

        // 5. Runaway loop circuit breaker (stops external agent loops burning quota/CPU)
        if !self.check_loop_breaker(&principal.principal_id, tool, args, cfg.limits.loop_breaker_limit) {
            return PolicyDecision::Deny {
                reason: format!(
                    "Loop circuit breaker tripped: identical call to '{tool}' repeated >{} times in 30s",
                    cfg.limits.loop_breaker_limit
                ),
            };
        }

        // 6. Daily AI budget check (anti-ban quota protection)
        if risk == ToolRisk::AiModelRun {
            let cap = principal
                .daily_ai_cap
                .unwrap_or(cfg.limits.default_daily_ai_cap);
            if cap > 0 && !self.check_daily_ai_budget(&principal.principal_id, cap) {
                return PolicyDecision::Deny {
                    reason: format!("Daily AI execution cap ({cap}) reached for key '{}'", principal.label),
                };
            }
        }

        // 7. HITL (Human-in-the-Loop Telegram approval) for HighRiskExec
        if risk == ToolRisk::HighRiskExec {
            let action = if principal.is_owner {
                cfg.owner_high_risk_action
            } else {
                cfg.non_owner_high_risk_action
            };
            return match action {
                RiskAction::Allow => PolicyDecision::Allow,
                RiskAction::AskTelegram => PolicyDecision::RequireHitl {
                    reason: format!("High-risk tool '{tool}' requires Owner approval in Telegram"),
                },
                RiskAction::Deny => PolicyDecision::Deny {
                    reason: format!("High-risk tool '{tool}' is blocked by gateway policy"),
                },
            };
        }

        PolicyDecision::Allow
    }

    fn check_loop_breaker(&self, principal_id: &str, tool: &str, args: &Value, limit: u32) -> bool {
        let sig = call_signature(principal_id, tool, args);
        let now = Instant::now();
        if self.loop_window.len() > 2048 {
            self.loop_window.clear();
        }
        let mut entry = self.loop_window.entry(sig).or_default();
        while let Some(&front) = entry.front() {
            if now.duration_since(front).as_secs() > 30 {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= limit as usize {
            return false;
        }
        entry.push_back(now);
        true
    }

    fn check_daily_ai_budget(&self, principal_id: &str, cap: u32) -> bool {
        let today = day_bucket_utc();
        let mut entry = self
            .daily_ai_counts
            .entry(principal_id.to_string())
            .or_insert((today, 0));
        if entry.0 != today {
            *entry = (today, 0);
        }
        if entry.1 >= cap {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }

    /// Acquire a bounded MCP AI execution permit (prevents concurrent bursts from banning accounts).
    pub fn try_acquire_ai_slot(&self) -> Option<OwnedSemaphorePermit> {
        let max_allowed = self.cfg_store.snapshot().limits.max_mcp_ai_concurrency;
        if max_allowed == 0 {
            return None;
        }
        self.ai_sem.clone().try_acquire_owned().ok()
    }

    pub fn active_ai_slots_available(&self) -> usize {
        self.ai_sem.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthKind, KeyPreset};
    use serde_json::json;
    use tempfile::TempDir;

    fn dev_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            principal_id: "key:dev1".to_string(),
            label: "dev1".to_string(),
            auth_kind: AuthKind::ApiKey,
            sections: KeyPreset::Developer.default_sections(),
            allow_write: true,
            allow_exec: true,
            allow_models_run: true,
            allow_root_access: false,
            is_owner: false,
            rpm_override: None,
            daily_ai_cap: Some(2),
        }
    }

    #[test]
    fn policy_blocks_forbidden_paths_trips_loop_breaker_and_enforces_hitl_and_ai_cap() {
        let dir = TempDir::new().unwrap();
        let cfg = Arc::new(GatewayConfigStore::open(dir.path().join("gw.json")).unwrap());
        cfg.update(|c| c.limits.loop_breaker_limit = 3).unwrap();
        let eng = PolicyEngine::new(Arc::clone(&cfg));
        let dev = dev_principal();

        // Forbidden credential path blocked
        assert!(matches!(
            eng.evaluate(
                &dev,
                SectionId::Openhands,
                "oh_file_editor",
                ToolRisk::ReadOnly,
                &json!({"path": "/var/lib/agy-telegram/accounts/acc1/token"})
            ),
            PolicyDecision::Deny { .. }
        ));

        // HighRiskExec for non-owner triggers AskTelegram HITL by default
        assert!(matches!(
            eng.evaluate(
                &dev,
                SectionId::Openhands,
                "oh_execute_code",
                ToolRisk::HighRiskExec,
                &json!({"code": "print(1)"})
            ),
            PolicyDecision::RequireHitl { .. }
        ));

        // Loop circuit breaker trips on 4th identical call within 30s
        let args = json!({"query": "same"});
        for _ in 0..3 {
            assert_eq!(
                eng.evaluate(&dev, SectionId::Search, "search_web_v3", ToolRisk::ReadOnly, &args),
                PolicyDecision::Allow
            );
        }
        assert!(matches!(
            eng.evaluate(&dev, SectionId::Search, "search_web_v3", ToolRisk::ReadOnly, &args),
            PolicyDecision::Deny { .. }
        ));

        // Daily AI cap = 2 blocks 3rd AI call
        assert_eq!(
            eng.evaluate(&dev, SectionId::Models, "models_run", ToolRisk::AiModelRun, &json!({"p": 1})),
            PolicyDecision::Allow
        );
        assert_eq!(
            eng.evaluate(&dev, SectionId::Models, "models_run", ToolRisk::AiModelRun, &json!({"p": 2})),
            PolicyDecision::Allow
        );
        assert!(matches!(
            eng.evaluate(&dev, SectionId::Models, "models_run", ToolRisk::AiModelRun, &json!({"p": 3})),
            PolicyDecision::Deny { .. }
        ));

        // Dedicated MCP AI concurrency semaphore (default 2)
        let p1 = eng.try_acquire_ai_slot();
        let p2 = eng.try_acquire_ai_slot();
        let p3 = eng.try_acquire_ai_slot();
        assert!(p1.is_some() && p2.is_some() && p3.is_none());
    }
}

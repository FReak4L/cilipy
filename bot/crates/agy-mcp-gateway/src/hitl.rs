//! Human-in-the-Loop (HITL) Telegram Owner approval broker for high-risk MCP tool invocations.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitlDecision {
    AllowOnce,
    AllowSession,
    Deny,
    TimedOut,
}

struct PendingHitl {
    principal_id: String,
    tool_name: String,
    tx: oneshot::Sender<HitlDecision>,
}

/// Coordinates pending Owner inline approvals in Telegram (`mcpgw:hitl:...`) and session-level grants.
pub struct HitlBroker {
    pending: DashMap<String, PendingHitl>,
    /// Session grants: `principal_id -> (expires_at, allowed_tool_names)`.
    session_grants: DashMap<String, (Instant, HashSet<String>)>,
}

impl Default for HitlBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl HitlBroker {
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
            session_grants: DashMap::new(),
        }
    }

    pub fn has_session_grant(&self, principal_id: &str, tool_name: &str) -> bool {
        if let Some(entry) = self.session_grants.get(principal_id) {
            if Instant::now() < entry.0 && entry.1.contains(tool_name) {
                return true;
            }
        }
        false
    }

    /// Create a pending HITL request returning `(req_id, receiver)`.
    pub fn create_request(
        &self,
        principal_id: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> (String, oneshot::Receiver<HitlDecision>) {
        let req_id = Uuid::new_v4().simple().to_string()[..12].to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(
            req_id.clone(),
            PendingHitl {
                principal_id: principal_id.into(),
                tool_name: tool_name.into(),
                tx,
            },
        );
        (req_id, rx)
    }

    /// Wait up to `timeout` for Owner resolution, automatically cleaning up on timeout.
    pub async fn wait_for(
        &self,
        req_id: &str,
        rx: oneshot::Receiver<HitlDecision>,
        timeout: Duration,
    ) -> HitlDecision {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(dec)) => dec,
            _ => {
                self.pending.remove(req_id);
                HitlDecision::TimedOut
            }
        }
    }

    /// Called by Telegram Owner callback handler (`mcpgw:hitl:once|sess|no:<req_id>`).
    pub fn resolve(&self, req_id: &str, decision: HitlDecision) -> bool {
        let Some((_, entry)) = self.pending.remove(req_id) else {
            return false;
        };
        if decision == HitlDecision::AllowSession {
            let mut grant = self
                .session_grants
                .entry(entry.principal_id)
                .or_insert_with(|| (Instant::now() + Duration::from_secs(3600), HashSet::new()));
            grant.0 = Instant::now() + Duration::from_secs(3600);
            grant.1.insert(entry.tool_name);
        }
        let _ = entry.tx.send(decision);
        true
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hitl_broker_resolves_once_and_session_grants() {
        let broker = HitlBroker::new();
        let (id, rx) = broker.create_request("key:dev1", "oh_execute_code");
        assert!(broker.resolve(&id, HitlDecision::AllowSession));
        let dec = broker.wait_for(&id, rx, Duration::from_secs(1)).await;
        assert_eq!(dec, HitlDecision::AllowSession);
        assert!(broker.has_session_grant("key:dev1", "oh_execute_code"));
        assert!(!broker.has_session_grant("key:dev1", "oh_git_ops"));
    }
}

//! Async background task manager for long-running MCP tool executions (>45s) so clients
//! behind Cloudflare (`gateway.example.com`, 100s timeout) never suffer Error 524.

use std::future::Future;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use uuid::Uuid;

const MAX_RETAINED_TASKS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSnapshot {
    pub task_id: String,
    pub principal_id: String,
    pub tool_name: String,
    pub status: TaskStatus,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

struct TaskRecord {
    snapshot: TaskSnapshot,
    cancel_tx: watch::Sender<bool>,
}

pub struct TaskManager {
    tasks: DashMap<String, TaskRecord>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            tasks: DashMap::new(),
        }
    }

    pub fn spawn_tracked<F, Fut>(
        self: &Arc<Self>,
        principal_id: impl Into<String>,
        tool_name: impl Into<String>,
        work: F,
    ) -> String
    where
        F: FnOnce(watch::Receiver<bool>) -> Fut + Send + 'static,
        Fut: Future<Output = std::result::Result<Value, String>> + Send + 'static,
    {
        if self.tasks.len() >= MAX_RETAINED_TASKS {
            self.prune_finished();
        }
        let task_id = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let snap = TaskSnapshot {
            task_id: task_id.clone(),
            principal_id: principal_id.into(),
            tool_name: tool_name.into(),
            status: TaskStatus::Running,
            created_at: Utc::now().timestamp(),
            finished_at: None,
            result: None,
            error: None,
        };
        self.tasks.insert(
            task_id.clone(),
            TaskRecord {
                snapshot: snap,
                cancel_tx,
            },
        );

        let mgr = Arc::clone(self);
        let tid = task_id.clone();
        tokio::spawn(async move {
            let outcome = work(cancel_rx).await;
            if let Some(mut rec) = mgr.tasks.get_mut(&tid) {
                rec.snapshot.finished_at = Some(Utc::now().timestamp());
                if rec.snapshot.status == TaskStatus::Cancelled {
                    return;
                }
                match outcome {
                    Ok(v) => {
                        rec.snapshot.status = TaskStatus::Completed;
                        rec.snapshot.result = Some(v);
                    }
                    Err(e) => {
                        rec.snapshot.status = TaskStatus::Failed;
                        rec.snapshot.error = Some(e);
                    }
                }
            }
        });

        task_id
    }

    pub fn get(&self, task_id: &str, principal_id: &str, is_owner: bool) -> Option<TaskSnapshot> {
        self.tasks.get(task_id).and_then(|r| {
            if is_owner || r.snapshot.principal_id == principal_id {
                Some(r.snapshot.clone())
            } else {
                None
            }
        })
    }

    pub fn cancel(&self, task_id: &str, principal_id: &str, is_owner: bool) -> bool {
        if let Some(mut rec) = self.tasks.get_mut(task_id) {
            if !is_owner && rec.snapshot.principal_id != principal_id {
                return false;
            }
            if rec.snapshot.status == TaskStatus::Running {
                rec.snapshot.status = TaskStatus::Cancelled;
                rec.snapshot.finished_at = Some(Utc::now().timestamp());
                let _ = rec.cancel_tx.send(true);
                return true;
            }
        }
        false
    }

    pub fn cancel_all(&self) -> usize {
        let mut n = 0usize;
        for mut rec in self.tasks.iter_mut() {
            if rec.snapshot.status == TaskStatus::Running {
                rec.snapshot.status = TaskStatus::Cancelled;
                rec.snapshot.finished_at = Some(Utc::now().timestamp());
                let _ = rec.cancel_tx.send(true);
                n += 1;
            }
        }
        n
    }

    pub fn running_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|r| r.snapshot.status == TaskStatus::Running)
            .count()
    }

    fn prune_finished(&self) {
        let finished: Vec<String> = self
            .tasks
            .iter()
            .filter(|r| r.snapshot.status != TaskStatus::Running)
            .map(|r| r.key().clone())
            .take(MAX_RETAINED_TASKS / 2)
            .collect();
        for k in finished {
            self.tasks.remove(&k);
        }
    }
}

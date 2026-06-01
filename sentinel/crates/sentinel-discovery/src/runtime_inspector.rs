//! Runtime inspector — finds MCP server processes currently running.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessusObserve {
    pub pid: u32,
    pub command: String,
    pub args: Vec<String>,
    pub parent_pid: Option<u32>,
    /// Heuristic-derived guess at the AI client that spawned this process.
    pub probable_client: Option<String>,
}

pub struct InspecteurRuntime;

impl InspecteurRuntime {
    /// Scans running processes for MCP-server-like patterns.
    /// Implemented by the runtime-inspector agent.
    pub async fn scanner() -> Vec<ProcessusObserve> {
        vec![]
    }
}

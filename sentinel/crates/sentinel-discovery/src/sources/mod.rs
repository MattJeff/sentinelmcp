//! Per-client discovery sources. One module per AI client.
//!
//! Each module exposes a struct implementing [`SourceClient`].
//! Adding a new client = drop a new module + add it to `sources_par_defaut()`.

use crate::model::ClientDecouvert;
use async_trait::async_trait;

pub mod os_paths;
pub mod claude_desktop;
pub mod claude_code_cli;
pub mod cursor;
pub mod windsurf;
pub mod continuedev;
pub mod zed;
pub mod vscode;
pub mod aider;
pub mod goose;
pub mod codex;
pub mod antigravity;
pub mod lmstudio;

#[async_trait]
pub trait SourceClient: Send + Sync {
    /// Short identifier of the source ("claude-desktop", "cursor", …).
    fn id(&self) -> &'static str;

    /// Run the detection. Returns one or more `ClientDecouvert` if found.
    /// Returns an empty vec if the client isn't installed.
    async fn detecter(&self) -> Vec<ClientDecouvert>;
}

/// Default set of detection sources used by the orchestrator.
pub fn sources_par_defaut() -> Vec<Box<dyn SourceClient>> {
    vec![
        Box::new(claude_desktop::SourceClaudeDesktop),
        Box::new(claude_code_cli::SourceClaudeCodeCli),
        Box::new(cursor::SourceCursor),
        Box::new(windsurf::SourceWindsurf::new()),
        Box::new(continuedev::SourceContinuedev),
        Box::new(zed::SourceZed::new()),
        Box::new(vscode::SourceVscode),
        Box::new(aider::SourceAider),
        Box::new(goose::SourceGoose),
        Box::new(codex::SourceCodex),
        Box::new(antigravity::SourceAntigravity),
        Box::new(lmstudio::SourceLmstudio),
    ]
}

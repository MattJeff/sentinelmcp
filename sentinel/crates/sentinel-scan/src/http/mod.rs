//! Capture HTTP Streamable — transport MCP sur Streamable HTTP (POST + GET/SSE).
//!
//! Ce module fournit :
//! - [`CaptureHttp`] : proxy HTTP passif (mode A) qui observe le trafic MCP.
//! - [`SuiviSessionsHttp`] : table des sessions regroupées par `Mcp-Session-Id`.
//! - `sse` : parseur de flux Server-Sent Events.
//!
//! Seul `CaptureHttp` est nécessaire à l'orchestrateur. Les autres types sont
//! exposés pour les tests et l'agent 1.3 (normaliseur).

pub mod capture;
pub mod proxy;
pub mod sessions;
pub mod sse;

pub use capture::CaptureHttp;
pub use proxy::ProxyMcp;
pub use sessions::SuiviSessionsHttp;

//! Sinks SIEM externes (Splunk HEC, Elastic, Syslog, etc.).
//!
//! Modules : `splunk` (V17), `elastic` (V18), `syslog` (V18).

pub mod splunk;
pub mod elastic;
pub mod syslog;

pub use splunk::{ClientSplunkHec, SinkError};

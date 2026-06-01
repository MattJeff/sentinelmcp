//! Canaux d'alerte (dashboard, email, webhook).

pub mod dashboard;
pub mod email;
pub mod webhook;

use async_trait::async_trait;
use sentinel_protocol::Alerte;

#[async_trait]
pub trait CanalEmetteur: Send + Sync {
    async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()>;
    fn nom(&self) -> &'static str;
}

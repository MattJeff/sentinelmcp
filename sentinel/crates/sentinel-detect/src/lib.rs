//! sentinel-detect — Module 3. Empreinte canonique, rug-pull, poisoning, sosies.

pub mod canonical;
pub mod fingerprint;
pub mod diff;
pub mod rugpull;
pub mod poisoning;
pub mod exfiltration;
pub mod sampling;
pub mod shadowing;
pub mod cve_match;
pub mod lookalikes;
pub mod corpus;
pub mod yara;
pub mod llm_judge;

pub use canonical::canonicaliser_json;
pub use fingerprint::{empreinte_outil, empreinte_serveur, empreintes_par_outil};
pub use diff::{diff_outils, RenduDiff};
pub use rugpull::DetecteurRugPull;
pub use poisoning::{ConfigDetection, ConstatPoisoning, InspecteurPoisoning};
pub use exfiltration::{
    est_entree_non_fiable, DetecteurExfiltration, SignalExfiltration, SignalTrifecta,
};
pub use sampling::{ConfigSampling, DetecteurSampling, NatureSignalSampling, SignalSampling};
// D5 — tool shadowing inter-serveurs. La fonction `shadowing::vers_constat`
// reste accessible via le chemin de module (homonyme de `cve_match::vers_constat`).
pub use shadowing::{detecter_shadowing, ConstatShadowing, InventaireServeur, NatureShadowing};
// D8 — matching CVE/OSV hors-ligne. `cve_match::vers_constat` via chemin de module.
pub use cve_match::{rechercher_cve, severite_depuis_cvss, ConstatCve};
pub use lookalikes::ConnecteurRegistres;
pub use yara::{ConstatYara, MoteurYara};
pub use llm_judge::{ConfigJugeLlm, JugeLlm, VerdictLlm, OLLAMA_DEFAULT_URL};

/// Identifiant **déterministe et stable** d'un constat.
///
/// Deux re-détections du même constat logique (même serveur, même outil, même
/// règle/pattern…) produisent le MÊME identifiant — la clé ne contient ni
/// horodatage ni aléa. Le store déduplique alors via UPSERT au lieu d'empiler un
/// doublon à chaque cycle de surveillance. Des constats *distincts* gardent des
/// identifiants distincts (la clé encode tout ce qui les différencie).
///
/// Utilise UUID v5 (SHA-1 d'une clé namespacée) : reproductible entre exécutions
/// et entre machines, sans état partagé.
pub fn id_constat(parties: &[&str]) -> uuid::Uuid {
    // U+001F (Unit Separator) — improbable dans les noms d'outils/règles, évite
    // les collisions de concaténation (« a|b » vs « a », « b »).
    let cle = parties.join("\u{1f}");
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, cle.as_bytes())
}

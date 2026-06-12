//! sentinel-detect — Module 3. Empreinte canonique, rug-pull, poisoning, sosies.

pub mod canonical;
pub mod fingerprint;
pub mod diff;
pub mod rugpull;
pub mod poisoning;
pub mod exfiltration;
pub mod sampling;
pub mod lookalikes;
pub mod corpus;
pub mod yara;
pub mod llm_judge;

pub use canonical::canonicaliser_json;
pub use fingerprint::{empreinte_outil, empreinte_serveur, empreintes_par_outil};
pub use diff::{diff_outils, RenduDiff};
pub use rugpull::DetecteurRugPull;
pub use poisoning::{InspecteurPoisoning, ConstatPoisoning};
pub use exfiltration::DetecteurExfiltration;
pub use sampling::{ConfigSampling, DetecteurSampling, NatureSignalSampling, SignalSampling};
pub use lookalikes::ConnecteurRegistres;
pub use yara::{ConstatYara, MoteurYara};
pub use llm_judge::{ConfigJugeLlm, JugeLlm, VerdictLlm, OLLAMA_DEFAULT_URL};

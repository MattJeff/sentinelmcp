//! sentinel-detect — Module 3. Empreinte canonique, rug-pull, poisoning, sosies.

pub mod canonical;
pub mod fingerprint;
pub mod diff;
pub mod rugpull;
pub mod poisoning;
pub mod exfiltration;
pub mod lookalikes;
pub mod corpus;

pub use canonical::canonicaliser_json;
pub use fingerprint::{empreinte_outil, empreinte_serveur, empreintes_par_outil};
pub use diff::{diff_outils, RenduDiff};
pub use rugpull::DetecteurRugPull;
pub use poisoning::{InspecteurPoisoning, ConstatPoisoning};
pub use exfiltration::DetecteurExfiltration;
pub use lookalikes::ConnecteurRegistres;

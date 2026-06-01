//! Signature cryptographique Ed25519 et horodatage — agent 5.5.

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Structures publiques
// ---------------------------------------------------------------------------

/// Paire de clés Ed25519 utilisée pour signer les bundles.
pub struct SignataireBundle {
    pub cle_secrete: Vec<u8>,  // 32 bytes — graine de la SigningKey
    pub cle_publique: Vec<u8>, // 32 bytes — VerifyingKey
}

/// Bundle signé renvoyé par `signer_bundle`.
#[derive(Debug, Clone)]
pub struct BundleSigne {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,           // 64 bytes Ed25519
    pub cle_publique: Vec<u8>,        // 32 bytes
    pub horodatage: DateTime<Utc>,
    pub horodatage_iso8601: String,   // RFC 3339 / ISO 8601
}

// ---------------------------------------------------------------------------
// Implémentation
// ---------------------------------------------------------------------------

impl SignataireBundle {
    /// Génère une nouvelle paire (cle_secrete, cle_publique) via OsRng.
    pub fn generer() -> Self {
        let cle_signature = SigningKey::generate(&mut OsRng);
        let cle_secrete = cle_signature.to_bytes().to_vec();
        let cle_publique = cle_signature.verifying_key().to_bytes().to_vec();
        Self { cle_secrete, cle_publique }
    }

    /// Recharge un `SignataireBundle` depuis 32 bytes de graine existants.
    pub fn depuis_bytes(secret: &[u8]) -> anyhow::Result<Self> {
        let octets: [u8; 32] = secret
            .try_into()
            .map_err(|_| anyhow!("la clé secrète doit faire exactement 32 bytes"))?;
        let cle_signature = SigningKey::from_bytes(&octets);
        let cle_secrete = cle_signature.to_bytes().to_vec();
        let cle_publique = cle_signature.verifying_key().to_bytes().to_vec();
        Ok(Self { cle_secrete, cle_publique })
    }

    /// Signe `payload` et retourne la signature brute (64 bytes).
    pub fn signer(&self, payload: &[u8]) -> Vec<u8> {
        let cle = self.cle_interne();
        cle.sign(payload).to_bytes().to_vec()
    }

    /// Signe `payload` et retourne un [`BundleSigne`] complet avec horodatage.
    pub fn signer_bundle(&self, payload: Vec<u8>) -> BundleSigne {
        let signature = self.signer(&payload);
        let horodatage = Utc::now();
        let horodatage_iso8601 = horodatage.to_rfc3339();
        BundleSigne {
            payload,
            signature,
            cle_publique: self.cle_publique.clone(),
            horodatage,
            horodatage_iso8601,
        }
    }

    // Reconstruction interne de la SigningKey — infaillible car les bytes ont
    // été validés à la création.
    fn cle_interne(&self) -> SigningKey {
        let octets: [u8; 32] = self.cle_secrete.as_slice().try_into()
            .expect("cle_secrete toujours 32 bytes");
        SigningKey::from_bytes(&octets)
    }
}

// ---------------------------------------------------------------------------
// Fonctions de vérification publiques
// ---------------------------------------------------------------------------

/// Vérifie la cohérence cryptographique d'un [`BundleSigne`].
pub fn verifier(bundle: &BundleSigne) -> anyhow::Result<bool> {
    Ok(verifier_signature(&bundle.cle_publique, &bundle.payload, &bundle.signature))
}

/// Vérifie une signature Ed25519 brute.
///
/// Retourne `false` (pas d'erreur) si les bytes sont invalides ou si la
/// vérification échoue, afin de simplifier l'usage dans les pipelines.
pub fn verifier_signature(cle_publique: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    let octets_cle: [u8; 32] = match cle_publique.try_into() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let cle_verif = match VerifyingKey::from_bytes(&octets_cle) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let octets_sig: [u8; 64] = match signature.try_into() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&octets_sig);
    cle_verif.verify(payload, &sig).is_ok()
}

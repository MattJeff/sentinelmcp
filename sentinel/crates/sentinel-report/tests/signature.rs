//! Tests de signature cryptographique Ed25519 — agent 5.5.

use sentinel_report::signature::{
    verifier, verifier_signature, SignataireBundle,
};

/// Les clés générées ont exactement 32 bytes chacune.
#[test]
fn generer_produit_cles_32_bytes() {
    let signataire = SignataireBundle::generer();
    assert_eq!(signataire.cle_secrete.len(), 32, "clé secrète doit faire 32 bytes");
    assert_eq!(signataire.cle_publique.len(), 32, "clé publique doit faire 32 bytes");
}

/// Round-trip : signer puis vérifier retourne `true`.
#[test]
fn signer_puis_verifier_round_trip() {
    let signataire = SignataireBundle::generer();
    let payload = b"bundle-sentinel-conformite-mcp09";
    let signature = signataire.signer(payload);
    let valide = verifier_signature(&signataire.cle_publique, payload, &signature);
    assert!(valide, "la signature doit être valide après round-trip");
}

/// Un payload modifié invalide la signature.
#[test]
fn payload_modifie_invalide_signature() {
    let signataire = SignataireBundle::generer();
    let payload_original = b"rapport-conforme-owasp-mcp03";
    let signature = signataire.signer(payload_original);

    let payload_altere = b"rapport-conforme-owasp-mcp03-ALTERE";
    let valide = verifier_signature(&signataire.cle_publique, payload_altere, &signature);
    assert!(!valide, "la signature ne doit pas être valide avec un payload différent");
}

/// `depuis_bytes` recharge une clé et produit la même clé publique.
#[test]
fn depuis_bytes_recharge_cle_identique() {
    let signataire_original = SignataireBundle::generer();
    let signataire_recharge =
        SignataireBundle::depuis_bytes(&signataire_original.cle_secrete)
            .expect("rechargement doit réussir");

    assert_eq!(
        signataire_original.cle_publique,
        signataire_recharge.cle_publique,
        "la clé publique rechargée doit être identique"
    );

    // La signature produite par la clé rechargée doit aussi être vérifiable.
    let payload = b"rechargement-cle-sentinel";
    let signature = signataire_recharge.signer(payload);
    assert!(
        verifier_signature(&signataire_recharge.cle_publique, payload, &signature),
        "la signature de la clé rechargée doit être valide"
    );
}

/// `BundleSigne.horodatage_iso8601` est un timestamp ISO 8601 parseable.
#[test]
fn bundle_signe_horodatage_iso8601_valide() {
    let signataire = SignataireBundle::generer();
    let payload = b"horodatage-conformite-safe-t1001".to_vec();
    let bundle = signataire.signer_bundle(payload);

    // Le champ doit être parseable comme DateTime RFC 3339 / ISO 8601.
    let parse_result = bundle.horodatage_iso8601.parse::<chrono::DateTime<chrono::Utc>>();
    assert!(
        parse_result.is_ok(),
        "horodatage_iso8601 doit être parseable : {}",
        bundle.horodatage_iso8601
    );

    // La fonction `verifier` de haut niveau doit valider le bundle.
    assert!(
        verifier(&bundle).expect("verifier ne doit pas échouer"),
        "le bundle signé doit être vérifié avec succès"
    );
}

/// Une signature forgée (bytes aléatoires) est rejetée.
#[test]
fn signature_forgee_rejetee() {
    let signataire = SignataireBundle::generer();
    let payload = b"safe-t1201-rug-pull-detection";
    let signature_forgee = vec![0xABu8; 64];
    let valide = verifier_signature(&signataire.cle_publique, payload, &signature_forgee);
    assert!(!valide, "une signature forgée doit être rejetée");
}

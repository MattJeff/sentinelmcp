//! Tests d'intégration du cache de registres.
//!
//! On vérifie le contrat public minimal : aller-retour write/read,
//! fraîcheur dépendante du TTL, et entrée absente.

use std::path::PathBuf;

use sentinel_store::registry_cache::CacheRegistres;

/// Construit un cache in-memory pour rester rapide et hermétique.
fn cache_memoire() -> CacheRegistres {
    CacheRegistres::nouveau(PathBuf::from(":memory:")).expect("cache in-memory")
}

#[test]
fn aller_retour_ecrire_puis_lire() {
    let cache = cache_memoire();
    let payload = b"{\"name\":\"left-pad\",\"latest\":\"1.3.0\"}";
    cache.ecrire("npm:left-pad", payload).unwrap();

    let lu = cache.lire("npm:left-pad").unwrap();
    let (payload_lu, ecrit_a) = lu.expect("entrée présente après ecrire");
    assert_eq!(payload_lu, payload);
    // l'horodatage doit être très récent (moins d'une minute d'écart)
    let delta = chrono::Utc::now()
        .signed_duration_since(ecrit_a)
        .num_seconds()
        .abs();
    assert!(delta < 60, "horodatage trop éloigné de now() : {delta}s");
}

#[test]
fn est_frais_vrai_dans_ttl_faux_au_dela() {
    let cache = cache_memoire();
    cache.ecrire("pypi:requests", b"payload").unwrap();

    // TTL généreux (24h) → l'entrée vient d'être écrite, doit être fraîche.
    assert!(cache.est_frais("pypi:requests", 24 * 3600).unwrap());

    // TTL à 0 seconde → toute entrée est immédiatement périmée.
    assert!(!cache.est_frais("pypi:requests", 0).unwrap());
}

#[test]
fn lire_entree_manquante_retourne_none() {
    let cache = cache_memoire();
    assert!(cache.lire("crates.io:inconnu").unwrap().is_none());
    // est_frais sur une clé absente doit être false (rien à servir).
    assert!(!cache.est_frais("crates.io:inconnu", 3600).unwrap());
}

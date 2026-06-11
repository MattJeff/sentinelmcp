//! Tests de la matrice de sévérité — agent 4.2.

use sentinel_alerts::severity::{ConfigSeverite, MatriceSeverite};
use sentinel_protocol::{Severite, TypeConstat};
use std::time::Instant;

/// Test 1 : par_defaut couvre tous les TypeConstat avec les bonnes sévérités.
#[test]
fn par_defaut_couvre_tous_les_types() {
    let matrice = MatriceSeverite::par_defaut();

    let cas = [
        (TypeConstat::NouveauServeur, Severite::Moyenne),
        (TypeConstat::ShadowMcp, Severite::Moyenne),
        (TypeConstat::RugPull, Severite::Critique),
        (TypeConstat::Poisoning, Severite::Critique),
        (TypeConstat::Sosie, Severite::Haute),
        (TypeConstat::Exfiltration, Severite::Critique),
        (TypeConstat::SansAuthentification, Severite::Haute),
        (TypeConstat::DeriveInterSession, Severite::Haute),
        (TypeConstat::Autre, Severite::Moyenne),
    ];

    for (tc, severite_attendue) in cas {
        let obtenue = matrice.severite_pour(&tc);
        assert_eq!(
            obtenue, severite_attendue,
            "TypeConstat::{tc:?} → attendu {severite_attendue:?}, obtenu {obtenue:?}"
        );
    }
}

/// Test 2 : surcharge d'une règle existante via ConfigSeverite::definir.
#[test]
fn surcharge_fonctionne() {
    let mut config = ConfigSeverite::par_defaut();
    // On passe NouveauServeur de Moyenne à Critique.
    config.definir(TypeConstat::NouveauServeur, Severite::Critique);
    // On passe ShadowMcp de Moyenne à Haute.
    config.definir(TypeConstat::ShadowMcp, Severite::Haute);

    let matrice = MatriceSeverite::depuis_config(config);

    assert_eq!(
        matrice.severite_pour(&TypeConstat::NouveauServeur),
        Severite::Critique,
        "surcharge NouveauServeur → Critique"
    );
    assert_eq!(
        matrice.severite_pour(&TypeConstat::ShadowMcp),
        Severite::Haute,
        "surcharge ShadowMcp → Haute"
    );
    // Les autres règles non surchargées restent intactes.
    assert_eq!(
        matrice.severite_pour(&TypeConstat::RugPull),
        Severite::Critique,
        "RugPull non surchargé reste Critique"
    );
}

/// Test 3 : sévérité inconnue (type absent) → Moyenne par défaut.
#[test]
fn severite_inconnue_retourne_moyenne() {
    // Config vide — aucune règle définie.
    let config = ConfigSeverite::default();
    let matrice = MatriceSeverite::depuis_config(config);

    // Tous les types doivent retourner Moyenne puisqu'aucune règle n'est définie.
    assert_eq!(
        matrice.severite_pour(&TypeConstat::Poisoning),
        Severite::Moyenne,
        "config vide → Moyenne pour tout type"
    );
    assert_eq!(
        matrice.severite_pour(&TypeConstat::Exfiltration),
        Severite::Moyenne,
        "config vide → Moyenne pour tout type"
    );
}

/// Test 4 : lookup O(1) — 1000 lookups en moins de 1 ms.
/// Meilleure de plusieurs mesures pour neutraliser la contention quand
/// toute la suite tourne en parallèle (`cargo test --workspace`, CI).
#[test]
fn lookup_o1_moins_de_1ms_pour_1000_appels() {
    let matrice = MatriceSeverite::par_defaut();
    let types = [
        TypeConstat::RugPull,
        TypeConstat::Poisoning,
        TypeConstat::ShadowMcp,
        TypeConstat::Sosie,
        TypeConstat::Exfiltration,
    ];

    const ESSAIS: usize = 5;
    let mut meilleure = std::time::Duration::MAX;
    for _ in 0..ESSAIS {
        let debut = Instant::now();
        for i in 0..1000usize {
            let tc = &types[i % types.len()];
            let _ = std::hint::black_box(matrice.severite_pour(std::hint::black_box(tc)));
        }
        let duree = debut.elapsed();
        meilleure = meilleure.min(duree);
        if duree.as_millis() < 1 {
            return;
        }
    }

    panic!(
        "1000 lookups ont pris {:?} (meilleure de {} mesures), attendu < 1 ms",
        meilleure, ESSAIS
    );
}

/// Test 5 : ConfigSeverite implémente Debug (sérialisable pour audit/logs).
#[test]
fn config_serialisable_debug() {
    let config = ConfigSeverite::par_defaut();
    let repr = format!("{config:?}");

    // Vérifie que la représentation contient bien des informations exploitables.
    assert!(repr.contains("regles"), "Debug doit exposer le champ regles");
    assert!(repr.contains("Critique"), "Debug doit exposer les valeurs de sévérité");
    assert!(repr.contains("RugPull"), "Debug doit exposer les types de constat");

    // Clone doit aussi fonctionner (nécessaire pour la propagation vers les canaux 4.3/4.4/4.5).
    let config2 = config.clone();
    let repr2 = format!("{config2:?}");
    assert_eq!(repr, repr2, "Clone puis Debug doit produire le même résultat");
}

/// Test 6 : definir ajoute une nouvelle règle si le type est absent.
#[test]
fn definir_ajoute_si_absent() {
    let mut config = ConfigSeverite::default();
    assert_eq!(config.regles.len(), 0);

    config.definir(TypeConstat::Poisoning, Severite::Critique);
    assert_eq!(config.regles.len(), 1);

    // Appel une deuxième fois sur le même type : mise à jour, pas ajout.
    config.definir(TypeConstat::Poisoning, Severite::Haute);
    assert_eq!(config.regles.len(), 1, "mise à jour ne doit pas dupliquer la règle");

    let matrice = MatriceSeverite::depuis_config(config);
    assert_eq!(
        matrice.severite_pour(&TypeConstat::Poisoning),
        Severite::Haute,
        "dernière valeur définie l'emporte"
    );
}

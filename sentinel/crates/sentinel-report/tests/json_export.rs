//! Tests de l'export JSON structuré — Agent 5.7.

use chrono::Utc;
use sentinel_protocol::{
    Constat, EtatConstat, Serveur, Severite, StatutServeur, Transport,
    TypeConstat, Couleur, Portee,
};
use sentinel_report::json_export::{ExportJson, VERSION_SCHEMA};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serveur(statut: StatutServeur) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://localhost:8080".to_string(),
        transport: Transport::Http,
        portees: vec![Portee::ApiExterne],
        statut,
        couleur: Couleur::Vert,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
    }
}

fn constat(severite: Severite) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: None,
        type_constat: TypeConstat::ShadowMcp,
        severite,
        titre: "constat test".to_string(),
        detail: "détail test".to_string(),
        diff: None,
        references_conformite: vec!["OWASP MCP09".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : `construire` calcule correctement serveurs_total
// ---------------------------------------------------------------------------

#[test]
fn construire_calcule_serveurs_total() {
    let serveurs = vec![
        serveur(StatutServeur::Approuve),
        serveur(StatutServeur::Suspect),
        serveur(StatutServeur::Inconnu),
    ];
    let schema = ExportJson::construire(serveurs.clone(), vec![]);

    assert_eq!(
        schema.statistiques.serveurs_total,
        serveurs.len() as u64,
        "serveurs_total doit correspondre à la taille de la liste"
    );
}

// ---------------------------------------------------------------------------
// Test 2 : `construire` calcule correctement les compteurs de sévérité
// ---------------------------------------------------------------------------

#[test]
fn construire_calcule_compteurs_severite() {
    let constats = vec![
        constat(Severite::Critique),
        constat(Severite::Critique),
        constat(Severite::Haute),
        constat(Severite::Moyenne),
        constat(Severite::Info),
    ];
    let schema = ExportJson::construire(vec![], constats);

    assert_eq!(schema.statistiques.constats_critiques, 2);
    assert_eq!(schema.statistiques.constats_hauts, 1);
    assert_eq!(schema.statistiques.constats_moyens, 1);
}

// ---------------------------------------------------------------------------
// Test 3 : `construire` calcule correctement serveurs_approuves et
//           serveurs_a_risque
// ---------------------------------------------------------------------------

#[test]
fn construire_calcule_serveurs_approuves_et_a_risque() {
    let serveurs = vec![
        serveur(StatutServeur::Approuve),
        serveur(StatutServeur::Approuve),
        serveur(StatutServeur::Suspect),
        serveur(StatutServeur::AInvestiguer),
        serveur(StatutServeur::Bloque),
        serveur(StatutServeur::Inconnu),
    ];
    let schema = ExportJson::construire(serveurs, vec![]);

    assert_eq!(schema.statistiques.serveurs_approuves, 2);
    assert_eq!(schema.statistiques.serveurs_a_risque, 3);
}

// ---------------------------------------------------------------------------
// Test 4 : `serveurs.len() == schema.statistiques.serveurs_total`
// ---------------------------------------------------------------------------

#[test]
fn serveurs_len_egal_statistiques_serveurs_total() {
    let serveurs = vec![
        serveur(StatutServeur::Inconnu),
        serveur(StatutServeur::Approuve),
    ];
    let schema = ExportJson::construire(serveurs, vec![]);

    assert_eq!(
        schema.serveurs.len() as u64,
        schema.statistiques.serveurs_total
    );
}

// ---------------------------------------------------------------------------
// Test 5 : `vers_value` retourne un objet avec la clé `version`
// ---------------------------------------------------------------------------

#[test]
fn vers_value_contient_cle_version() {
    let schema = ExportJson::construire(vec![], vec![]);
    let valeur = ExportJson::vers_value(&schema);

    assert!(
        valeur.is_object(),
        "vers_value doit retourner un objet JSON"
    );
    assert_eq!(
        valeur["version"].as_str().unwrap(),
        VERSION_SCHEMA,
        "la clé `version` doit être présente et correcte"
    );
}

// ---------------------------------------------------------------------------
// Test 6 : `produire_depuis` écrit un fichier parsable
// ---------------------------------------------------------------------------

#[test]
fn produire_depuis_ecrit_fichier_parsable() {
    let dir = std::env::temp_dir();
    let chemin = dir.join(format!("sentinel_test_{}.json", Uuid::new_v4()));

    let schema = ExportJson::construire(
        vec![serveur(StatutServeur::Approuve)],
        vec![constat(Severite::Haute)],
    );
    ExportJson::produire_depuis(&schema, &chemin)
        .expect("produire_depuis ne doit pas échouer");

    let contenu = std::fs::read_to_string(&chemin)
        .expect("le fichier doit être lisible");
    let _: serde_json::Value = serde_json::from_str(&contenu)
        .expect("le contenu doit être du JSON valide");

    // Nettoyage.
    let _ = std::fs::remove_file(&chemin);
}

// ---------------------------------------------------------------------------
// Test 7 : le fichier produit commence par `{`
// ---------------------------------------------------------------------------

#[test]
fn fichier_produit_commence_par_accolade() {
    let dir = std::env::temp_dir();
    let chemin = dir.join(format!("sentinel_test_{}.json", Uuid::new_v4()));

    let schema = ExportJson::construire(vec![], vec![]);
    ExportJson::produire_depuis(&schema, &chemin)
        .expect("produire_depuis ne doit pas échouer");

    let contenu = std::fs::read_to_string(&chemin)
        .expect("le fichier doit être lisible");
    assert!(
        contenu.trim_start().starts_with('{'),
        "le fichier JSON doit commencer par une accolade ouvrante"
    );

    let _ = std::fs::remove_file(&chemin);
}

// ---------------------------------------------------------------------------
// Test 8 : `version` est le premier champ sérialisé
// ---------------------------------------------------------------------------

#[test]
fn version_est_premier_champ_serialise() {
    let schema = ExportJson::construire(vec![], vec![]);
    let json_str = serde_json::to_string_pretty(&schema)
        .expect("sérialisation ne doit pas échouer");

    // La première clé du JSON doit être "version".
    let premier_champ = json_str
        .lines()
        .nth(1) // ligne 0 = `{`, ligne 1 = premier champ
        .expect("le JSON doit avoir au moins deux lignes");
    assert!(
        premier_champ.trim().starts_with("\"version\""),
        "le premier champ sérialisé doit être `version`, obtenu : {:?}",
        premier_champ
    );
}

// ---------------------------------------------------------------------------
// Test 9 : références de conformité dédupliquées et triées
// ---------------------------------------------------------------------------

#[test]
fn references_conformite_dedupliquees_et_triees() {
    let mut c1 = constat(Severite::Critique);
    c1.references_conformite = vec!["OWASP MCP09".to_string(), "SAFE-T1001".to_string()];

    let mut c2 = constat(Severite::Haute);
    c2.references_conformite = vec!["OWASP MCP03".to_string(), "OWASP MCP09".to_string()];

    let schema = ExportJson::construire(vec![], vec![c1, c2]);

    // Pas de doublon.
    let refs = &schema.references_conformite;
    let mut dedup = refs.clone();
    dedup.dedup();
    assert_eq!(refs, &dedup, "les références ne doivent pas contenir de doublons");

    // Triées.
    let mut triees = refs.clone();
    triees.sort();
    assert_eq!(refs, &triees, "les références doivent être triées");

    // Doit contenir exactement 3 entrées distinctes.
    assert_eq!(refs.len(), 3);
}

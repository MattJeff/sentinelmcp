//! Tests du module SIEM — agent 4.9.
//!
//! Vérifie : conversion Alerte→Enregistrement, mapping de gravité,
//! format CEF parsable, format LEEF bien formé, champs ECS requis.

use chrono::Utc;
use sentinel_alerts::{
    AdaptateurStandard, ContratSiem, gravite_siem,
    vers_cef, vers_leef, vers_ecs_json,
};
use sentinel_protocol::{
    Alerte, CanalAlerte, Severite,
};
use uuid::Uuid;

// ─── Helpers ────────────────────────────────────────────────────────────────

fn alerte_de_test(titre: &str, message: &str, severite: Severite, diff: Option<String>) -> Alerte {
    Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Siem,
        severite,
        titre: titre.to_string(),
        message: message.to_string(),
        diff,
        horodatage: Utc::now(),
        envoyee: false,
        tentatives: 0,
    }
}

// ─── Test 1 : conversion Alerte → EnregistrementSiem ────────────────────────

#[test]
fn test_conversion_alerte_vers_enregistrement() {
    let a = alerte_de_test(
        "shadow-mcp détecté : serveur inconnu",
        "Le serveur 192.168.1.42 n'est pas dans l'inventaire approuvé.",
        Severite::Critique,
        None,
    );

    let enreg = AdaptateurStandard::vers_enregistrement(&a);

    assert_eq!(enreg.source, "sentinel-mcp");
    assert_eq!(enreg.categorie, "shadow-mcp");
    assert_eq!(enreg.gravite, "CRITICAL");
    assert_eq!(enreg.message, a.message);
    assert_eq!(enreg.alerte_id, a.id.to_string());
    assert!(enreg.diff.is_none());
    // L'horodatage doit être une chaîne ISO-8601 non vide.
    assert!(!enreg.horodatage_iso8601.is_empty());
    assert!(enreg.horodatage_iso8601.contains('T'));
}

// ─── Test 2 : mapping de gravité pour toutes les sévérités ──────────────────

#[test]
fn test_mapping_gravite_complet() {
    assert_eq!(gravite_siem(Severite::Info),    "INFO");
    assert_eq!(gravite_siem(Severite::Moyenne), "MEDIUM");
    assert_eq!(gravite_siem(Severite::Haute),   "HIGH");
    assert_eq!(gravite_siem(Severite::Critique),"CRITICAL");
}

// ─── Test 3 : format CEF parsable ───────────────────────────────────────────
//
// Un analyseur CEF minimal attend :
//   CEF:0|<vendor>|<product>|<version>|<deviceEventClassId>|<name>|<severity>|<extension>
// Soit au moins 8 segments délimités par `|` (les `|` dans les champs sont échappés \|).

#[test]
fn test_cef_parsable() {
    let a = alerte_de_test(
        "rug-pull détecté",
        "La description de l'outil exec_sql a changé.",
        Severite::Haute,
        Some("- ancienne desc\n+ nouvelle desc".to_string()),
    );
    let enreg = AdaptateurStandard::vers_enregistrement(&a);
    let cef = vers_cef(&enreg);

    // Commence par le préfixe CEF.
    assert!(cef.starts_with("CEF:0|"), "préfixe CEF absent : {}", cef);

    // Compte les délimiteurs `|` non échappés (les \\| ne comptent pas).
    // Stratégie : remplacer \\| puis compter |.
    let sans_echap = cef.replace("\\|", "\x00");
    let nb_pipes = sans_echap.matches('|').count();
    assert!(
        nb_pipes >= 7,
        "CEF doit avoir ≥ 7 pipes non échappés, trouvé {} : {}",
        nb_pipes, cef
    );

    // Les champs vendor et product sont présents.
    assert!(cef.contains("|Sentinel|"), "vendor absent : {}", cef);
    assert!(cef.contains("|MCP|"), "product absent : {}", cef);

    // Le champ gravité numérique doit être 8 (Haute).
    // Il est à la position du 7e segment (index 6).
    let segments: Vec<&str> = sans_echap.splitn(8, '|').collect();
    assert_eq!(segments.get(6).copied(), Some("8"), "gravité CEF incorrecte : {:?}", segments);

    // L'extension contient l'alerte_id.
    assert!(cef.contains(&a.id.to_string()), "alerte_id absent de l'extension CEF");
}

// ─── Test 4 : format LEEF bien formé ────────────────────────────────────────

#[test]
fn test_leef_bien_forme() {
    let a = alerte_de_test(
        "poisoning détecté",
        "Instruction malveillante dans la description de l'outil.",
        Severite::Critique,
        None,
    );
    let enreg = AdaptateurStandard::vers_enregistrement(&a);
    let leef = vers_leef(&enreg);

    // Préfixe LEEF 2.0.
    assert!(leef.starts_with("LEEF:2.0|"), "préfixe LEEF absent : {}", leef);

    // En-tête : LEEF:2.0|Sentinel|MCP|1.0|<categorie>|^|
    assert!(leef.contains("|Sentinel|"), "vendor LEEF absent");
    assert!(leef.contains("|MCP|"),      "product LEEF absent");
    // Délimiteur ^ obligatoire en LEEF 2.0.
    assert!(leef.contains("|^|"), "délimiteur ^ LEEF absent : {}", leef);

    // Les champs de l'extension sont présents et tab-séparés.
    let partie_ext = leef.split("|^|").nth(1).expect("extension LEEF absente");
    assert!(partie_ext.contains("sev=CRITICAL"),   "sev absent : {}", partie_ext);
    assert!(partie_ext.contains("src=sentinel-mcp"), "src absent : {}", partie_ext);
    assert!(partie_ext.contains(&format!("alerteId={}", a.id)), "alerteId absent");
    assert!(partie_ext.contains("cat=poisoning"),  "cat absent : {}", partie_ext);

    // Les champs sont séparés par des tabulations.
    assert!(partie_ext.contains('\t'), "séparateur tabulation absent dans LEEF");
}

// ─── Test 5 : ECS contient tous les champs requis ───────────────────────────

#[test]
fn test_ecs_champs_requis() {
    let a = alerte_de_test(
        "derive-inter-session détectée",
        "L'empreinte de l'outil diffère entre deux sessions consécutives.",
        Severite::Moyenne,
        Some("- hash: abc\n+ hash: def".to_string()),
    );
    let enreg = AdaptateurStandard::vers_enregistrement(&a);
    let ecs = vers_ecs_json(&enreg);

    // Champ @timestamp obligatoire.
    assert!(ecs.get("@timestamp").is_some(), "@timestamp absent");
    let ts = ecs["@timestamp"].as_str().unwrap();
    assert!(ts.contains('T'), "@timestamp non ISO-8601 : {}", ts);

    // Champ event avec les sous-champs requis.
    let event = ecs.get("event").expect("event absent");
    assert!(event.get("category").is_some(),  "event.category absent");
    assert!(event.get("severity").is_some(),  "event.severity absent");
    assert!(event.get("dataset").is_some(),   "event.dataset absent");
    assert_eq!(event["severity"].as_u64(), Some(5), "event.severity doit être 5 pour MEDIUM");

    // Champ message.
    assert_eq!(ecs["message"].as_str(), Some(a.message.as_str()), "message ECS incorrect");

    // Labels obligatoires.
    let labels = ecs.get("labels").expect("labels absent");
    assert_eq!(labels["alerte_id"].as_str(), Some(a.id.to_string().as_str()), "alerte_id absent des labels");
    assert_eq!(labels["gravite"].as_str(), Some("MEDIUM"), "gravite incorrecte dans labels");

    // Diff présent dans event.reason.
    assert!(event.get("reason").is_some(), "event.reason absent alors que diff fourni");
}

// ─── Test 6 : catégorie déduite depuis le titre ──────────────────────────────

#[test]
fn test_categorie_depuis_divers_titres() {
    let cas: &[(&str, &str)] = &[
        ("shadow-mcp détecté",              "shadow-mcp"),
        ("Alerte rug-pull sur exec_sql",    "rug-pull"),
        ("poisoning dans tool.desc",        "poisoning"),
        ("sosie de l'outil approuvé",       "sosie"),
        ("exfiltration de données",         "exfiltration"),
        ("dérive inter-session détectée",   "derive-inter-session"),
        ("anomalie générique",              "autre"),
    ];

    for (titre, categorie_attendue) in cas {
        let a = alerte_de_test(titre, "détail", Severite::Info, None);
        let enreg = AdaptateurStandard::vers_enregistrement(&a);
        assert_eq!(
            enreg.categorie, *categorie_attendue,
            "titre='{}' → attendu '{}', obtenu '{}'",
            titre, categorie_attendue, enreg.categorie
        );
    }
}

// ─── Test 7 : EnregistrementSiem est sérialisable en JSON ───────────────────

#[test]
fn test_enregistrement_serialisable_json() {
    let a = alerte_de_test(
        "shadow-mcp détecté",
        "Serveur inconnu contacté.",
        Severite::Haute,
        None,
    );
    let enreg = AdaptateurStandard::vers_enregistrement(&a);
    let json = serde_json::to_string(&enreg).expect("sérialisation JSON échouée");

    // Vérifie la présence des clés principales.
    assert!(json.contains("\"source\""),             "clé source absente");
    assert!(json.contains("\"sentinel-mcp\""),       "valeur source incorrecte");
    assert!(json.contains("\"gravite\""),             "clé gravite absente");
    assert!(json.contains("\"HIGH\""),               "valeur gravite incorrecte");
    assert!(json.contains("\"horodatage_iso8601\""), "clé horodatage absente");
}

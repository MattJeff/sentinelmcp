//! Tests du moteur de déduplication et d'anti-bruit (agent 4.7).

use chrono::{Duration, Utc};
use sentinel_alerts::dedup::{ConfigAntiBruit, DedupAntiBruit};
use sentinel_protocol::{Alerte, CanalAlerte, Severite};
use uuid::Uuid;

/// Construit une alerte minimale pour les tests.
fn alerte(titre: &str, canal: CanalAlerte, severite: Severite) -> Alerte {
    Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal,
        severite,
        titre: titre.to_string(),
        message: "message test".to_string(),
        diff: None,
        horodatage: Utc::now(),
        envoyee: false,
        tentatives: 0,
    }
}

/// Config avec fenêtres très courtes pour ne pas avoir à attendre en test.
fn config_test(fenetre_normale_ms: i64, fenetre_critique_ms: i64, max: u32) -> ConfigAntiBruit {
    ConfigAntiBruit {
        fenetre_normale: Duration::milliseconds(fenetre_normale_ms),
        fenetre_critique: Duration::milliseconds(fenetre_critique_ms),
        max_par_fenetre: max,
    }
}

// --- Test 1 : la première alerte est toujours émise ---
#[test]
fn premiere_alerte_emise() {
    let mut dedup = DedupAntiBruit::nouveau(ConfigAntiBruit::par_defaut());
    let a = alerte("Shadow MCP détecté", CanalAlerte::Dashboard, Severite::Haute);
    assert!(dedup.doit_emettre(&a), "la première alerte doit être émise");
}

// --- Test 2 : une alerte identique dans la fenêtre est supprimée ---
#[test]
fn deuxieme_alerte_identique_dans_fenetre_supprimee() {
    // Fenêtre de 10 secondes, max=5 : la 2e occurrence (compteur=2) doit être bloquée.
    let mut dedup = DedupAntiBruit::nouveau(config_test(10_000, 1_000, 5));
    let a = alerte("Rug-pull détecté", CanalAlerte::Email, Severite::Haute);
    assert!(dedup.doit_emettre(&a), "première émission attendue");
    let b = alerte("Rug-pull détecté", CanalAlerte::Email, Severite::Haute);
    assert!(!dedup.doit_emettre(&b), "deuxième émission doit être bloquée dans la fenêtre");
}

// --- Test 3 : hors fenêtre, l'alerte est ré-émise ---
#[test]
fn alerte_hors_fenetre_re_emise() {
    // Fenêtre de 1 ms : expirée dès la deuxième lecture.
    let mut dedup = DedupAntiBruit::nouveau(config_test(1, 1, 5));
    let a = alerte("Tool poisoning", CanalAlerte::Webhook, Severite::Moyenne);
    assert!(dedup.doit_emettre(&a));
    // On attend que la fenêtre expire.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let b = alerte("Tool poisoning", CanalAlerte::Webhook, Severite::Moyenne);
    assert!(dedup.doit_emettre(&b), "hors fenêtre : doit être ré-émise");
}

// --- Test 4 : Critique a une fenêtre plus courte ---
#[test]
fn critique_fenetre_courte() {
    // fenetre_normale=10 s (longue), fenetre_critique=1 ms (expire tout de suite).
    let mut dedup = DedupAntiBruit::nouveau(config_test(10_000, 1, 5));

    let critique = alerte("Exfiltration critique", CanalAlerte::Dashboard, Severite::Critique);
    let haute = alerte("Exfiltration critique", CanalAlerte::Dashboard, Severite::Haute);

    assert!(dedup.doit_emettre(&critique));
    // On attend que la fenêtre critique expire mais pas la normale.
    std::thread::sleep(std::time::Duration::from_millis(5));

    // Même titre/canal, sévérité Critique → fenêtre expirée → doit émettre.
    let critique2 = alerte("Exfiltration critique", CanalAlerte::Dashboard, Severite::Critique);
    assert!(
        dedup.doit_emettre(&critique2),
        "critique doit ré-émettre après la fenêtre courte"
    );

    // Si on avait utilisé Haute (fenêtre longue), ce serait supprimé.
    let haute2 = alerte("Exfiltration critique", CanalAlerte::Dashboard, Severite::Haute);
    // La clé diffère de la critique (même titre/canal mais entrée séparée ?
    // Non : la clé est titre|canal, indépendante de la sévérité.
    // Ici la clé est identique à celle de la critique, donc elle hérite du
    // compteur réinitialisé ci-dessus. On vérifie simplement que haute
    // est bloquée par sa propre fenêtre longue en créant une nouvelle entrée.
    let mut dedup_haute = DedupAntiBruit::nouveau(config_test(10_000, 1, 5));
    assert!(dedup_haute.doit_emettre(&haute));
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(
        !dedup_haute.doit_emettre(&haute2),
        "haute doit rester supprimée dans la longue fenêtre"
    );
}

// --- Test 5 : le regroupement est déclenché au seuil max_par_fenetre ---
#[test]
fn regroupement_au_seuil() {
    let max: u32 = 3;
    let mut dedup = DedupAntiBruit::nouveau(config_test(10_000, 1_000, max));
    let titre = "Shadow MCP répété";
    let canal = CanalAlerte::Dashboard;
    let severite = Severite::Moyenne;

    // 1ère : émise.
    assert!(dedup.doit_emettre(&alerte(titre, canal.clone(), severite)));
    // 2e : dans la fenêtre, compteur=2 < max → bloquée.
    assert!(!dedup.doit_emettre(&alerte(titre, canal.clone(), severite)));
    // 3e : compteur == max → émise (message de regroupement).
    assert!(
        dedup.doit_emettre(&alerte(titre, canal.clone(), severite)),
        "au seuil max le regroupement doit être émis une fois"
    );
    // 4e : compteur=4 > max → supprimée.
    assert!(!dedup.doit_emettre(&alerte(titre, canal.clone(), severite)));

    // regroupements() doit lister cette clé avec compteur >= max.
    let regs = dedup.regroupements();
    assert_eq!(regs.len(), 1, "un regroupement actif attendu");
    let (_, compteur) = &regs[0];
    assert!(*compteur >= max, "compteur doit être >= max");
}

// --- Test 6 : deux alertes de titres différents ont des compteurs indépendants ---
#[test]
fn alertes_differentes_independantes() {
    let mut dedup = DedupAntiBruit::nouveau(config_test(10_000, 1_000, 5));
    let a = alerte("Alerte A", CanalAlerte::Dashboard, Severite::Haute);
    let b = alerte("Alerte B", CanalAlerte::Dashboard, Severite::Haute);
    assert!(dedup.doit_emettre(&a));
    assert!(dedup.doit_emettre(&b), "titres différents → clés différentes → toutes deux émises");
}

// --- Test 7 : même titre, canaux différents → clés différentes ---
#[test]
fn meme_titre_canaux_differents_independants() {
    let mut dedup = DedupAntiBruit::nouveau(config_test(10_000, 1_000, 5));
    let a = alerte("Anomalie", CanalAlerte::Dashboard, Severite::Haute);
    let b = alerte("Anomalie", CanalAlerte::Email, Severite::Haute);
    assert!(dedup.doit_emettre(&a));
    assert!(dedup.doit_emettre(&b), "canaux différents → clés différentes → toutes deux émises");
}

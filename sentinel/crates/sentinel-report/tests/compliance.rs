//! Tests d'intégration du moteur de mapping de conformité — agent 5.4.
//!
//! Règle : un mapping faux est pire que pas de rapport. Chaque test vérifie
//! les identifiants précis attendus par les référentiels OWASP MCP, SAFE-MCP,
//! SOC 2 et ISO 27001.

use sentinel_protocol::{
    Constat, EtatConstat, Severite, TypeConstat,
};
use sentinel_report::compliance::MoteurConformite;
use uuid::Uuid;
use chrono::Utc;

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

fn identifiants(refs: &[sentinel_report::compliance::Reference]) -> Vec<&str> {
    refs.iter().map(|r| r.identifiant).collect()
}

fn constat_simple(type_constat: TypeConstat, titre: &str) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: None,
        type_constat,
        severite: Severite::Haute,
        titre: titre.to_string(),
        detail: String::new(),
        diff: None,
        references_conformite: vec![],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : RugPull → OWASP MCP03, SAFE-T1201, SOC 2 CC7.1, ISO A.14.2.2
// ---------------------------------------------------------------------------

#[test]
fn rugpull_references_correctes() {
    let refs = MoteurConformite::references_pour(&TypeConstat::RugPull);

    let ids = identifiants(&refs);
    assert!(
        ids.contains(&"MCP03"),
        "RugPull doit référencer OWASP MCP03, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"SAFE-T1201"),
        "RugPull doit référencer SAFE-T1201, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"CC7.1"),
        "RugPull doit référencer SOC 2 CC7.1, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"A.14.2.2"),
        "RugPull doit référencer ISO 27001 A.14.2.2, obtenu : {:?}",
        ids
    );

    // Pas de MCP09 pour RugPull — ce n'est pas un shadow server.
    assert!(
        !ids.contains(&"MCP09"),
        "RugPull ne doit PAS référencer MCP09 (mauvais mapping), obtenu : {:?}",
        ids
    );
}

// ---------------------------------------------------------------------------
// Test 2 : NouveauServeur → OWASP MCP09, SOC 2 CC6.1, ISO A.12.4.1
// ---------------------------------------------------------------------------

#[test]
fn nouveau_serveur_references_correctes() {
    let refs = MoteurConformite::references_pour(&TypeConstat::NouveauServeur);

    let ids = identifiants(&refs);
    assert!(
        ids.contains(&"MCP09"),
        "NouveauServeur doit référencer OWASP MCP09, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"CC6.1"),
        "NouveauServeur doit référencer SOC 2 CC6.1, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"A.12.4.1"),
        "NouveauServeur doit référencer ISO 27001 A.12.4.1, obtenu : {:?}",
        ids
    );

    // NouveauServeur est du shadow, pas du poisoning.
    assert!(
        !ids.contains(&"MCP03"),
        "NouveauServeur ne doit PAS référencer MCP03, obtenu : {:?}",
        ids
    );
}

// ---------------------------------------------------------------------------
// Test 3 : Poisoning → OWASP MCP03, SAFE-T1001, SOC 2 CC7.2, ISO A.12.6.1
// ---------------------------------------------------------------------------

#[test]
fn poisoning_references_correctes() {
    let refs = MoteurConformite::references_pour(&TypeConstat::Poisoning);

    let ids = identifiants(&refs);
    assert!(
        ids.contains(&"MCP03"),
        "Poisoning doit référencer OWASP MCP03, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"SAFE-T1001"),
        "Poisoning doit référencer SAFE-T1001, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"CC7.2"),
        "Poisoning doit référencer SOC 2 CC7.2, obtenu : {:?}",
        ids
    );
    assert!(
        ids.contains(&"A.12.6.1"),
        "Poisoning doit référencer ISO 27001 A.12.6.1, obtenu : {:?}",
        ids
    );

    // SAFE-T1001 est le poisoning, pas le rug-pull.
    assert!(
        !ids.contains(&"SAFE-T1201"),
        "Poisoning ne doit PAS référencer SAFE-T1201 (c'est le rug-pull), obtenu : {:?}",
        ids
    );
}

// ---------------------------------------------------------------------------
// Test 4 : Autre → liste vide
// ---------------------------------------------------------------------------

#[test]
fn autre_retourne_liste_vide() {
    let refs = MoteurConformite::references_pour(&TypeConstat::Autre);
    assert!(
        refs.is_empty(),
        "TypeConstat::Autre doit retourner une liste vide, obtenu : {:?}",
        identifiants(&refs)
    );
}

// ---------------------------------------------------------------------------
// Test 5 : markdown_section contient les bons identifiants
// ---------------------------------------------------------------------------

#[test]
fn markdown_section_contient_identifiants_attendus() {
    let constats = vec![
        constat_simple(TypeConstat::RugPull, "Changement d'outil détecté"),
        constat_simple(TypeConstat::Poisoning, "Instruction cachée dans la description"),
        constat_simple(TypeConstat::NouveauServeur, "Serveur inconnu observé"),
    ];

    let md = MoteurConformite::markdown_section(&constats);

    // RugPull
    assert!(
        md.contains("MCP03"),
        "markdown_section doit contenir MCP03 (RugPull), section obtenue :\n{}",
        md
    );
    assert!(
        md.contains("SAFE-T1201"),
        "markdown_section doit contenir SAFE-T1201 (RugPull), section obtenue :\n{}",
        md
    );
    assert!(
        md.contains("CC7.1"),
        "markdown_section doit contenir CC7.1 (RugPull), section obtenue :\n{}",
        md
    );

    // Poisoning
    assert!(
        md.contains("SAFE-T1001"),
        "markdown_section doit contenir SAFE-T1001 (Poisoning), section obtenue :\n{}",
        md
    );
    assert!(
        md.contains("CC7.2"),
        "markdown_section doit contenir CC7.2 (Poisoning), section obtenue :\n{}",
        md
    );

    // NouveauServeur
    assert!(
        md.contains("MCP09"),
        "markdown_section doit contenir MCP09 (NouveauServeur), section obtenue :\n{}",
        md
    );
    assert!(
        md.contains("CC6.1"),
        "markdown_section doit contenir CC6.1 (NouveauServeur), section obtenue :\n{}",
        md
    );

    // Structure Markdown minimale
    assert!(
        md.contains("| Constat |"),
        "markdown_section doit contenir l'en-tête de tableau, section obtenue :\n{}",
        md
    );
    assert!(
        md.contains("## Conformité"),
        "markdown_section doit commencer par le titre ## Conformité, section obtenue :\n{}",
        md
    );
}

// ---------------------------------------------------------------------------
// Test 6 : ShadowMcp alias de NouveauServeur (même mapping)
// ---------------------------------------------------------------------------

#[test]
fn shadow_mcp_identique_a_nouveau_serveur() {
    let refs_nouveau = MoteurConformite::references_pour(&TypeConstat::NouveauServeur);
    let refs_shadow = MoteurConformite::references_pour(&TypeConstat::ShadowMcp);

    let ids_nouveau = identifiants(&refs_nouveau);
    let ids_shadow = identifiants(&refs_shadow);

    assert_eq!(
        ids_nouveau, ids_shadow,
        "ShadowMcp et NouveauServeur doivent avoir le même mapping de conformité"
    );
}

// ---------------------------------------------------------------------------
// Test 7 : tableau_complet couvre tous les types et préserve la cohérence
// ---------------------------------------------------------------------------

#[test]
fn tableau_complet_coherent() {
    let tableau = MoteurConformite::tableau_complet();

    // Tous les TypeConstat doivent apparaître (11 variantes).
    assert_eq!(
        tableau.len(),
        11,
        "tableau_complet doit couvrir les 11 variantes de TypeConstat"
    );

    // Cohérence : les refs de chaque ligne correspondent à references_pour.
    for (type_constat, refs) in &tableau {
        let attendu = MoteurConformite::references_pour(type_constat);
        let ids_ligne: Vec<&str> = identifiants(refs);
        let ids_attendu: Vec<&str> = identifiants(&attendu);
        assert_eq!(
            ids_ligne, ids_attendu,
            "tableau_complet incohérent pour {:?}",
            type_constat
        );
    }
}

// ---------------------------------------------------------------------------
// Test 8 : URLs présentes pour OWASP et SAFE-MCP
// ---------------------------------------------------------------------------

#[test]
fn urls_presentes_pour_owasp_et_safe_mcp() {
    let types_avec_owasp = [
        TypeConstat::NouveauServeur,
        TypeConstat::RugPull,
        TypeConstat::Poisoning,
    ];

    for t in &types_avec_owasp {
        let refs = MoteurConformite::references_pour(t);
        for r in &refs {
            if r.cadre == "OWASP MCP" || r.cadre == "SAFE-MCP" {
                assert!(
                    r.url.is_some(),
                    "Référence {}/{} doit avoir une URL, type : {:?}",
                    r.cadre, r.identifiant, t
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 9 : markdown_section avec liste vide ne produit pas de lignes de données
// ---------------------------------------------------------------------------

#[test]
fn markdown_section_liste_vide_pas_de_lignes_donnees() {
    let md = MoteurConformite::markdown_section(&[]);

    // L'en-tête doit être présent.
    assert!(md.contains("## Conformité"));
    assert!(md.contains("| Constat |"));

    // Aucune ligne de données (pas de "|" après le séparateur).
    // On compte les lignes contenant "|" : exactement 2 (en-tête + séparateur).
    let lignes_tableau: Vec<&str> = md
        .lines()
        .filter(|l| l.starts_with('|'))
        .collect();
    assert_eq!(
        lignes_tableau.len(),
        2,
        "Section vide ne doit avoir que l'en-tête et le séparateur, obtenu : {:?}",
        lignes_tableau
    );
}

// ---------------------------------------------------------------------------
// D10 — Test 10 : references_frameworks estampille les bons IDs par type
// ---------------------------------------------------------------------------

#[test]
fn frameworks_poisoning_inclut_owasp_safe_atlas() {
    let ids = MoteurConformite::references_frameworks(&TypeConstat::Poisoning);
    assert!(ids.contains(&"MCP03"), "Poisoning → OWASP MCP03, obtenu : {:?}", ids);
    assert!(ids.contains(&"SAFE-T1001"), "Poisoning → SAFE-T1001, obtenu : {:?}", ids);
    assert!(
        ids.contains(&"ATLAS AML.T0051"),
        "Poisoning → ATLAS AML.T0051 (prompt injection), obtenu : {:?}",
        ids
    );
    // Faux positif à éviter : le poisoning n'est pas un rug-pull.
    assert!(
        !ids.contains(&"SAFE-T1201"),
        "Poisoning ne doit PAS porter SAFE-T1201 (rug-pull), obtenu : {:?}",
        ids
    );
}

#[test]
fn frameworks_rugpull_et_sosie_mitre() {
    let rug = MoteurConformite::references_frameworks(&TypeConstat::RugPull);
    assert!(rug.contains(&"SAFE-T1201"), "RugPull → SAFE-T1201, obtenu : {:?}", rug);
    assert!(
        rug.contains(&"ATT&CK T1195"),
        "RugPull → ATT&CK T1195 (supply chain), obtenu : {:?}",
        rug
    );

    let sosie = MoteurConformite::references_frameworks(&TypeConstat::Sosie);
    assert!(
        sosie.contains(&"ATT&CK T1036"),
        "Sosie → ATT&CK T1036 (masquerading), obtenu : {:?}",
        sosie
    );
    assert!(sosie.contains(&"MCP09"), "Sosie → OWASP MCP09, obtenu : {:?}", sosie);
}

#[test]
fn frameworks_exfiltration_et_elicitation() {
    let exfil = MoteurConformite::references_frameworks(&TypeConstat::Exfiltration);
    assert!(
        exfil.contains(&"ATT&CK T1567"),
        "Exfiltration → ATT&CK T1567 (exfil over web service), obtenu : {:?}",
        exfil
    );

    let elic = MoteurConformite::references_frameworks(&TypeConstat::ElicitationSensible);
    assert!(
        elic.contains(&"ATT&CK T1598"),
        "ElicitationSensible → ATT&CK T1598 (phishing for information), obtenu : {:?}",
        elic
    );
}

#[test]
fn frameworks_autre_vide() {
    // Cas négatif : un constat non catégorisé ne porte aucune correspondance.
    let ids = MoteurConformite::references_frameworks(&TypeConstat::Autre);
    assert!(ids.is_empty(), "Autre ne doit porter aucun référentiel, obtenu : {:?}", ids);
}

#[test]
fn frameworks_shadow_alias_nouveau_serveur() {
    // Cohérence : ShadowMcp et NouveauServeur partagent le même estampillage.
    assert_eq!(
        MoteurConformite::references_frameworks(&TypeConstat::ShadowMcp),
        MoteurConformite::references_frameworks(&TypeConstat::NouveauServeur),
    );
}

#[test]
fn frameworks_markdown_liste_types_presents() {
    let constats = vec![
        constat_simple(TypeConstat::Poisoning, "poison"),
        constat_simple(TypeConstat::Poisoning, "poison 2 (doublon de type)"),
        constat_simple(TypeConstat::Exfiltration, "exfil"),
    ];
    let md = MoteurConformite::frameworks_markdown(&constats);

    assert!(md.contains("Correspondances multi-référentiels"));
    assert!(md.contains("ATLAS AML.T0051"), "section frameworks :\n{}", md);
    assert!(md.contains("ATT&CK T1567"), "section frameworks :\n{}", md);

    // Déduplication par type : Poisoning ne doit apparaître qu'une seule fois.
    let occurrences = md.matches("Poisoning").count();
    assert_eq!(occurrences, 1, "Poisoning dédupliqué attendu, section :\n{}", md);
}

// ---------------------------------------------------------------------------
// P3 — Test 11 : matrice de couverture honnête (OWASP MCP / ASI)
// ---------------------------------------------------------------------------

#[test]
fn matrice_couverture_couvre_les_dix_owasp_mcp_et_dix_asi() {
    let matrice = MoteurConformite::matrice_couverture();
    let nb_mcp = matrice.iter().filter(|c| c.cadre == "OWASP MCP").count();
    let nb_asi = matrice.iter().filter(|c| c.cadre == "OWASP ASI").count();
    assert_eq!(nb_mcp, 10, "10 catégories OWASP MCP attendues");
    assert_eq!(nb_asi, 10, "10 catégories OWASP ASI attendues");
}

#[test]
fn matrice_couverture_asi06_est_un_angle_mort() {
    // Honnêteté assumée : la mémoire persistante (ASI06) est un « Non ».
    let matrice = MoteurConformite::matrice_couverture();
    let asi06 = matrice
        .iter()
        .find(|c| c.identifiant == "ASI06")
        .expect("ASI06 doit figurer dans la matrice");
    assert_eq!(
        asi06.niveau,
        sentinel_report::compliance::NiveauCouverture::Non,
        "ASI06 (mémoire persistante) doit être déclaré non couvert"
    );

    // Cas positif symétrique : le serveur fantôme (MCP09) est bien couvert.
    let mcp09 = matrice
        .iter()
        .find(|c| c.identifiant == "MCP09")
        .expect("MCP09 doit figurer dans la matrice");
    assert_eq!(
        mcp09.niveau,
        sentinel_report::compliance::NiveauCouverture::Oui,
        "MCP09 (shadow server) doit être déclaré couvert"
    );
}

#[test]
fn matrice_couverture_markdown_lisible_pour_auditeur() {
    let md = MoteurConformite::matrice_couverture_markdown();
    assert!(md.contains("## Matrice de couverture"), "titre attendu :\n{}", md);
    assert!(md.contains("| Cadre | ID | Catégorie | Couverture | Justification |"));
    assert!(md.contains("MCP09"));
    assert!(md.contains("ASI06"));
    // La légende des niveaux doit être présente pour le RSSI.
    assert!(md.contains("Oui") && md.contains("Partiel") && md.contains("Non"));
}

#[test]
fn matrice_couverture_json_structuree() {
    let v = MoteurConformite::matrice_couverture_json();
    let cats = v["categories"].as_array().expect("categories doit être un tableau");
    assert_eq!(cats.len(), 20, "20 catégories attendues (10 MCP + 10 ASI)");
    // Chaque entrée porte les champs attendus.
    let asi06 = cats
        .iter()
        .find(|c| c["identifiant"] == "ASI06")
        .expect("ASI06 doit être présent dans le JSON");
    assert_eq!(asi06["couverture"], "Non");
    assert!(asi06["justification"].is_string());
}

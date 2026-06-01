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

    // Tous les TypeConstat doivent apparaître (9 variantes).
    assert_eq!(
        tableau.len(),
        9,
        "tableau_complet doit couvrir les 9 variantes de TypeConstat"
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

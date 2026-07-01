//! Tests de rendu PDF — agent 5.6.

use sentinel_report::pdf::{ContenuPdf, RenduPdf};
use std::fs;

// ─── Test 1 : produire() crée un fichier .pdf non vide ─────────────────────

#[test]
fn produire_cree_fichier_non_vide() {
    let dir = std::env::temp_dir();
    let chemin = dir.join("sentinel_test_produire.pdf");

    // Nettoyage préalable au cas où le fichier existerait déjà
    let _ = fs::remove_file(&chemin);

    RenduPdf::produire(&chemin).expect("produire() doit reussir");

    assert!(chemin.exists(), "Le fichier PDF doit exister");
    let metadonnees = fs::metadata(&chemin).expect("metadata lisibles");
    assert!(metadonnees.len() > 0, "Le fichier PDF ne doit pas etre vide");

    let _ = fs::remove_file(&chemin);
}

// ─── Test 2 : produire_contenu() crée un fichier .pdf non vide ─────────────

#[test]
fn produire_contenu_cree_fichier_non_vide() {
    let dir = std::env::temp_dir();
    let chemin = dir.join("sentinel_test_produire_contenu.pdf");
    let _ = fs::remove_file(&chemin);

    let contenu = ContenuPdf {
        titre: "Compliance Report Sentinel MCP".to_string(),
        sous_titre: "Unit tests — agent 5.6".to_string(),
        resume_exec: "No anomaly detected over this period.".to_string(),
        inventaire: "server-alpha  http://localhost:3000\nserver-beta   http://localhost:4000"
            .to_string(),
        journal: "2026-06-01T00:00:00Z  INFO  Sensor startup\n\
                  2026-06-01T00:01:00Z  WARN  Unknown server detected"
            .to_string(),
        mapping_conformite: "OWASP MCP09  Shadow MCP  Covered\nOWASP MCP03  Tool Poisoning  Covered"
            .to_string(),
        plan_remediation: "1. Approve server-alpha before 2026-06-07.\n\
                           2. Audit server-beta tools."
            .to_string(),
        horodatage: "2026-06-01T00:00:00Z".to_string(),
        ..Default::default()
    };

    let chemin_retourne =
        RenduPdf::produire_contenu(&contenu, &chemin).expect("produire_contenu() doit reussir");

    assert_eq!(
        chemin_retourne.canonicalize().unwrap(),
        chemin.canonicalize().unwrap(),
        "Le chemin retourne doit etre identique au chemin fourni"
    );
    assert!(chemin.exists(), "Le fichier PDF doit exister");
    let metadonnees = fs::metadata(&chemin).expect("metadata lisibles");
    assert!(
        metadonnees.len() > 100,
        "Le fichier PDF doit avoir une taille minimale significative ({}o)",
        metadonnees.len()
    );

    let _ = fs::remove_file(&chemin);
}

// ─── Test 3 : le fichier commence par l'en-tête PDF (%PDF) ─────────────────

#[test]
fn fichier_commence_par_entete_pdf() {
    let dir = std::env::temp_dir();
    let chemin = dir.join("sentinel_test_entete_pdf.pdf");
    let _ = fs::remove_file(&chemin);

    RenduPdf::produire(&chemin).expect("produire() doit reussir");

    let octets = fs::read(&chemin).expect("lecture du fichier PDF");
    assert!(
        octets.len() >= 4,
        "Le fichier doit avoir au moins 4 octets"
    );
    assert_eq!(
        &octets[..4],
        b"%PDF",
        "Les 4 premiers octets doivent etre '%PDF', obtenus : {:?}",
        &octets[..4.min(octets.len())]
    );

    let _ = fs::remove_file(&chemin);
}

// ─── Test 4 : produire_contenu() avec contenu vide ne panique pas ──────────

#[test]
fn produire_contenu_vide_ne_panique_pas() {
    let dir = std::env::temp_dir();
    let chemin = dir.join("sentinel_test_contenu_vide.pdf");
    let _ = fs::remove_file(&chemin);

    let contenu = ContenuPdf::default();
    let resultat = RenduPdf::produire_contenu(&contenu, &chemin);
    assert!(
        resultat.is_ok(),
        "produire_contenu avec contenu vide ne doit pas echouer : {:?}",
        resultat.err()
    );

    let metadonnees = fs::metadata(&chemin).expect("metadata lisibles");
    assert!(metadonnees.len() > 0, "Le fichier PDF ne doit pas etre vide");

    let _ = fs::remove_file(&chemin);
}

// ─── Test 5 : produire_contenu() avec texte long (pagination) ──────────────

#[test]
fn produire_contenu_texte_long_pagination() {
    let dir = std::env::temp_dir();
    let chemin = dir.join("sentinel_test_pagination.pdf");
    let _ = fs::remove_file(&chemin);

    // Generer un texte long pour declencher la pagination
    let texte_long: String = (0..200)
        .map(|i| format!("Line {} : server-mcp-{:04} detected, status RED, high risk.", i, i))
        .collect::<Vec<_>>()
        .join("\n");

    let contenu = ContenuPdf {
        titre: "Compliance Report Sentinel MCP".to_string(),
        sous_titre: "Pagination test".to_string(),
        resume_exec: texte_long.clone(),
        inventaire: texte_long.clone(),
        journal: texte_long,
        mapping_conformite: "MCP09 Covered\nMCP03 Covered".to_string(),
        plan_remediation: "No action required.".to_string(),
        horodatage: "2026-06-01T12:00:00Z".to_string(),
        ..Default::default()
    };

    RenduPdf::produire_contenu(&contenu, &chemin).expect("rendu avec texte long doit reussir");

    let metadonnees = fs::metadata(&chemin).expect("metadata lisibles");
    // Un PDF multi-pages doit etre sensiblement plus grand
    assert!(
        metadonnees.len() > 1024,
        "PDF avec texte long attendu > 1 Ko, obtenu {}o",
        metadonnees.len()
    );

    let octets = fs::read(&chemin).expect("lecture");
    assert_eq!(&octets[..4], b"%PDF", "en-tete PDF toujours valide");

    let _ = fs::remove_file(&chemin);
}

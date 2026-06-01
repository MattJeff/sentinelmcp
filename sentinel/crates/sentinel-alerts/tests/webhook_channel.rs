//! Tests du canal webhook — agent 4.5.

use sentinel_alerts::channels::webhook::{CanalWebhook, TypeWebhook};
use sentinel_alerts::channels::CanalEmetteur;
use sentinel_protocol::{Alerte, CanalAlerte, Severite};
use uuid::Uuid;
use chrono::Utc;

/// Fabrique une alerte de test avec les paramètres fournis.
fn alerte_test(severite: Severite, diff: Option<String>) -> Alerte {
    Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Webhook,
        severite,
        titre: "Serveur MCP fantôme détecté".to_string(),
        message: "Un serveur MCP non référencé répond sur le port 8765.".to_string(),
        diff,
        horodatage: Utc::now(),
        envoyee: false,
        tentatives: 0,
    }
}

/// Test 1 : charge_utile_slack produit un JSON valide avec les champs obligatoires.
#[test]
fn charge_utile_slack_json_valide() {
    let alerte = alerte_test(Severite::Critique, None);
    let charge = CanalWebhook::charge_utile_slack(&alerte);

    // Champ "text" présent et contient le titre.
    let texte = charge["text"].as_str().expect("champ 'text' manquant ou non-string");
    assert!(texte.contains("CRITIQUE"), "le texte doit contenir la sévérité CRITIQUE");
    assert!(texte.contains("Serveur MCP fantôme détecté"), "le texte doit contenir le titre");

    // Champ "attachments" présent avec au moins un élément.
    let attachments = charge["attachments"].as_array().expect("champ 'attachments' manquant");
    assert!(!attachments.is_empty(), "attachments ne doit pas être vide");

    // La couleur doit être "danger" pour Critique.
    let couleur = attachments[0]["color"].as_str().expect("couleur manquante");
    assert_eq!(couleur, "danger", "Critique → couleur danger");

    // Les champs (fields) doivent être présents.
    let champs = attachments[0]["fields"].as_array().expect("champ 'fields' manquant");
    assert!(!champs.is_empty(), "fields ne doit pas être vide");
}

/// Test 2 : charge_utile_teams produit un MessageCard valide avec @type et sections.
#[test]
fn charge_utile_teams_json_valide() {
    let alerte = alerte_test(Severite::Haute, Some("- ancien outil\n+ nouvel outil".to_string()));
    let charge = CanalWebhook::charge_utile_teams(&alerte);

    // Vérification du @type obligatoire.
    assert_eq!(
        charge["@type"].as_str().unwrap_or(""),
        "MessageCard",
        "@type doit être MessageCard"
    );

    // @context doit être présent.
    assert!(
        charge["@context"].as_str().is_some(),
        "@context doit être présent"
    );

    // themeColor non vide.
    let couleur = charge["themeColor"].as_str().expect("themeColor manquant");
    assert!(!couleur.is_empty(), "themeColor ne doit pas être vide");
    // Haute → FF6600.
    assert_eq!(couleur, "FF6600", "Haute → themeColor FF6600");

    // summary doit contenir le titre.
    let summary = charge["summary"].as_str().expect("summary manquant");
    assert_eq!(summary, "Serveur MCP fantôme détecté");

    // sections avec activityTitle et facts.
    let sections = charge["sections"].as_array().expect("sections manquantes");
    assert!(!sections.is_empty(), "sections ne doit pas être vide");

    let faits = sections[0]["facts"].as_array().expect("facts manquants");
    // Le diff doit apparaître dans les faits.
    let noms: Vec<&str> = faits
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(noms.contains(&"Diff"), "le diff doit figurer dans les faits Teams");
}

/// Test 3 : charge_utile_generique produit un JSON avec le sous-objet "alerte" complet.
#[test]
fn charge_utile_generique_json_valide() {
    let alerte = alerte_test(Severite::Moyenne, None);
    let charge = CanalWebhook::charge_utile_generique(&alerte);

    let objet = &charge["alerte"];
    assert!(!objet.is_null(), "le champ 'alerte' doit être présent");

    // Champs obligatoires.
    assert!(objet["id"].as_str().is_some(), "id manquant");
    assert_eq!(objet["severite"].as_str().unwrap_or(""), "MOYENNE");
    assert_eq!(
        objet["titre"].as_str().unwrap_or(""),
        "Serveur MCP fantôme détecté"
    );
    assert!(objet["message"].as_str().is_some(), "message manquant");
    assert!(objet["horodatage"].as_str().is_some(), "horodatage manquant");

    // diff null quand absent.
    assert!(objet["diff"].is_null(), "diff doit être null si absent");
}

/// Test 4 : dry_run capture l'URL et le body sans effectuer de requête HTTP.
#[tokio::test]
async fn dry_run_capture_url_et_body() {
    let url = "https://hooks.example.com/sentinel-test".to_string();
    let canal = CanalWebhook::dry_run(url.clone(), TypeWebhook::Generique);

    let alerte = alerte_test(Severite::Critique, Some("diff de test".to_string()));

    // emettre ne doit pas échouer.
    canal.emettre(&alerte).await.expect("emettre dry_run ne doit pas échouer");

    let captures = canal.captures.lock().unwrap();
    assert_eq!(captures.len(), 1, "une capture attendue");

    let (url_cap, body_cap) = &captures[0];
    assert_eq!(url_cap, &url, "l'URL capturée doit correspondre");

    // Le body doit être du JSON valide contenant le titre.
    let valeur: serde_json::Value =
        serde_json::from_str(body_cap).expect("le body capturé doit être du JSON valide");
    assert!(
        !valeur.is_null(),
        "le body JSON ne doit pas être null"
    );
}

/// Test 5 : slack colorie correctement selon chaque sévérité.
#[test]
fn slack_couleur_par_severite() {
    let cas = [
        (Severite::Critique, "danger"),
        (Severite::Haute, "danger"),
        (Severite::Moyenne, "warning"),
        (Severite::Info, "good"),
    ];

    for (severite, couleur_attendue) in cas {
        let alerte = alerte_test(severite, None);
        let charge = CanalWebhook::charge_utile_slack(&alerte);
        let couleur = charge["attachments"][0]["color"]
            .as_str()
            .expect("couleur manquante");
        assert_eq!(couleur, couleur_attendue, "sévérité {:?} → couleur {}", alerte.severite, couleur_attendue);
    }
}

/// Test 6 : dry_run en mode Slack capture un body contenant le champ "text".
#[tokio::test]
async fn dry_run_slack_body_contient_text() {
    let canal = CanalWebhook::dry_run(
        "https://hooks.slack.com/test".to_string(),
        TypeWebhook::Slack,
    );

    let alerte = alerte_test(Severite::Haute, None);
    canal.emettre(&alerte).await.expect("emettre dry_run Slack ne doit pas échouer");

    let captures = canal.captures.lock().unwrap();
    let (_, body) = &captures[0];
    let valeur: serde_json::Value = serde_json::from_str(body).unwrap();
    assert!(
        valeur["text"].as_str().is_some(),
        "le body Slack doit contenir le champ 'text'"
    );
}

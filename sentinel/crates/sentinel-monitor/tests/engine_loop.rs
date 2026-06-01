//! Tests d'intégration de la boucle de surveillance — agent 2.1.

use chrono::Utc;
use sentinel_monitor::engine::demarrer;
use sentinel_protocol::{Direction, MessageMcp, MethodeMcp, Transport};
use sentinel_store::Store;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn message(serveur: &str, methode: MethodeMcp, direction: Direction) -> MessageMcp {
    MessageMcp {
        session_id: "session-test-001".into(),
        transport: Transport::Http,
        serveur: serveur.to_owned(),
        direction,
        methode,
        id_jsonrpc: None,
        payload: serde_json::json!({"tools": []}),
        horodatage: Utc::now(),
    }
}

fn message_quelconque(serveur: &str) -> MessageMcp {
    message(serveur, MethodeMcp::Initialize, Direction::ClientVersServeur)
}

fn message_tools_list_reponse(serveur: &str) -> MessageMcp {
    message(serveur, MethodeMcp::ToolsList, Direction::ServeurVersClient)
}

// ---------------------------------------------------------------------------
// Test 1 : 5 messages → 5 contacts enregistrés dans le store
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cinq_messages_enregistrent_cinq_contacts() {
    let store = Store::in_memory().expect("store en mémoire");
    let poignee = demarrer(store.clone()).await;

    // Injecte 5 messages vers des serveurs distincts.
    for i in 0..5u32 {
        poignee
            .emetteur_messages
            .send(message_quelconque(&format!("http://serveur-{i}")))
            .await
            .expect("envoi message");
    }

    // Laisse la boucle traiter.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Ferme le canal pour arrêter proprement le moteur.
    drop(poignee.emetteur_messages);
    poignee._task.await.expect("tâche OK").expect("boucle OK");

    // Vérifie que 5 serveurs distincts ont été créés.
    let serveurs = store.lister_serveurs().expect("lister serveurs");
    assert_eq!(serveurs.len(), 5, "5 serveurs distincts attendus dans le store");
}

// ---------------------------------------------------------------------------
// Test 2 : un message tools/list → un fait émis sur le canal de faits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_emet_un_fait() {
    let store = Store::in_memory().expect("store en mémoire");
    let mut poignee = demarrer(store.clone()).await;

    poignee
        .emetteur_messages
        .send(message_tools_list_reponse("http://monitored-server"))
        .await
        .expect("envoi message tools/list");

    // Attend le fait avec un timeout.
    let fait = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        poignee.recepteur_faits.recv(),
    )
    .await
    .expect("timeout : aucun fait reçu dans les 500 ms")
    .expect("canal faits fermé prématurément");

    assert_eq!(fait.serveur_id, {
        // Le serveur doit exister dans le store après le traitement.
        let s = store
            .get_serveur_par_endpoint("http://monitored-server")
            .expect("store OK")
            .expect("serveur absent du store");
        s.id
    });

    use sentinel_protocol::TypeConstat;
    assert!(
        matches!(fait.type_fait, TypeConstat::NouveauServeur | TypeConstat::RugPull),
        "type de fait inattendu : {:?}",
        fait.type_fait
    );

    drop(poignee.emetteur_messages);
    poignee._task.await.expect("tâche OK").expect("boucle OK");
}

// ---------------------------------------------------------------------------
// Test 3 : fermeture du canal d'entrée → la boucle se termine proprement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fermeture_canal_arrete_la_boucle() {
    let store = Store::in_memory().expect("store en mémoire");
    let poignee = demarrer(store).await;

    // Ferme immédiatement le canal d'entrée.
    drop(poignee.emetteur_messages);

    // La tâche doit se terminer dans un délai raisonnable.
    let resultat = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        poignee._task,
    )
    .await
    .expect("timeout : la boucle ne s'est pas arrêtée après fermeture du canal");

    resultat
        .expect("la tâche Tokio a paniqué")
        .expect("la boucle a retourné une erreur");
}

//! Tests d'intégration — détection de sosies intra-inventaire (agent L10).

use sentinel_detect::lookalikes::intra_inventory::{detecter_sosies_intra, EntreeInventaire};
use sentinel_detect::lookalikes::SignatureOutil;

fn signature(nom: &str, enums: &[&str]) -> SignatureOutil {
    SignatureOutil {
        nom: nom.to_string(),
        enums_tries: enums.iter().map(|s| s.to_string()).collect(),
        description_empreinte: String::new(),
    }
}

fn entree(id: &str, nom: &str, description: Option<&str>, outils: Vec<SignatureOutil>) -> EntreeInventaire {
    EntreeInventaire {
        id: id.to_string(),
        nom: nom.to_string(),
        // Tests historiques : pas de package_id calculé ni de flag
        // officiel. Les gardes ajoutées au commit 3 (skip si
        // package_id ou est_officiel partagés) restent inertes,
        // donc ces tests valident toujours le score combiné v2.
        package_id: String::new(),
        est_officiel: false,
        description: description.map(|s| s.to_string()),
        outils,
    }
}

#[test]
fn inventaire_vide_retourne_vide() {
    let sosies = detecter_sosies_intra(&[]);
    assert!(sosies.is_empty(), "un inventaire vide ne doit produire aucun sosie");
}

#[test]
fn deux_serveurs_outils_identiques_nom_proche_detectes_comme_sosies() {
    // Deux serveurs aux noms proches partageant exactement la même
    // palette d'outils + enums + description : couverture maximale
    // sur toutes les composantes du score combiné v2.
    let outils = vec![
        signature("fs.open", &["append", "read", "write"]),
        signature("fs.close", &["force"]),
        signature("fs.read", &["binary", "text"]),
    ];
    let inventaire = vec![
        entree(
            "srv-1",
            "filesystem-server",
            Some("accès au système de fichiers local"),
            outils.clone(),
        ),
        entree(
            "srv-2",
            "filesystern-server",
            Some("accès au système de fichiers local"),
            outils.clone(),
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert_eq!(sosies.len(), 1, "attendu exactement 1 sosie, obtenu {}", sosies.len());

    let s = &sosies[0];
    assert!(s.score >= 0.85, "score attendu ≥ 0.85, obtenu {:.4}", s.score);
    assert_ne!(s.a_nom, s.b_nom, "les noms d'une paire sosie doivent différer");
    let ids = [s.a_id.as_str(), s.b_id.as_str()];
    assert!(ids.contains(&"srv-1"));
    assert!(ids.contains(&"srv-2"));
}

#[test]
fn deux_serveurs_sans_rapport_ne_produisent_aucun_sosie() {
    let inventaire = vec![
        entree(
            "srv-1",
            "filesystem-server",
            Some("accès au système de fichiers local"),
            vec![
                signature("fs.open", &["append", "read", "write"]),
                signature("fs.close", &["force"]),
            ],
        ),
        entree(
            "srv-2",
            "payment-gateway",
            Some("passerelle de paiement par carte bancaire"),
            vec![
                signature("pay.charge", &["eur", "usd"]),
                signature("pay.refund", &["full", "partial"]),
            ],
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert!(
        sosies.is_empty(),
        "deux serveurs sans rapport ne doivent produire aucun sosie, obtenu {}",
        sosies.len()
    );
}

// ──────────────────────────────────────────────────────────────────────
// Asymétrie sosie / officiel — commit 3
// ──────────────────────────────────────────────────────────────────────
//
// Ces tests verrouillent la règle « précision avant couverture » :
// on ne doit pas crier au sosie sur deux instances d'un même paquet
// officiel ni sur deux paquets officiels distincts. Le seul cas qui
// doit ressortir, c'est le typo-squat (nom proche d'un officiel mais
// hors allowlist).

fn entree_avec_identite(
    id: &str,
    nom: &str,
    package_id: &str,
    est_officiel: bool,
    outils: Vec<SignatureOutil>,
) -> EntreeInventaire {
    EntreeInventaire {
        id: id.to_string(),
        nom: nom.to_string(),
        package_id: package_id.to_string(),
        est_officiel,
        description: Some("filesystem helper".to_string()),
        outils,
    }
}

#[test]
fn meme_package_id_meme_outils_ne_produit_aucun_sosie() {
    // Cas typique du bug pré-V4 : deux configs clientes déclarent
    // le même `@modelcontextprotocol/server-postgres` avec des args
    // différents. Pré-fix : 97.4% CRITICAL. Post-fix : 0 sosie.
    let outils = vec![signature("query", &["SELECT", "INSERT"])];
    let inventaire = vec![
        entree_avec_identite(
            "srv-1",
            "npx -y @modelcontextprotocol/server-postgres db_dev",
            "@modelcontextprotocol/server-postgres",
            true,
            outils.clone(),
        ),
        entree_avec_identite(
            "srv-2",
            "npx -y @modelcontextprotocol/server-postgres db_test",
            "@modelcontextprotocol/server-postgres",
            true,
            outils,
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert!(
        sosies.is_empty(),
        "le même paquet déclaré deux fois ne doit jamais être sosie de lui-même, obtenu {} sosies",
        sosies.len()
    );
}

#[test]
fn deux_paquets_officiels_distincts_ne_produisent_aucun_sosie() {
    // `@modelcontextprotocol/server-postgres` vs.
    // `@modelcontextprotocol/server-fetch` : noms proches (même
    // préfixe scope), descriptions courtes, scores combinés
    // historiques au-dessus de 0.85. Avec l'allowlist : skip net,
    // 0 sosie. C'est ce qui élimine les 87/88 lignes CRITICAL de
    // la capture utilisateur.
    let inventaire = vec![
        entree_avec_identite(
            "srv-1",
            "npx -y @modelcontextprotocol/server-postgres",
            "@modelcontextprotocol/server-postgres",
            true,
            vec![signature("query", &[])],
        ),
        entree_avec_identite(
            "srv-2",
            "npx -y @modelcontextprotocol/server-fetch",
            "@modelcontextprotocol/server-fetch",
            true,
            vec![signature("fetch", &[])],
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert!(
        sosies.is_empty(),
        "deux officiels distincts ne sont jamais sosies, obtenu {} sosies",
        sosies.len()
    );
}

#[test]
fn typosquat_face_a_officiel_reste_detecte() {
    // Le seul cas qu'on doit GARDER détecté : un nom proche d'un
    // officiel mais hors allowlist. C'est le critère de succès donné
    // par l'utilisateur : « filesystm-mcp » doit ressortir en sosie
    // de `@modelcontextprotocol/server-filesystem`.
    let outils = vec![
        signature("fs.read", &["binary", "text"]),
        signature("fs.write", &[]),
    ];
    let inventaire = vec![
        entree_avec_identite(
            "officiel",
            "filesystem-server",
            "@modelcontextprotocol/server-filesystem",
            true,
            outils.clone(),
        ),
        entree_avec_identite(
            "typosquat",
            "filesystern-server",
            "filesystm-mcp",
            false,
            outils,
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert_eq!(
        sosies.len(),
        1,
        "le typo-squat doit toujours être détecté, obtenu {} sosies",
        sosies.len()
    );
}

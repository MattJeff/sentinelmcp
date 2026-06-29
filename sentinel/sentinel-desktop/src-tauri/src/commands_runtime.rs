//! Tauri commands exposant les défenses RUNTIME (Vague D) à l'UI.
//!
//! Trois familles de commandes, toutes ADDITIVES et exécutables hors-ligne
//! (aucune dépendance réseau dans les tests) :
//!
//!   1. **Approve-before-run** — politique de gate persistée (`enforce`/`seuil`)
//!      + file des appels « retenus pour approbation » dérivée des constats du
//!      store, avec acquittement (`approve_call` / `deny_call`).
//!   2. **Rogue sockets** — `list_rogue_sockets` lance la découverte runtime et
//!      renvoie les sockets en écoute hors-inventaire (angle mort
//!      « NeighborJack », F2).
//!   3. **CVE / supply-chain** — `list_cve_findings` confronte les serveurs de
//!      l'inventaire (transport stdio à version épinglée) à la base CVE MCP
//!      embarquée (`sentinel_detect::rechercher_cve`).
//!
//! ## Niveau d'interactivité réellement atteint (approve-before-run)
//!
//! Le proxy HTTP du desktop (`commands_proxy::ProxyMcp`) relaie bit-exact et ne
//! déclenche pas (encore) la rétention `enforce`. Le couplage temps réel
//! complet serait lourd ; conformément au contrat, on implémente le **minimum**
//! robuste :
//!   * (a) la configuration `enforce`/`seuil` est **persistée** sur disque
//!     (`gate.json`) et mise en cache dans `AppState` pour que le gate puisse la
//!     consulter ;
//!   * (b) `list_pending_approvals` expose les appels RÉCEMMENT retenus/flaggés,
//!     dérivés des constats « approve-before-run » OUVERTS du store, et
//!     `approve_call` / `deny_call` les **acquittent** (constat marqué résolu).
//!
//! Le registre `AppState::pending_approvals` + le hook
//! `AppState::pousser_demande_approbation` sont prêts pour un coupleur temps
//! réel : `list_pending_approvals` fusionne déjà les demandes poussées en
//! direct avec celles dérivées du store.

use std::time::Duration;

use sentinel_detect::{rechercher_cve, ConstatCve};
use sentinel_discovery::{OrchestrateurDecouverte, SocketEnEcoute};
use sentinel_protocol::{extraire_package_id, Constat, Severite, Transport};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio::time::timeout;
use uuid::Uuid;

use crate::state::{AppState, GateConfig, PendingApproval};

// ───────────────────────────────────────────────────────────────────────────
// Helpers partagés
// ───────────────────────────────────────────────────────────────────────────

/// Mappe une sévérité Sentinel vers le vocabulaire du contrat TS.
fn severite_vers_libelle(s: Severite) -> &'static str {
    match s {
        Severite::Info => "info",
        Severite::Moyenne => "medium",
        Severite::Haute => "high",
        Severite::Critique => "critical",
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. APPROVE-BEFORE-RUN — configuration du gate (persistée) + file d'attente
// ═══════════════════════════════════════════════════════════════════════════

/// Nom du fichier de configuration du gate, à côté de `sentinel.db`.
const GATE_CONFIG_FILENAME: &str = "gate.json";

/// Marqueur présent dans le `detail` de TOUT constat « approve-before-run »
/// émis par le proxy temps réel (rétention ET advisory) — cf.
/// `sentinel_scan::proxy::MoteurInspection::constat_politique`.
const MARQUEUR_APPROBATION: &str = "approve-before-run";

/// Résout le chemin du fichier `gate.json` dans le data-dir applicatif.
fn chemin_gate_config(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir.join(GATE_CONFIG_FILENAME))
}

/// Charge la config du gate depuis le disque. Tolérant : fichier absent ou
/// illisible/corrompu ⇒ valeurs par défaut (jamais d'échec côté UI).
fn charger_gate_config_fichier(path: &std::path::Path) -> GateConfig {
    if !path.exists() {
        return GateConfig::default();
    }
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(e) => {
            log::warn!(
                "could not read gate config {:?}: {} — using defaults",
                path,
                e
            );
            GateConfig::default()
        }
    }
}

/// Écrit la config du gate sur le disque (JSON lisible).
fn ecrire_gate_config_fichier(path: &std::path::Path, cfg: &GateConfig) -> Result<(), String> {
    let serialized = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("could not serialize gate config: {}", e))?;
    std::fs::write(path, serialized).map_err(|e| format!("could not write {:?}: {}", path, e))
}

/// Seuils de risque acceptés (du plus permissif au plus strict).
fn seuil_valide(seuil: &str) -> bool {
    matches!(seuil, "low" | "medium" | "high")
}

/// Lit la configuration « approve-before-run » persistée. Met à jour le cache
/// mémoire (`AppState::gate_config`) au passage.
#[tauri::command]
pub async fn get_gate_config(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<GateConfig, String> {
    let path = chemin_gate_config(&app)?;
    let cfg = tokio::task::spawn_blocking(move || charger_gate_config_fichier(&path))
        .await
        .map_err(|e| e.to_string())?;
    *state.gate_config.write().await = cfg.clone();
    Ok(cfg)
}

/// Persiste la configuration « approve-before-run » et rafraîchit le cache.
/// Rejette un `seuil` inconnu pour éviter une politique silencieusement inerte.
#[tauri::command]
pub async fn set_gate_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: GateConfig,
) -> Result<GateConfig, String> {
    if !seuil_valide(&config.seuil) {
        return Err(format!(
            "invalid seuil '{}': expected 'low', 'medium' or 'high'",
            config.seuil
        ));
    }
    let path = chemin_gate_config(&app)?;
    let a_ecrire = config.clone();
    tokio::task::spawn_blocking(move || ecrire_gate_config_fichier(&path, &a_ecrire))
        .await
        .map_err(|e| e.to_string())??;
    *state.gate_config.write().await = config.clone();
    Ok(config)
}

/// `true` si le constat provient de la politique « approve-before-run » du
/// proxy temps réel (appel retenu OU advisory à risque élevé).
fn est_demande_approbation(c: &Constat) -> bool {
    c.detail.contains(MARQUEUR_APPROBATION)
}

/// `true` si l'appel a été effectivement RETENU (bloqué), par opposition à un
/// simple advisory relayé en mode détection.
fn appel_retenu(c: &Constat) -> bool {
    c.titre.contains("retenu pour approbation")
}

/// Convertit un constat store « approve-before-run » en demande d'approbation.
fn constat_vers_demande(c: &Constat) -> PendingApproval {
    PendingApproval {
        id: c.id.to_string(),
        server_id: c.serveur_id.to_string(),
        tool: c.outil_nom.clone(),
        risk_level: severite_vers_libelle(c.severite).to_string(),
        reason: c.detail.clone(),
        title: c.titre.clone(),
        requested_at: c.horodatage.to_rfc3339(),
        held: appel_retenu(c),
        source: "store".to_string(),
        state: "pending".to_string(),
    }
}

/// Liste les appels en attente d'approbation.
///
/// Fusionne (a) les constats « approve-before-run » OUVERTS du store et (b) les
/// demandes encore `pending` poussées en direct par le gate. Déduplication par
/// `id`, tri par horodatage décroissant.
#[tauri::command]
pub async fn list_pending_approvals(
    state: State<'_, AppState>,
) -> Result<Vec<PendingApproval>, String> {
    let store = state.store.clone();
    let constats = tokio::task::spawn_blocking(move || store.lister_constats_ouverts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    let mut demandes: Vec<PendingApproval> = constats
        .iter()
        .filter(|c| est_demande_approbation(c))
        .map(constat_vers_demande)
        .collect();

    // Demandes poussées en direct par le gate, non encore résolues et non déjà
    // présentes via le store.
    {
        let live = state.pending_approvals.read().await;
        for d in live.iter().filter(|d| d.state == "pending") {
            if !demandes.iter().any(|x| x.id == d.id) {
                demandes.push(d.clone());
            }
        }
    }

    // Plus récentes d'abord (les horodatages ISO-8601 se trient lexicalement).
    demandes.sort_by(|a, b| b.requested_at.cmp(&a.requested_at));
    Ok(demandes)
}

/// Acquitte une demande : marque le constat store sous-jacent comme résolu (si
/// l'`id` est un UUID de constat) et reflète l'état dans le registre live.
async fn resoudre_demande(
    state: &AppState,
    id: String,
    etat: &str,
    note: &str,
) -> Result<(), String> {
    if let Ok(uuid) = Uuid::parse_str(&id) {
        let store = state.store.clone();
        let note_owned = Some(note.to_string());
        match tokio::task::spawn_blocking(move || store.marquer_constat_resolu(uuid, note_owned))
            .await
        {
            Ok(Ok(())) => {}
            // Best-effort : un id live (absent en base) ne doit pas faire échouer
            // l'acquittement — on log seulement.
            Ok(Err(e)) => {
                log::warn!("approve/deny: could not acknowledge constat {}: {}", id, e)
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    let mut live = state.pending_approvals.write().await;
    if let Some(d) = live.iter_mut().find(|d| d.id == id) {
        d.state = etat.to_string();
    }
    Ok(())
}

/// Approuve un appel retenu (acquittement de la demande).
#[tauri::command]
pub async fn approve_call(state: State<'_, AppState>, id: String) -> Result<(), String> {
    resoudre_demande(
        &state,
        id,
        "approved",
        "approuvé par l'opérateur (approve-before-run)",
    )
    .await
}

/// Refuse un appel retenu (acquittement de la demande).
#[tauri::command]
pub async fn deny_call(state: State<'_, AppState>, id: String) -> Result<(), String> {
    resoudre_demande(
        &state,
        id,
        "denied",
        "refusé par l'opérateur (approve-before-run)",
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. ROGUE SOCKETS — sockets en écoute hors-inventaire (NeighborJack, F2)
// ═══════════════════════════════════════════════════════════════════════════

/// Un socket TCP en écoute observé sur la machine, normalisé pour l'UI.
#[derive(Serialize)]
pub struct RogueSocket {
    /// `"tcp"` (IPv4) ou `"tcp6"` (IPv6).
    pub protocol: String,
    /// Adresse de bind observée (`0.0.0.0`, `127.0.0.1`, `::`, `*`…).
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// `true` si l'écoute couvre toutes les interfaces (exposé au réseau local).
    pub bind_all_interfaces: bool,
}

/// Un constat runtime « NeighborJack » (socket bind-all hors inventaire).
#[derive(Serialize)]
pub struct RogueSocketFinding {
    /// Identité stable dérivée de l'adresse:port observée (UUID).
    pub server_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub compliance_refs: Vec<String>,
}

/// Rapport renvoyé par [`list_rogue_sockets`].
#[derive(Serialize)]
pub struct RogueSocketReport {
    /// Tous les sockets en écoute observés (contexte).
    pub sockets: Vec<RogueSocket>,
    /// Les constats « NeighborJack » — sockets exposés hors inventaire.
    pub findings: Vec<RogueSocketFinding>,
    /// Nombre total de sockets observés.
    pub observed_count: u64,
    /// Nombre de sockets signalés comme rogue.
    pub rogue_count: u64,
}

fn map_socket(s: &SocketEnEcoute) -> RogueSocket {
    RogueSocket {
        protocol: s.protocole.clone(),
        address: s.adresse.clone(),
        port: s.port,
        pid: s.pid,
        process: s.processus.clone(),
        bind_all_interfaces: s.bind_toutes_interfaces,
    }
}

fn map_runtime_finding(c: &Constat) -> RogueSocketFinding {
    RogueSocketFinding {
        server_id: c.serveur_id.to_string(),
        severity: severite_vers_libelle(c.severite).to_string(),
        title: c.titre.clone(),
        detail: c.detail.clone(),
        compliance_refs: c.references_conformite.clone(),
    }
}

/// Lance la découverte runtime et renvoie les sockets en écoute hors-inventaire.
///
/// L'énumération des sockets est best-effort (`lsof`/`ss`) et ne dépend
/// d'aucun réseau ; sur un hôte sans ces outils, le rapport est simplement
/// vide. Borné par un timeout de 15 s comme les autres balayages.
#[tauri::command]
pub async fn list_rogue_sockets() -> Result<RogueSocketReport, String> {
    let orchestrator = OrchestrateurDecouverte::default();
    let report = timeout(Duration::from_secs(15), orchestrator.balayer())
        .await
        .map_err(|_| "discovery timed out after 15s".to_string())?;

    let sockets: Vec<RogueSocket> = report.sockets_observes.iter().map(map_socket).collect();
    let findings: Vec<RogueSocketFinding> =
        report.constats_runtime.iter().map(map_runtime_finding).collect();
    let observed_count = sockets.len() as u64;
    let rogue_count = findings.len() as u64;

    Ok(RogueSocketReport {
        sockets,
        findings,
        observed_count,
        rogue_count,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. CVE / SUPPLY-CHAIN — confrontation de l'inventaire à la base CVE embarquée
// ═══════════════════════════════════════════════════════════════════════════

/// Une correspondance CVE sur un serveur de l'inventaire, normalisée pour l'UI.
#[derive(Serialize)]
pub struct CveFinding {
    /// Identifiant du serveur dans l'inventaire (UUID).
    pub server_id: String,
    /// Identité de paquet ayant matché.
    pub package: String,
    /// Version détectée (épinglée dans la config).
    pub version: String,
    /// Identifiant CVE (ex. `CVE-2025-6514`).
    pub cve_id: String,
    /// Plage affectée, lisible (ex. `>=0.0.5, <0.1.16`).
    pub affected_range: String,
    /// Score CVSS (base score).
    pub cvss: f64,
    pub severity: String,
    /// Résumé lisible de la vulnérabilité.
    pub summary: String,
    /// Références (URLs NVD/GHSA + identifiant CVE).
    pub references: Vec<String>,
}

/// Extrait la version épinglée du token désignant `package_id`
/// (`pkg@1.2.3`, `@org/pkg@1.2.3`). `None` si aucune version n'est figée.
///
/// Logique alignée sur l'audit CLI (`cmd_audit::version_du_token`), réimplantée
/// localement car privée au crate CLI — additif et purement local.
fn version_du_token(token: &str) -> Option<String> {
    let v = if let Some(rest) = token.strip_prefix('@') {
        // Paquet scopé `@scope/pkg@version` : le 1er `@` fait partie du nom.
        let slash = rest.find('/')?;
        let after = &rest[slash + 1..];
        let at = after.find('@')?;
        &after[at + 1..]
    } else {
        let at = token.find('@')?;
        &token[at + 1..]
    };
    (!v.is_empty()).then(|| v.to_string())
}

/// Cherche, dans la ligne de commande, le token portant la version épinglée du
/// paquet `package_id`. Le token doit canoniquement DÉSIGNER ce paquet pour
/// qu'un argument arbitraire contenant un `@` ne soit pas pris pour la version.
fn extraire_version_epinglee(endpoint: &str, package_id: &str) -> Option<String> {
    endpoint.split_whitespace().find_map(|token| {
        version_du_token(token).filter(|_| extraire_package_id(token, Transport::Stdio) == package_id)
    })
}

fn map_cve(server_id: &str, c: &ConstatCve) -> CveFinding {
    let mut references = vec![c.cve_id.clone()];
    references.extend(c.references.iter().cloned());
    CveFinding {
        server_id: server_id.to_string(),
        package: c.package.clone(),
        version: c.version_detectee.clone(),
        cve_id: c.cve_id.clone(),
        affected_range: c.plage_affectee.clone(),
        cvss: c.cvss,
        severity: severite_vers_libelle(c.severite).to_string(),
        summary: c.resume.clone(),
        references,
    }
}

/// Confronte les serveurs de l'inventaire à la base CVE MCP embarquée.
///
/// Seuls les serveurs **stdio à version épinglée** dans leur ligne de commande
/// (`@org/pkg@1.2.3`) sont confrontés : sans version, aucun constat n'est émis
/// (anti-faux-positif). Recherche purement locale (`rechercher_cve`).
#[tauri::command]
pub async fn list_cve_findings(state: State<'_, AppState>) -> Result<Vec<CveFinding>, String> {
    let store = state.store.clone();
    let serveurs = tokio::task::spawn_blocking(move || store.lister_serveurs())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    let mut findings: Vec<CveFinding> = Vec::new();
    for s in &serveurs {
        // Pas de version de paquet épinglée pour un endpoint HTTP.
        if s.transport != Transport::Stdio {
            continue;
        }
        let package_id = extraire_package_id(&s.endpoint, s.transport);
        let Some(version) = extraire_version_epinglee(&s.endpoint, &package_id) else {
            continue;
        };
        let server_id = s.id.to_string();
        for c in rechercher_cve(&package_id, &version) {
            findings.push(map_cve(&server_id, &c));
        }
    }

    // CVSS décroissant puis identifiant CVE (ordre déterministe).
    findings.sort_by(|a, b| {
        b.cvss
            .total_cmp(&a.cvss)
            .then_with(|| a.cve_id.cmp(&b.cve_id))
    });
    Ok(findings)
}

// ───────────────────────────────────────────────────────────────────────────
// Tests — logique PURE uniquement (les commandes `#[tauri::command]` exigent un
// runtime Tauri + un store/des sockets réels, exercés par les tests
// d'intégration). Tout ici est hors-ligne et déterministe.
// ───────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_protocol::{EtatConstat, TypeConstat};

    fn constat_synthetique(titre: &str, detail: &str) -> Constat {
        Constat {
            id: Uuid::new_v4(),
            serveur_id: Uuid::new_v4(),
            outil_nom: Some("send_webhook".to_string()),
            type_constat: TypeConstat::Autre,
            severite: Severite::Haute,
            titre: titre.to_string(),
            detail: detail.to_string(),
            diff: None,
            references_conformite: vec!["OWASP MCP09".to_string()],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }

    // ── Gate config ───────────────────────────────────────────────────────────

    #[test]
    fn gate_config_par_defaut_est_detection_seule_seuil_strict() {
        let g = GateConfig::default();
        assert!(!g.enforce, "détection seule par défaut");
        assert_eq!(g.seuil, "high", "seuil le plus strict par défaut");
    }

    #[test]
    fn seuils_acceptes_et_rejetes() {
        for ok in ["low", "medium", "high"] {
            assert!(seuil_valide(ok), "{ok} doit être accepté");
        }
        for ko in ["", "High", "eleve", "critical", "none"] {
            assert!(!seuil_valide(ko), "{ko} doit être rejeté");
        }
    }

    #[test]
    fn gate_config_round_trip_sur_disque() {
        let dir = std::env::temp_dir().join(format!("sentinel-gate-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gate.json");

        // Fichier absent ⇒ valeurs par défaut.
        let def = charger_gate_config_fichier(&path);
        assert!(!def.enforce);

        // Écriture puis relecture identique.
        let cfg = GateConfig {
            enforce: true,
            seuil: "medium".to_string(),
        };
        ecrire_gate_config_fichier(&path, &cfg).unwrap();
        let relu = charger_gate_config_fichier(&path);
        assert!(relu.enforce);
        assert_eq!(relu.seuil, "medium");

        // JSON corrompu ⇒ défauts tolérants (jamais d'échec côté UI).
        std::fs::write(&path, "{ this is not json").unwrap();
        let secours = charger_gate_config_fichier(&path);
        assert!(!secours.enforce);
        assert_eq!(secours.seuil, "high");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Reconnaissance des constats approve-before-run ───────────────────────

    #[test]
    fn detecte_constat_retenu_et_advisory() {
        let retenu = constat_synthetique(
            "Appel retenu pour approbation — risque élevé (outil « x »)",
            "[temps réel — approve-before-run] Appel NON relayé (mode enforce). raison. Session s.",
        );
        let advisory = constat_synthetique(
            "Appel à risque élevé (advisory) — outil « x »",
            "[temps réel — approve-before-run] Appel relayé (mode détection). raison. Session s.",
        );
        let autre = constat_synthetique("Nouveau serveur", "découverte d'un nouveau serveur MCP");

        assert!(est_demande_approbation(&retenu));
        assert!(est_demande_approbation(&advisory));
        assert!(!est_demande_approbation(&autre));

        assert!(appel_retenu(&retenu), "le titre marque la rétention");
        assert!(!appel_retenu(&advisory), "un advisory n'est pas retenu");
    }

    #[test]
    fn constat_vers_demande_renseigne_le_dto() {
        let c = constat_synthetique(
            "Appel retenu pour approbation — risque élevé (outil « send_webhook »)",
            "[temps réel — approve-before-run] Appel NON relayé (mode enforce). raison. Session s.",
        );
        let d = constat_vers_demande(&c);
        assert_eq!(d.id, c.id.to_string());
        assert_eq!(d.server_id, c.serveur_id.to_string());
        assert_eq!(d.tool.as_deref(), Some("send_webhook"));
        assert_eq!(d.risk_level, "high");
        assert!(d.held);
        assert_eq!(d.source, "store");
        assert_eq!(d.state, "pending");
    }

    // ── Extraction de version épinglée ───────────────────────────────────────

    #[test]
    fn version_token_scope_et_simple() {
        assert_eq!(version_du_token("@org/pkg@1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(version_du_token("pkg@0.1.15").as_deref(), Some("0.1.15"));
        assert_eq!(version_du_token("@org/pkg"), None);
        assert_eq!(version_du_token("pkg"), None);
        assert_eq!(version_du_token("@org/pkg@"), None);
    }

    #[test]
    fn version_epinglee_ne_confond_pas_un_argument() {
        // La version doit provenir du token DÉSIGNANT le paquet, pas d'un arg.
        let endpoint = "npx -y mcp-remote@0.1.15 --header x@y";
        let pkg = extraire_package_id(endpoint, Transport::Stdio);
        assert_eq!(pkg, "mcp-remote");
        assert_eq!(
            extraire_version_epinglee(endpoint, &pkg).as_deref(),
            Some("0.1.15")
        );

        // Sans version épinglée : aucune extraction.
        let sans = "npx -y mcp-remote";
        let pkg2 = extraire_package_id(sans, Transport::Stdio);
        assert_eq!(extraire_version_epinglee(sans, &pkg2), None);
    }

    // ── Mapping CVE via la base embarquée (hors-ligne) ───────────────────────

    #[test]
    fn map_cve_sur_paquet_vulnerable_connu() {
        // `mcp-remote` < 0.1.16 est dans la base CVE embarquée.
        let constats = rechercher_cve("mcp-remote", "0.1.15");
        assert!(
            !constats.is_empty(),
            "mcp-remote 0.1.15 doit matcher la base embarquée"
        );
        let dto = map_cve("11111111-1111-1111-1111-111111111111", &constats[0]);
        assert_eq!(dto.server_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(dto.package, "mcp-remote");
        assert_eq!(dto.version, "0.1.15");
        assert!(dto.cve_id.starts_with("CVE-"));
        // La 1re référence est l'identifiant CVE lui-même.
        assert_eq!(dto.references.first().map(String::as_str), Some(dto.cve_id.as_str()));
        assert!(["info", "medium", "high", "critical"].contains(&dto.severity.as_str()));

        // Version corrigée : aucun constat.
        assert!(rechercher_cve("mcp-remote", "1.0.0").is_empty());
    }
}

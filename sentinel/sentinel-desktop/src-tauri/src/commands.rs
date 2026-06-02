//! Tauri commands exposed to the React frontend.
//!
//! Each command name MUST match the value in `src/api/contract.ts`.
//! Returned types use camelCase via `serde(rename_all)` where needed,
//! but for simplicity we mirror the protocol's snake_case in the JSON.

use sentinel_protocol::{Couleur, StatutServeur, Severite, Transport, Portee, ServeurId};
use sentinel_report::PlanRemediation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::state::AppState;

// ─── DTOs (mirror src/api/contract.ts) ──────────────────────────────────────

#[derive(Serialize)]
pub struct ServerCard {
    pub id: String,
    pub endpoint: String,
    pub transport: String,
    pub status: String,
    pub color: String,
    pub scopes: Vec<String>,
    pub tool_count: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub current_fingerprint: Option<String>,
}

#[derive(Serialize)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: serde_json::Value,
}

#[derive(Serialize)]
pub struct ServerDetail {
    pub server: ServerCard,
    pub tools: Vec<Tool>,
    pub open_findings: u64,
}

#[derive(Serialize)]
pub struct Finding {
    pub id: String,
    pub server_id: String,
    pub tool_name: Option<String>,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub diff: Option<String>,
    pub compliance_refs: Vec<String>,
    pub timestamp: String,
    pub state: String,
}

#[derive(Serialize, Default)]
pub struct Alert {
    pub id: String,
    pub finding_id: String,
    pub channel: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub diff: Option<String>,
    pub timestamp: String,
}

#[derive(Serialize, Clone, Default)]
pub struct ScanProgress {
    pub stage: String,
    pub servers_discovered: u64,
    pub tools_discovered: u64,
    pub time_to_first_red_ms: Option<u64>,
    pub log_line: Option<String>,
}

#[derive(Serialize)]
pub struct ExecutiveSummary {
    pub servers_total: u64,
    pub servers_approved: u64,
    pub servers_unapproved: u64,
    pub servers_at_risk: u64,
    pub findings_critical: u64,
    pub findings_high: u64,
    pub findings_medium: u64,
}

#[derive(Serialize)]
pub struct ComplianceReference {
    pub framework: String,
    pub identifier: String,
    pub title: String,
    pub url: Option<String>,
}

#[derive(Serialize)]
pub struct ReportBundle {
    pub executive_summary_md: String,
    pub inventory_md: String,
    pub changelog_md: String,
    pub compliance_map_md: String,
    pub remediation_plan_md: String,
    pub json_path: Option<String>,
    pub pdf_path: Option<String>,
    pub signed: bool,
    pub signature_iso8601: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanParams {
    pub mode: Option<String>,
    /// Required when `mode == "http"`: the Streamable HTTP MCP endpoint to probe.
    pub http_url: Option<String>,
}

#[derive(Deserialize)]
pub struct ApprovalDecision {
    pub decision: String,
    pub operator: String,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn libelle_transport(t: Transport) -> &'static str {
    match t {
        Transport::Stdio => "stdio",
        Transport::Http => "http",
    }
}

fn libelle_statut(s: StatutServeur) -> &'static str {
    match s {
        StatutServeur::Approuve => "approved",
        StatutServeur::Inconnu => "unknown",
        StatutServeur::Suspect => "suspect",
        StatutServeur::AInvestiguer => "to_investigate",
        StatutServeur::Bloque => "blocked",
    }
}

fn libelle_couleur(c: Couleur) -> &'static str {
    match c {
        Couleur::Vert => "green",
        Couleur::Orange => "orange",
        Couleur::Rouge => "red",
    }
}

fn libelle_portee(p: Portee) -> &'static str {
    match p {
        Portee::Filesystem => "filesystem",
        Portee::BaseDonnees => "database",
        Portee::ApiExterne => "external_api",
        Portee::Secrets => "secrets",
        Portee::Reseau => "network",
        Portee::Lecture => "read",
        Portee::Ecriture => "write",
        Portee::Inconnu => "unknown",
    }
}

fn libelle_severite(s: Severite) -> &'static str {
    match s {
        Severite::Info => "info",
        Severite::Moyenne => "medium",
        Severite::Haute => "high",
        Severite::Critique => "critical",
    }
}

fn serveur_to_card(s: &sentinel_protocol::Serveur, tool_count: u64) -> ServerCard {
    ServerCard {
        id: s.id.to_string(),
        endpoint: s.endpoint.clone(),
        transport: libelle_transport(s.transport).into(),
        status: libelle_statut(s.statut).into(),
        color: libelle_couleur(s.couleur).into(),
        scopes: s.portees.iter().copied().map(|p| libelle_portee(p).to_string()).collect(),
        tool_count,
        first_seen: s.premiere_vue.to_rfc3339(),
        last_seen: s.derniere_vue.to_rfc3339(),
        current_fingerprint: s.empreinte_courante.clone(),
    }
}

// ─── Commands ───────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_servers(state: State<'_, AppState>) -> Result<Vec<ServerCard>, String> {
    let store = state.store.clone();
    let serveurs = tokio::task::spawn_blocking(move || store.lister_serveurs())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    let mut cards = Vec::with_capacity(serveurs.len());
    for s in &serveurs {
        let store2 = state.store.clone();
        let id = s.id;
        let outils = tokio::task::spawn_blocking(move || store2.lister_outils(id))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        cards.push(serveur_to_card(s, outils.len() as u64));
    }
    Ok(cards)
}

#[tauri::command]
pub async fn get_server_detail(id: String, state: State<'_, AppState>) -> Result<ServerDetail, String> {
    let server_id: ServeurId = Uuid::parse_str(&id).map_err(|e| format!("bad uuid: {}", e))?;
    let store = state.store.clone();
    let serveurs = tokio::task::spawn_blocking(move || store.lister_serveurs())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let s = serveurs.iter().find(|s| s.id == server_id)
        .ok_or_else(|| format!("server not found: {}", id))?
        .clone();

    let store2 = state.store.clone();
    let outils = tokio::task::spawn_blocking(move || store2.lister_outils(server_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    let card = serveur_to_card(&s, outils.len() as u64);
    let tools: Vec<Tool> = outils.into_iter().map(|o| Tool {
        name: o.nom,
        description: o.description,
        input_schema: o.input_schema,
    }).collect();

    let store3 = state.store.clone();
    let constats = tokio::task::spawn_blocking(move || store3.lister_constats_ouverts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let open_findings = constats.iter().filter(|c| c.serveur_id == server_id).count() as u64;

    Ok(ServerDetail { server: card, tools, open_findings })
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    params: ScanParams,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    {
        let mut running = state.scan_running.write().await;
        if *running {
            return Ok(serde_json::json!({ "ok": false, "reason": "already running" }));
        }
        *running = true;
    }
    let mode = params.mode.unwrap_or_else(|| "stdio".to_string());
    let http_url = params.http_url;
    let app_clone = app.clone();
    let state_clone = state.inner().clone();

    tokio::spawn(async move {
        let _ = run_scan_loop(app_clone, state_clone, mode, http_url).await;
    });

    Ok(serde_json::json!({ "ok": true }))
}

async fn run_scan_loop(
    app: AppHandle,
    state: AppState,
    mode: String,
    http_url: Option<String>,
) -> anyhow::Result<()> {
    use sentinel_detect::InspecteurPoisoning;
    use sentinel_discovery::{
        active_probe::{EtatProbe, ProbeurActif},
        OrchestrateurDecouverte,
    };
    use sentinel_protocol::{Portee, Transport};
    use sentinel_scan::scope::inferer_portee;
    use sentinel_scan::store_contract::{
        AdaptateurStore, ContratScanStore, EvenementInventaire,
    };

    let start = std::time::Instant::now();

    // HTTP mode: probe a single Streamable HTTP MCP endpoint provided by the UI.
    if mode.eq_ignore_ascii_case("http") {
        use sentinel_discovery::active_probe_http::ProbeurHttp;

        let url = match http_url.as_ref().map(|u| u.trim()).filter(|u| !u.is_empty()) {
            Some(u) => u.to_string(),
            None => {
                let _ = app.emit(
                    "sentinel://scan-progress",
                    ScanProgress {
                        stage: "error".into(),
                        servers_discovered: 0,
                        tools_discovered: 0,
                        time_to_first_red_ms: None,
                        log_line: Some(
                            "HTTP scan requires an endpoint URL — none provided".into(),
                        ),
                    },
                );
                *state.scan_running.write().await = false;
                return Ok(());
            }
        };

        // Derive a stable logical name from the URL host (best-effort: split
        // on "://" then on "/" — no extra crate needed for this lightweight
        // labelling).
        let nom = {
            let apres_schema = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(url.as_str());
            let host = apres_schema
                .split('/')
                .next()
                .unwrap_or(apres_schema)
                .trim();
            if host.is_empty() {
                url.clone()
            } else {
                host.to_string()
            }
        };

        let _ = app.emit(
            "sentinel://scan-progress",
            ScanProgress {
                stage: "capturing".into(),
                servers_discovered: 0,
                tools_discovered: 0,
                time_to_first_red_ms: None,
                log_line: Some(format!("Probing HTTP {}…", url)),
            },
        );

        let adaptateur = Arc::new(AdaptateurStore::nouveau(state.store.clone()));
        let probeur = ProbeurHttp::par_defaut();
        let rapport_probe = probeur.probe_url(&nom, &url).await;

        let mut servers_discovered: u64 = 0;
        let mut tools_discovered: u64 = 0;
        let mut time_to_first_red_ms: Option<u64> = None;

        if rapport_probe.etat != EtatProbe::Reussi {
            let raison = rapport_probe
                .erreur
                .clone()
                .unwrap_or_else(|| format!("{:?}", rapport_probe.etat));
            let _ = app.emit(
                "sentinel://scan-progress",
                ScanProgress {
                    stage: "error".into(),
                    servers_discovered: 0,
                    tools_discovered: 0,
                    time_to_first_red_ms: None,
                    log_line: Some(format!("Probe failed for {}: {}", url, raison)),
                },
            );
        } else {
            // Persist identically to stdio: scopes, inventory event, poisoning findings.
            let portees = inferer_portee(&rapport_probe.outils);
            let nb_outils = rapport_probe.outils.len() as u64;

            let evenement = EvenementInventaire {
                endpoint: url.clone(),
                transport: Transport::Http,
                outils: rapport_probe.outils.clone(),
                portees: portees.clone(),
            };

            match adaptateur.enregistrer_inventaire(evenement).await {
                Ok(serveur_id) => {
                    servers_discovered = 1;
                    tools_discovered = nb_outils;

                    let constats = if rapport_probe.constats_poisoning.is_empty() {
                        InspecteurPoisoning::inspecter(&rapport_probe.outils)
                    } else {
                        rapport_probe.constats_poisoning.clone()
                    };
                    for cp in &constats {
                        let constat = InspecteurPoisoning::vers_constat(cp, serveur_id);
                        if let Err(e) = state.store.enregistrer_constat(&constat) {
                            log::warn!("could not store poisoning finding: {}", e);
                        }
                    }

                    let est_rouge = portees
                        .iter()
                        .any(|p| matches!(p, Portee::Secrets | Portee::Filesystem));
                    if est_rouge && time_to_first_red_ms.is_none() {
                        time_to_first_red_ms = Some(start.elapsed().as_millis() as u64);
                    }

                    let _ = app.emit(
                        "sentinel://scan-progress",
                        ScanProgress {
                            stage: "capturing".into(),
                            servers_discovered,
                            tools_discovered,
                            time_to_first_red_ms,
                            log_line: Some(format!(
                                "Probed {} — {} tool(s) discovered",
                                url, nb_outils
                            )),
                        },
                    );
                }
                Err(e) => {
                    let _ = app.emit(
                        "sentinel://scan-progress",
                        ScanProgress {
                            stage: "error".into(),
                            servers_discovered: 0,
                            tools_discovered: 0,
                            time_to_first_red_ms: None,
                            log_line: Some(format!("Failed to persist {}: {}", url, e)),
                        },
                    );
                }
            }
        }

        let _ = app.emit(
            "sentinel://scan-progress",
            ScanProgress {
                stage: "finished".into(),
                servers_discovered,
                tools_discovered,
                time_to_first_red_ms,
                log_line: Some(format!(
                    "Scan finished in {} ms",
                    start.elapsed().as_millis()
                )),
            },
        );
        *state.scan_running.write().await = false;
        return Ok(());
    }

    // 1. Discover every AI client + declared MCP server on this Mac.
    let rapport = OrchestrateurDecouverte::default().balayer().await;

    let nb_clients = rapport.clients.len();
    let nb_serveurs_declares: usize =
        rapport.clients.iter().map(|c| c.serveurs.len()).sum();

    // 2. Initial "capturing" event with the discovery summary.
    let _ = app.emit(
        "sentinel://scan-progress",
        ScanProgress {
            stage: "capturing".into(),
            servers_discovered: 0,
            tools_discovered: 0,
            time_to_first_red_ms: None,
            log_line: Some(format!(
                "Discovered {} declared servers across {} clients",
                nb_serveurs_declares, nb_clients
            )),
        },
    );

    let adaptateur = Arc::new(AdaptateurStore::nouveau(state.store.clone()));
    let probeur = ProbeurActif::par_defaut();

    let mut servers_discovered: u64 = 0;
    let mut tools_discovered: u64 = 0;
    let mut time_to_first_red_ms: Option<u64> = None;

    // 3. Probe every declared stdio server, emit live progress.
    for client in &rapport.clients {
        for serv in &client.serveurs {
            if serv.disabled {
                continue;
            }
            // Only stdio servers are probed today.
            if !serv.transport.eq_ignore_ascii_case("stdio") {
                continue;
            }

            let _ = app.emit(
                "sentinel://scan-progress",
                ScanProgress {
                    stage: "capturing".into(),
                    servers_discovered,
                    tools_discovered,
                    time_to_first_red_ms,
                    log_line: Some(format!("Probing {}…", serv.nom)),
                },
            );

            let rapport_probe = probeur.probe_serveur(serv).await;

            if rapport_probe.etat != EtatProbe::Reussi {
                let raison = rapport_probe
                    .erreur
                    .clone()
                    .unwrap_or_else(|| format!("{:?}", rapport_probe.etat));
                let _ = app.emit(
                    "sentinel://scan-progress",
                    ScanProgress {
                        stage: "capturing".into(),
                        servers_discovered,
                        tools_discovered,
                        time_to_first_red_ms,
                        log_line: Some(format!(
                            "Probe failed for {}: {}",
                            serv.nom, raison
                        )),
                    },
                );
                continue;
            }

            // 4. Successful probe — persist server + tools through the contract.
            let portees = inferer_portee(&rapport_probe.outils);
            let nb_outils = rapport_probe.outils.len() as u64;

            let endpoint = if rapport_probe.serveur_commande.is_empty() {
                serv.nom.clone()
            } else {
                rapport_probe.serveur_commande.clone()
            };

            let evenement = EvenementInventaire {
                endpoint: endpoint.clone(),
                transport: Transport::Stdio,
                outils: rapport_probe.outils.clone(),
                portees: portees.clone(),
            };

            let serveur_id = match adaptateur.enregistrer_inventaire(evenement).await {
                Ok(id) => id,
                Err(e) => {
                    let _ = app.emit(
                        "sentinel://scan-progress",
                        ScanProgress {
                            stage: "capturing".into(),
                            servers_discovered,
                            tools_discovered,
                            time_to_first_red_ms,
                            log_line: Some(format!(
                                "Failed to persist {}: {}",
                                serv.nom, e
                            )),
                        },
                    );
                    continue;
                }
            };

            servers_discovered += 1;
            tools_discovered += nb_outils;

            // 5. Persist poisoning findings, if any.
            let constats = if rapport_probe.constats_poisoning.is_empty() {
                InspecteurPoisoning::inspecter(&rapport_probe.outils)
            } else {
                rapport_probe.constats_poisoning.clone()
            };
            for cp in &constats {
                let constat = InspecteurPoisoning::vers_constat(cp, serveur_id);
                if let Err(e) = state.store.enregistrer_constat(&constat) {
                    log::warn!("could not store poisoning finding: {}", e);
                }
            }

            // 6. Time-to-first-red: first sighting of a Secrets/Filesystem server.
            let est_rouge = portees
                .iter()
                .any(|p| matches!(p, Portee::Secrets | Portee::Filesystem));
            if est_rouge && time_to_first_red_ms.is_none() {
                time_to_first_red_ms = Some(start.elapsed().as_millis() as u64);
            }

            let _ = app.emit(
                "sentinel://scan-progress",
                ScanProgress {
                    stage: "capturing".into(),
                    servers_discovered,
                    tools_discovered,
                    time_to_first_red_ms,
                    log_line: Some(format!(
                        "Probed {} — {} tool(s) discovered",
                        serv.nom, nb_outils
                    )),
                },
            );
        }
    }

    // 7. Final event.
    let _ = app.emit(
        "sentinel://scan-progress",
        ScanProgress {
            stage: "finished".into(),
            servers_discovered,
            tools_discovered,
            time_to_first_red_ms,
            log_line: Some(format!(
                "Scan finished in {} ms",
                start.elapsed().as_millis()
            )),
        },
    );

    *state.scan_running.write().await = false;
    Ok(())
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    *state.scan_running.write().await = false;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub async fn scan_progress(state: State<'_, AppState>) -> Result<ScanProgress, String> {
    let running = *state.scan_running.read().await;
    Ok(ScanProgress {
        stage: if running { "capturing".into() } else { "idle".into() },
        servers_discovered: 0,
        tools_discovered: 0,
        time_to_first_red_ms: None,
        log_line: None,
    })
}

#[tauri::command]
pub async fn list_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    let store = state.store.clone();
    let constats = tokio::task::spawn_blocking(move || store.lister_constats_ouverts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    Ok(constats.into_iter().map(|c| Finding {
        id: c.id.to_string(),
        server_id: c.serveur_id.to_string(),
        tool_name: c.outil_nom,
        finding_type: format!("{:?}", c.type_constat).to_lowercase(),
        severity: libelle_severite(c.severite).into(),
        title: c.titre,
        detail: c.detail,
        diff: c.diff,
        compliance_refs: c.references_conformite,
        timestamp: c.horodatage.to_rfc3339(),
        state: format!("{:?}", c.etat).to_lowercase(),
    }).collect())
}

#[tauri::command]
pub async fn resolve_finding(
    state: State<'_, AppState>,
    finding_id: String,
    note: Option<String>,
) -> Result<(), String> {
    let id = Uuid::parse_str(&finding_id).map_err(|e| format!("bad uuid: {}", e))?;
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.marquer_constat_resolu(id, note))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn list_alerts(state: State<'_, AppState>) -> Result<Vec<Alert>, String> {
    // Each open Constat surfaces as a "dashboard" Alert in the in-app feed.
    // Other channels (email/webhook/siem) are produced by the alert pipeline,
    // not by this endpoint.
    let store = state.store.clone();
    let constats = tokio::task::spawn_blocking(move || store.lister_constats_ouverts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    Ok(constats
        .into_iter()
        .map(|c| Alert {
            id: format!("alert-{}", c.id),
            finding_id: c.id.to_string(),
            channel: "dashboard".to_string(),
            severity: libelle_severite(c.severite).into(),
            title: c.titre,
            message: c.detail,
            diff: c.diff,
            timestamp: c.horodatage.to_rfc3339(),
        })
        .collect())
}

#[tauri::command]
pub async fn apply_approval(
    server_id: String,
    decision: ApprovalDecision,
    state: State<'_, AppState>,
) -> Result<ServerCard, String> {
    let id: ServeurId = Uuid::parse_str(&server_id).map_err(|e| e.to_string())?;
    let store = state.store.clone();
    let decision_str = decision.decision.clone();
    let operator = decision.operator.clone();

    let serveur = tokio::task::spawn_blocking(move || -> anyhow::Result<sentinel_protocol::Serveur> {
        use sentinel_detect::empreinte_serveur;
        use sentinel_report::approval::{DecisionApprobation, FluxApprobation};

        let d = match decision_str.as_str() {
            "approve" => DecisionApprobation::Approuve,
            "investigate" => DecisionApprobation::AInvestiguer,
            "block" => DecisionApprobation::Bloque,
            _ => anyhow::bail!("unknown decision: {}", decision_str),
        };

        // Idempotence guard: on `approve`, if the most recent baseline already
        // matches the current server fingerprint, skip baseline creation —
        // re-running the same approval must not duplicate the row. We still
        // refresh statut/couleur/derniere_vue so the UI sees a consistent state.
        if d == DecisionApprobation::Approuve {
            let outils = store.lister_outils(id)?;
            let empreinte_courante = empreinte_serveur(&outils);
            if let Some(derniere) = store.derniere_baseline(id)? {
                if derniere.empreinte_serveur == empreinte_courante {
                    log::info!(
                        "apply_approval: baseline unchanged — re-using existing (server={}, fingerprint={})",
                        id,
                        empreinte_courante.as_str()
                    );
                    let mut serveur = store
                        .lister_serveurs()?
                        .into_iter()
                        .find(|s| s.id == id)
                        .ok_or_else(|| anyhow::anyhow!("serveur introuvable : {id}"))?;
                    serveur.statut = sentinel_protocol::StatutServeur::Approuve;
                    serveur.couleur = sentinel_protocol::Couleur::Vert;
                    serveur.derniere_vue = chrono::Utc::now();
                    store.upsert_serveur(&serveur)?;
                    return Ok(serveur);
                }
            }
        }

        let flux = FluxApprobation::nouveau(store.clone());
        flux.appliquer(id, d, &operator)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    Ok(serveur_to_card(&serveur, 0))
}

#[derive(Serialize)]
pub struct BaselineSummary {
    pub id: String,
    pub server_id: String,
    pub fingerprint: String,
    pub tool_count: u64,
    pub approved_by: String,
    pub approved_at: String,
}

#[tauri::command]
pub async fn list_baselines(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<BaselineSummary>, String> {
    let id: ServeurId = Uuid::parse_str(&server_id).map_err(|e| e.to_string())?;
    let store = state.store.clone();
    let baselines = tokio::task::spawn_blocking(move || store.lister_baselines(id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    Ok(baselines
        .into_iter()
        .map(|b| BaselineSummary {
            id: b.id.to_string(),
            server_id: b.serveur_id.to_string(),
            fingerprint: b.empreinte_serveur.as_str().to_string(),
            tool_count: b.outils.len() as u64,
            approved_by: b.approuve_par,
            approved_at: b.date_approbation.to_rfc3339(),
        })
        .collect())
}

#[tauri::command]
pub async fn generate_report(state: State<'_, AppState>) -> Result<ReportBundle, String> {
    let store = state.store.clone();
    let gen = sentinel_report::GenerateurRapport::nouveau(store.clone());
    let bundle = gen.generer_bundle().await.map_err(|e| e.to_string())?;

    // Also write PDF + JSON to a stable path the UI can open.
    let dir = std::env::temp_dir().join("sentinel-mcp");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let pdf_path = dir.join("sentinel-report.pdf");
    let json_path = dir.join("sentinel-report.json");

    let plan = PlanRemediation::construire(&bundle.inventaire, &[]);
    let inventory_txt = bundle.inventaire.iter()
        .map(|s| format!("- {} | transport={:?} | status={:?} | color={:?}",
            s.endpoint, s.transport, s.statut, s.couleur))
        .collect::<Vec<_>>().join("\n");
    let contenu_pdf = sentinel_report::pdf::ContenuPdf {
        titre: "Sentinel MCP Compliance Report".into(),
        sous_titre: "OWASP MCP09 / MCP03 — SAFE-MCP T1001 / T1201".into(),
        resume_exec: bundle.resume_exec_md.clone(),
        inventaire: inventory_txt,
        journal: bundle.journal_md.clone(),
        mapping_conformite: bundle.mapping_conformite_md.clone(),
        plan_remediation: PlanRemediation::vers_markdown(&plan),
        horodatage: chrono::Utc::now().to_rfc3339(),
    };
    let _ = sentinel_report::pdf::RenduPdf::produire_contenu(&contenu_pdf, &pdf_path);

    // JSON export.
    let store_clone = store.clone();
    let json_path_for_task = json_path.clone();
    let _ = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let serveurs = store_clone.lister_serveurs()?;
        let constats = store_clone.lister_constats_ouverts()?;
        let schema = sentinel_report::json_export::ExportJson::construire(serveurs, constats);
        sentinel_report::json_export::ExportJson::produire_depuis(&schema, &json_path_for_task)?;
        Ok(())
    }).await;

    Ok(ReportBundle {
        executive_summary_md: bundle.resume_exec_md,
        inventory_md: bundle.journal_md.clone(),
        changelog_md: bundle.journal_md,
        compliance_map_md: bundle.mapping_conformite_md,
        remediation_plan_md: bundle.plan_remediation_md,
        json_path: Some(json_path.to_string_lossy().to_string()),
        pdf_path: Some(pdf_path.to_string_lossy().to_string()),
        signed: bundle.signature_ed25519.is_some(),
        signature_iso8601: bundle.signature_horodatage.map(|d| d.to_rfc3339()),
    })
}

#[tauri::command]
pub async fn open_report_file(path: String, app: AppHandle) -> Result<serde_json::Value, String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener().open_path(path, None::<&str>).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub async fn executive_summary(state: State<'_, AppState>) -> Result<ExecutiveSummary, String> {
    let store = state.store.clone();
    let serveurs = tokio::task::spawn_blocking({
        let s = store.clone();
        move || s.lister_serveurs()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    let constats = tokio::task::spawn_blocking(move || store.lister_constats_ouverts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    let resume = sentinel_report::summary::ResumeExecutif::construire(&serveurs, &constats);
    Ok(ExecutiveSummary {
        servers_total: resume.serveurs_total,
        servers_approved: resume.serveurs_approuves,
        servers_unapproved: resume.serveurs_non_approuves,
        servers_at_risk: resume.serveurs_a_risque,
        findings_critical: resume.constats_critiques,
        findings_high: resume.constats_hauts,
        findings_medium: resume.constats_moyens,
    })
}

#[tauri::command]
pub async fn compliance_references() -> Result<Vec<ComplianceReference>, String> {
    use sentinel_protocol::TypeConstat;
    use sentinel_report::compliance::MoteurConformite;
    let mut refs = Vec::new();
    for t in [
        TypeConstat::NouveauServeur,
        TypeConstat::RugPull,
        TypeConstat::Poisoning,
        TypeConstat::Sosie,
        TypeConstat::Exfiltration,
        TypeConstat::SansAuthentification,
        TypeConstat::DeriveInterSession,
    ] {
        for r in MoteurConformite::references_pour(&t) {
            refs.push(ComplianceReference {
                framework: r.cadre.to_string(),
                identifier: r.identifiant.to_string(),
                title: r.titre.to_string(),
                url: r.url.map(|u| u.to_string()),
            });
        }
    }
    refs.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    refs.dedup_by(|a, b| a.identifier == b.identifier);
    Ok(refs)
}

#[tauri::command]
pub fn app_version() -> Result<String, String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

#[derive(Serialize)]
pub struct ObservedEvent {
    pub id: String,
    pub server_id: String,
    pub session_id: String,
    pub method: String,
    pub timestamp: String,
    pub direction: String,
}

// ─── Email test channel ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TestEmailInput {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub sender: String,
    pub recipient: String,
}

#[derive(Serialize)]
pub struct TestEmailResult {
    pub ok: bool,
    pub file_path: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn test_email_channel(cfg: TestEmailInput) -> Result<TestEmailResult, String> {
    use sentinel_alerts::channels::email::{CanalEmail, ConfigEmail};
    use sentinel_alerts::channels::CanalEmetteur;
    use sentinel_protocol::{Alerte, CanalAlerte, Severite};

    let config = ConfigEmail {
        smtp_host: cfg.smtp_host,
        smtp_port: cfg.smtp_port,
        utilisateur: cfg.user,
        mot_de_passe: cfg.password,
        expediteur: cfg.sender,
        destinataire: cfg.recipient,
    };

    let canal = CanalEmail::dry_run(config);

    let alerte_id = Uuid::new_v4();
    let alerte = Alerte {
        id: alerte_id,
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Email,
        severite: Severite::Critique,
        titre: "Sentinel MCP — test email".to_string(),
        message: "This is a synthetic test email sent from the Settings page \
                  to verify the email alert channel is wired correctly."
            .to_string(),
        diff: Some("synthetic test from Sentinel MCP".to_string()),
        horodatage: chrono::Utc::now(),
        envoyee: false,
        tentatives: 0,
    };

    match canal.emettre(&alerte).await {
        Ok(()) => Ok(TestEmailResult {
            ok: true,
            file_path: Some(format!("/tmp/sentinel-emails/{}.eml", alerte_id)),
            error: None,
        }),
        Err(e) => Ok(TestEmailResult {
            ok: false,
            file_path: None,
            error: Some(e.to_string()),
        }),
    }
}

// ─── Webhook test channel ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TestWebhookInput {
    pub url: String,
    pub format: String, // "generic" | "slack" | "teams"
}

#[derive(Serialize)]
pub struct TestWebhookResult {
    pub ok: bool,
    pub status: Option<u16>,
    pub body_preview: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn test_webhook_channel(cfg: TestWebhookInput) -> Result<TestWebhookResult, String> {
    use sentinel_alerts::channels::webhook::{CanalWebhook, TypeWebhook};
    use sentinel_alerts::channels::CanalEmetteur;
    use sentinel_protocol::{Alerte, CanalAlerte, Severite};

    if cfg.url.trim().is_empty() {
        return Ok(TestWebhookResult {
            ok: false,
            status: None,
            body_preview: None,
            error: Some("Webhook URL is empty".to_string()),
        });
    }

    let type_webhook = match cfg.format.to_lowercase().as_str() {
        "slack" => TypeWebhook::Slack,
        "teams" => TypeWebhook::Teams,
        "generic" | "" => TypeWebhook::Generique,
        other => {
            return Ok(TestWebhookResult {
                ok: false,
                status: None,
                body_preview: None,
                error: Some(format!("unknown webhook format: {}", other)),
            });
        }
    };

    let canal = CanalWebhook::nouveau(cfg.url.clone(), type_webhook);

    // Synthetic test alert.
    let alerte = Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Webhook,
        severite: Severite::Critique,
        titre: "Sentinel MCP test".to_string(),
        message: "Synthetic test from Sentinel MCP".to_string(),
        diff: None,
        horodatage: chrono::Utc::now(),
        envoyee: false,
        tentatives: 0,
    };

    let body_preview = serde_json::to_string(&canal.charge_utile(&alerte))
        .ok()
        .map(|s| {
            if s.len() > 240 {
                format!("{}…", &s[..240])
            } else {
                s
            }
        });

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        canal.emettre(&alerte),
    )
    .await;

    match outcome {
        Ok(Ok(())) => Ok(TestWebhookResult {
            ok: true,
            status: Some(200),
            body_preview,
            error: None,
        }),
        Ok(Err(e)) => Ok(TestWebhookResult {
            ok: false,
            status: None,
            body_preview,
            error: Some(e.to_string()),
        }),
        Err(_) => Ok(TestWebhookResult {
            ok: false,
            status: None,
            body_preview,
            error: Some("Webhook request timed out after 10s".to_string()),
        }),
    }
}

// ─── Live background monitoring ────────────────────────────────────────────

#[derive(Serialize)]
pub struct LiveStatus {
    pub interval_secs: u64,
    pub last_refresh_iso: String,
    pub watching_paths: Vec<String>,
}

/// Snapshot of the background loop: current tick interval, last refresh
/// timestamp, and the absolute paths the file watcher is armed on.
#[tauri::command]
pub async fn get_live_status(state: State<'_, AppState>) -> Result<LiveStatus, String> {
    use std::sync::atomic::Ordering;
    let interval = state.live_interval_secs.load(Ordering::Relaxed);
    let last = state.last_refresh_at.read().await;
    let watching_paths = crate::background::chemins_a_surveiller()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    Ok(LiveStatus {
        interval_secs: interval,
        last_refresh_iso: last.to_rfc3339(),
        watching_paths,
    })
}

/// Mutate the tick interval (seconds). Clamped to [10, 3600] to avoid both
/// runaway CPU and "live" intervals so long the badge becomes meaningless.
#[tauri::command]
pub async fn set_live_interval(
    state: State<'_, AppState>,
    secs: u64,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    let clamped = secs.clamp(10, 3600);
    state.live_interval_secs.store(clamped, Ordering::Relaxed);
    log::info!("live interval set to {} s", clamped);
    Ok(())
}

// ─── Investigations ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Investigation {
    pub id: String,
    pub server_id: String,
    pub note: String,
    pub created_by: String,
    pub created_at: String,
    pub state: String,
}

/// Create a persisted investigation note attached to a server. Returns the
/// new investigation id so the UI can surface it (e.g. in a toast).
#[tauri::command]
pub async fn create_investigation(
    state: State<'_, AppState>,
    server_id: String,
    note: String,
    operator: String,
) -> Result<String, String> {
    let id: ServeurId = Uuid::parse_str(&server_id).map_err(|e| format!("bad uuid: {}", e))?;
    let store = state.store.clone();
    let id_str = tokio::task::spawn_blocking(move || {
        store.enregistrer_investigation(id, &note, &operator)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    Ok(id_str)
}

/// List investigation notes, optionally filtered to a single server. Most
/// recent first.
#[tauri::command]
pub async fn list_investigations(
    state: State<'_, AppState>,
    server_id: Option<String>,
) -> Result<Vec<Investigation>, String> {
    let filter = match server_id {
        Some(s) => Some(Uuid::parse_str(&s).map_err(|e| format!("bad uuid: {}", e))?),
        None => None,
    };
    let store = state.store.clone();
    let rows = tokio::task::spawn_blocking(move || store.lister_investigations(filter))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|i| {
            // Strip JSON quotes around state (stored as `"ouvert"`).
            let etat = i.etat.trim_matches('"').to_string();
            Investigation {
                id: i.id,
                server_id: i.serveur_id,
                note: i.note,
                created_by: i.cree_par,
                created_at: i.cree_a.to_rfc3339(),
                state: etat,
            }
        })
        .collect())
}

#[tauri::command]
pub async fn list_observed_events(
    state: State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<ObservedEvent>, String> {
    let store = state.store.clone();
    let cap = limit.unwrap_or(500);
    let rows = tokio::task::spawn_blocking(move || store.lister_historique(cap))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|h| ObservedEvent {
            id: h.id.to_string(),
            server_id: h.serveur_id,
            session_id: h.session_id,
            method: h.methode,
            timestamp: h.horodatage.to_rfc3339(),
            direction: "client_to_server".to_string(),
        })
        .collect())
}

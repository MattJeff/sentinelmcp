//! Full E2E smoke test for Sentinel MCP (agent A15).
//!
//! Exercises the live host pipeline:
//!   1. Discovery sweep — find every AI client with declared MCP servers.
//!   2. Active probe — actually talk to each declared stdio server and list
//!      its tools.
//!   3. Trust graph — derive English scopes + blast radius per client.
//!   4. Threat intel — confirm the bundled feed loads with its full entry
//!      count.
//!
//! Run with:
//!   cargo run --example smoke_e2e -p sentinel-discovery

use sentinel_discovery::{
    OrchestrateurDecouverte,
    active_probe::{EtatProbe, ProbeurActif},
    threat_intel::FluxMenaces,
    trust_graph::ConstructeurGraphe,
};

#[tokio::main]
async fn main() {
    println!("=== Sentinel MCP — full E2E smoke test ===\n");

    // ------------------------------------------------------------------
    // 1. Discovery sweep
    // ------------------------------------------------------------------
    let rapport = OrchestrateurDecouverte::default().balayer().await;

    let nb_clients = rapport.clients.len();
    let nb_serveurs: usize = rapport.clients.iter().map(|c| c.serveurs.len()).sum();
    println!("[discovery]");
    println!("  detected clients : {}", nb_clients);
    println!("  declared servers : {}", nb_serveurs);
    for client in &rapport.clients {
        println!(
            "    - {} ({} server(s))",
            client.libelle,
            client.serveurs.len()
        );
        for serveur in &client.serveurs {
            let disabled = if serveur.disabled { " [disabled]" } else { "" };
            println!(
                "        • {} (transport={}){}",
                serveur.nom, serveur.transport, disabled
            );
        }
    }
    println!();

    // ------------------------------------------------------------------
    // 2. Active probe — stdio servers only
    // ------------------------------------------------------------------
    println!("[active probe]");
    let probe = ProbeurActif::par_defaut();
    let mut nb_probes = 0usize;
    let mut nb_reussi = 0usize;
    let mut nb_echec = 0usize;
    let mut tools_orizn = 0usize;

    for client in &rapport.clients {
        for serveur in &client.serveurs {
            if serveur.disabled {
                continue;
            }
            // Only probe stdio servers — the probe itself skips http/sse,
            // but we filter here too for cleaner output.
            if !serveur.transport.eq_ignore_ascii_case("stdio") {
                continue;
            }
            nb_probes += 1;
            let r = probe.probe_serveur(serveur).await;
            let outcome = match &r.etat {
                EtatProbe::Reussi => {
                    nb_reussi += 1;
                    if serveur.nom.contains("orizn") {
                        tools_orizn = r.outils.len();
                    }
                    format!("success ({} tool(s))", r.outils.len())
                }
                EtatProbe::EchecLancement => {
                    nb_echec += 1;
                    format!(
                        "fail [spawn] {}",
                        r.erreur.clone().unwrap_or_default()
                    )
                }
                EtatProbe::EchecHandshake => {
                    nb_echec += 1;
                    format!(
                        "fail [handshake] {}",
                        r.erreur.clone().unwrap_or_default()
                    )
                }
                EtatProbe::EchecParseur => {
                    nb_echec += 1;
                    format!(
                        "fail [parse] {}",
                        r.erreur.clone().unwrap_or_default()
                    )
                }
            };
            println!(
                "  {:32} via {:24} -> {} ({} ms)",
                serveur.nom, client.libelle, outcome, r.duree_ms
            );
        }
    }
    println!(
        "  totals : probed={}, success={}, fail={}",
        nb_probes, nb_reussi, nb_echec
    );
    println!("  orizn-visa tools observed : {}", tools_orizn);
    println!();

    // ------------------------------------------------------------------
    // 3. Trust graph + English scopes
    // ------------------------------------------------------------------
    println!("[trust graph]");
    let g = ConstructeurGraphe::construire(&rapport.clients);
    for s in &g.serveurs {
        println!(
            "  server {:?}  scopes={:?}",
            s.nom, s.portees
        );
    }
    for c in &g.clients {
        println!(
            "  client {:?}  blast_radius={}",
            c.libelle, c.blast_radius
        );
    }
    println!("  max blast radius = {}", g.indice_max);
    println!();

    // ------------------------------------------------------------------
    // 4. Threat intel feed
    // ------------------------------------------------------------------
    let menaces = FluxMenaces::par_defaut();
    println!("[threat intel]");
    println!("  feed version : {}", menaces.version_feed);
    println!("  entries      : {}", menaces.entrees.len());
    println!();

    println!("=== E2E smoke test complete ===");
}

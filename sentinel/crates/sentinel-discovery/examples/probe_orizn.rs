// Probe live the orizn-visa MCP server on this Mac.
use sentinel_discovery::{
    OrchestrateurDecouverte,
    active_probe::ProbeurActif,
    supply_chain::VerifierSupplyChain,
    threat_intel::FluxMenaces,
    trust_graph::ConstructeurGraphe,
};

#[tokio::main]
async fn main() {
    println!("=== Sentinel MCP — live probe ===\n");

    let rapport = OrchestrateurDecouverte::default().balayer().await;
    let probe = ProbeurActif::par_defaut();
    let supply = VerifierSupplyChain::par_defaut();
    let menaces = FluxMenaces::par_defaut();

    for client in &rapport.clients {
        for serveur in &client.serveurs {
            println!("─── {} via {} ───", serveur.nom, client.libelle);

            // 1. Active probe
            let r = probe.probe_serveur(serveur).await;
            println!("active probe : {:?} in {} ms", r.etat, r.duree_ms);
            if let Some(emp) = &r.empreinte_serveur {
                println!("  fingerprint : {}…", &emp.as_str()[..16.min(emp.as_str().len())]);
            }
            println!("  tools       : {}", r.outils.len());
            for o in &r.outils {
                let desc = o.description.as_deref().unwrap_or("(no description)");
                let desc = if desc.len() > 80 { format!("{}…", &desc[..80]) } else { desc.to_string() };
                println!("    • {} — {}", o.nom, desc);
            }
            if !r.constats_poisoning.is_empty() {
                println!("  ⚠ poisoning : {} signal(s)", r.constats_poisoning.len());
                for c in &r.constats_poisoning {
                    println!("    pattern='{}'  on  outil='{}'", c.pattern, c.outil);
                }
            }

            // 2. Supply chain
            let att = supply.attester(serveur).await;
            println!("supply chain : {:?}", att.etat);
            if let Some(pkg) = &att.package_name { println!("  package    : {}", pkg); }
            if let Some(v) = &att.version_disponible { println!("  latest     : {}", v); }
            if !att.maintainers.is_empty() { println!("  maintainers: {:?}", att.maintainers); }
            if let Some(date) = att.publie_a { println!("  published  : {}", date); }

            // 3. Threat intel
            let hits = menaces.correspondances(serveur);
            if hits.is_empty() {
                println!("threat intel : no match");
            } else {
                println!("threat intel : {} HIT(S)", hits.len());
                for h in hits { println!("  {} [{}] {}", h.identifiant, h.severite, h.raison); }
            }

            println!();
        }
    }

    // 4. Trust graph
    let g = ConstructeurGraphe::construire(&rapport.clients);
    println!("=== Trust graph ===");
    for c in &g.clients {
        println!("  {} blast_radius={}", c.libelle, c.blast_radius);
    }
    println!("  max = {}", g.indice_max);
}

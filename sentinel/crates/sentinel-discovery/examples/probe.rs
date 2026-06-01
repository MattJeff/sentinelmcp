// Quick host probe — runs every Sentinel discovery source and prints what's on this Mac.
use sentinel_discovery::{OrchestrateurDecouverte, sources::sources_par_defaut};

#[tokio::main]
async fn main() {
    let orch = OrchestrateurDecouverte::default();
    let rapport = orch.balayer().await;
    println!("=== Sentinel MCP — system discovery ===");
    println!("started_at: {}", rapport.demarre_a);
    println!("finished_at: {}", rapport.termine_a);
    println!("clients found: {}\n", rapport.clients.len());
    for c in &rapport.clients {
        let bin = c.binary_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "(no binary)".into());
        let ver = c.version.clone().unwrap_or_else(|| "?".into());
        println!("● {} ({}) v{}", c.libelle, format!("{:?}", c.kind).to_lowercase(), ver);
        println!("    binary : {}", bin);
        for cfg in &c.configs {
            println!("    config : {}", cfg.config_path.display());
        }
        if c.serveurs.is_empty() {
            println!("    servers: (none)");
        } else {
            println!("    servers: {}", c.serveurs.len());
            for s in &c.serveurs {
                let cmd = s.commande.clone().unwrap_or_else(|| "?".into());
                let args = s.args.join(" ");
                let env = if s.env_keys.is_empty() { String::new() } else { format!("  env={:?}", s.env_keys) };
                println!("      - {} [{}]: {} {}{}", s.nom, s.transport, cmd, args, env);
            }
        }
        if !c.notes.is_empty() {
            for n in &c.notes { println!("    note   : {}", n); }
        }
        println!();
    }
}

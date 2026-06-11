//! Binaire `sentinel-guard` — wrapper stdio transparent autour d'un
//! vrai serveur MCP.
//!
//! Usage :
//!     sentinel-guard [--db <chemin>] [--block] -- <commande> [args…]
//!
//! Tout ce qui suit `--` est la commande du vrai serveur MCP. Le garde
//! relaie stdin/stdout sans altération (stderr passthrough), observe
//! les réponses `tools/list`, écrit un constat en cas de dérive par
//! rapport à la baseline approuvée, et — en mode `--block` — remplace
//! une réponse en dérive critique par une erreur JSON-RPC -32000.
//!
//! Fail-open : si le store est indisponible, le relais fonctionne quand
//! même (observation désactivée) — le garde ne casse jamais le client.

use clap::Parser;
use sentinel_guard::db::ouvrir_store;
use sentinel_guard::GardeStdio;

#[derive(Parser)]
#[command(
    name = "sentinel-guard",
    version,
    about = "Sentinel MCP — garde stdio temps réel pour serveurs MCP"
)]
struct Cli {
    /// Chemin de la base SQLite (défaut : base de l'app desktop).
    #[arg(long, value_name = "CHEMIN")]
    db: Option<std::path::PathBuf>,

    /// Bloque les réponses tools/list en cas de dérive critique.
    #[arg(long)]
    block: bool,

    /// Commande du vrai serveur MCP (après `--`).
    #[arg(last = true, required = true, value_name = "COMMANDE")]
    commande: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let programme = cli.commande[0].clone();
    let args = cli.commande[1..].to_vec();

    let store = match ouvrir_store(cli.db.as_deref()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "source": "sentinel-guard",
                    "evenement": "store_indisponible",
                    "detail": e.to_string(),
                })
            );
            None
        }
    };

    let garde = GardeStdio::nouveau(programme, args, store, cli.block);
    match garde.executer().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "source": "sentinel-guard",
                    "evenement": "erreur_fatale",
                    "detail": e.to_string(),
                })
            );
            std::process::exit(1);
        }
    }
}

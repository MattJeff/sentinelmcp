//! sentinel — CLI scriptable de Sentinel MCP.
//!
//! Codes de sortie, partout :
//!   0 = aucun constat
//!   1 = au moins un constat de sévérité haute ou critique
//!   2 = erreur d'exécution

mod cmd_audit;
mod cmd_benchmark;
mod cmd_metrics;
mod cmd_monitor;
mod cmd_report;
mod cmd_scan;
mod db;
mod sortie;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

use sortie::CodeSortie;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Sentinel MCP — découverte, audit statique et surveillance des serveurs MCP"
)]
struct Cli {
    /// Supprime toute sortie standard ; le code de sortie reste la source de vérité.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatRapport {
    Json,
    Pdf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Découverte des clients IA installés + inventaire des serveurs MCP déclarés.
    Scan {
        /// Probe actif opt-in : lance chaque serveur stdio déclaré (handshake
        /// MCP réel + tools/list), empreinte SHA-256 et détection de poisoning.
        #[arg(long)]
        probe: bool,
        /// Chemin de la base SQLite (défaut : la base de l'app desktop).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Sortie JSON machine-readable (inventaire + constats).
        #[arg(long)]
        json: bool,
        /// Force l'activation du moteur YARA local (défaut : activé).
        #[arg(long)]
        yara: bool,
        /// Désactive le moteur YARA local.
        #[arg(long)]
        no_yara: bool,
        /// Active le juge LLM local (Ollama) — opt-in, zéro-cloud (défaut : désactivé).
        #[arg(long)]
        llm: bool,
        /// URL de base de l'API Ollama locale pour le juge LLM.
        #[arg(long, default_value_t = sentinel_detect::OLLAMA_DEFAULT_URL.to_string())]
        llm_url: String,
    },
    /// Audit statique d'un dépôt/dossier : trouve les configs MCP et applique
    /// la détection poisoning/sosies/transport/secrets — conçu pour la CI,
    /// aucun store requis.
    Audit {
        /// Dossier (ou fichier de config) à auditer.
        chemin: PathBuf,
        /// Sortie JSON machine-readable.
        #[arg(long)]
        json: bool,
        /// Force l'activation du moteur YARA local (défaut : activé).
        #[arg(long)]
        yara: bool,
        /// Désactive le moteur YARA local.
        #[arg(long)]
        no_yara: bool,
        /// Active le juge LLM local (Ollama) — opt-in, zéro-cloud (défaut : désactivé).
        #[arg(long)]
        llm: bool,
        /// URL de base de l'API Ollama locale pour le juge LLM.
        #[arg(long, default_value_t = sentinel_detect::OLLAMA_DEFAULT_URL.to_string())]
        llm_url: String,
    },
    /// Surveillance continue : re-balaye la découverte et signale les
    /// nouveaux serveurs. Logs structurés sur stderr.
    Monitor {
        /// Boucle infinie (arrêt propre SIGINT/SIGTERM). Sans ce flag,
        /// une seule itération est exécutée.
        #[arg(long)]
        daemon: bool,
        /// Intervalle entre deux balayages, en secondes.
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Chemin de la base SQLite (défaut : la base de l'app desktop).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Génère le rapport d'évidence via sentinel-report (JSON signé ou PDF).
    Report {
        #[arg(long, value_enum, default_value_t = FormatRapport::Json)]
        format: FormatRapport,
        /// Fichier de destination.
        #[arg(long)]
        output: PathBuf,
        /// Chemin de la base SQLite (défaut : la base de l'app desktop).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Exposition Prometheus des compteurs du store (textfile collector) :
    /// serveurs, outils, constats, alertes et répartitions. stdout scrappable.
    Metrics {
        /// Chemin de la base SQLite (défaut : la base de l'app desktop).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Benchmark public « on a scanné N serveurs » : agrège les registres MCP
    /// publics (ou un échantillon embarqué hors-ligne) et applique la
    /// détection statique sur les métadonnées pour produire des statistiques
    /// réelles (proportion de serveurs avec constat, répartition par
    /// catégorie/sévérité).
    Benchmark {
        /// N'interroge aucun réseau : utilise l'échantillon embarqué
        /// déterministe (source signalée, couverture limitée).
        #[arg(long)]
        offline: bool,
        /// Sortie JSON machine-readable.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs structurés sur stderr — stdout est réservé aux sorties (table/JSON).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let quiet = cli.quiet;

    let resultat: anyhow::Result<CodeSortie> = match cli.cmd {
        Cmd::Scan {
            probe,
            db,
            json,
            yara,
            no_yara,
            llm,
            llm_url,
        } => {
            cmd_scan::executer(cmd_scan::OptionsScan {
                probe,
                db,
                json,
                quiet,
                // `--no-yara` désactive ; `--yara` force ; défaut = activé.
                detection: sortie::config_detection(yara || !no_yara, llm, &llm_url),
            })
            .await
        }
        Cmd::Audit {
            chemin,
            json,
            yara,
            no_yara,
            llm,
            llm_url,
        } => cmd_audit::executer(
            &chemin,
            json,
            quiet,
            &sortie::config_detection(yara || !no_yara, llm, &llm_url),
        ),
        Cmd::Monitor {
            daemon,
            interval,
            db,
        } => cmd_monitor::executer(daemon, interval, db, quiet).await,
        Cmd::Report { format, output, db } => {
            cmd_report::executer(format == FormatRapport::Pdf, &output, db, quiet).await
        }
        Cmd::Metrics { db } => cmd_metrics::executer(db, quiet),
        Cmd::Benchmark { offline, json } => cmd_benchmark::executer(offline, json, quiet).await,
    };

    match resultat {
        Ok(CodeSortie::Aucun) => ExitCode::from(0),
        Ok(CodeSortie::ConstatsCritiques) => ExitCode::from(1),
        Err(e) => {
            eprintln!("erreur: {e:#}");
            ExitCode::from(2)
        }
    }
}

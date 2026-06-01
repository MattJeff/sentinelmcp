use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sentinel", version, about = "Sentinel MCP — découverte et surveillance des serveurs MCP")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Scan,
    Monitor,
    Report,
    Dashboard,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan => sentinel_scan::demo::lancer_demo().await?,
        Cmd::Monitor => {}
        Cmd::Report => {}
        Cmd::Dashboard => {}
    }
    Ok(())
}

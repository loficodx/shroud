use anyhow::{Context, Result};
use args::ServerCommand;
use shroud_core::config::{LoggingConfig, load_server_config_yaml};
use shroud_server::{setup, web};
use std::fs;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod args;

#[tokio::main]
async fn main() -> Result<()> {
    match args::parse()? {
        ServerCommand::Run { config_path } => run_server(config_path).await,
        ServerCommand::GenerateCerts(options) => {
            init_tracing(&LoggingConfig::default());
            let output = setup::run_generate_certs(options)?;
            setup::print_generate_certs_output(&output);
            Ok(())
        }
        ServerCommand::AddClient(options) => {
            init_tracing(&LoggingConfig::default());
            let output = setup::run_add_client(options)?;
            setup::print_add_client_output(&output);
            Ok(())
        }
        ServerCommand::ClientList(options) => {
            init_tracing(&LoggingConfig::default());
            let output = setup::run_client_list(options)?;
            setup::print_client_list_output(&output);
            Ok(())
        }
    }
}

async fn run_server(config_path: PathBuf) -> Result<()> {
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read server config: {}", config_path.display()))?;
    let cfg = load_server_config_yaml(&raw)
        .with_context(|| format!("failed to load server config: {}", config_path.display()))?;
    init_tracing(&LoggingConfig::default());

    info!(
        listen = %cfg.listen,
        modes = ?cfg.transport.modes,
        "starting shroud server"
    );
    web::serve(cfg).await
}

fn init_tracing(logging: &LoggingConfig) {
    let filter = EnvFilter::new(logging.level.trim());
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

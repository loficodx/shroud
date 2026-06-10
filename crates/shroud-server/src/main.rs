use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use shroud_core::config::{LoggingConfig, load_server_config_yaml};
use shroud_server::{setup, web};
use std::fs;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-server -- configs/server.yaml
// curl -i --cacert /home/laptop/Projects/shroud/certs/ca.crt https://localhost:8443/
// curl -X POST -i --cacert /home/laptop/Projects/shroud/certs/ca.crt https://localhost:8443/api/tunnel

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().into_command() {
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
    init_tracing(&cfg.logging);

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

#[derive(Debug, Parser)]
#[command(name = "shroud-server")]
struct Cli {
    #[arg(value_name = "config-path")]
    config_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<ServerSubcommand>,
}

#[derive(Debug)]
enum ServerCommand {
    Run { config_path: PathBuf },
    GenerateCerts(setup::GenerateCertsOptions),
    AddClient(setup::AddClientOptions),
    ClientList(setup::ClientListOptions),
}

#[derive(Debug, Subcommand)]
enum ServerSubcommand {
    GenerateCerts(GenerateCertsArgs),
    AddClient(AddClientArgs),
    #[command(name = "client-list", alias = "list-clients")]
    ClientList(ClientListArgs),
}

#[derive(Debug, clap::Args)]
struct GenerateCertsArgs {
    #[arg(long = "server", value_name = "host-or-ip")]
    server: String,

    #[arg(
        long = "config",
        value_name = "path",
        default_value = "configs/server.yaml"
    )]
    config_path: PathBuf,

    #[arg(long = "cert-dir", value_name = "path", default_value = "certs")]
    cert_dir: PathBuf,

    #[arg(long = "force")]
    force: bool,
}

#[derive(Debug, clap::Args)]
struct AddClientArgs {
    #[arg(long = "name", value_name = "name")]
    name: String,

    #[arg(long = "server", value_name = "host-or-ip")]
    server: String,

    #[arg(long = "port", value_name = "port")]
    port: Option<u16>,

    #[arg(
        long = "config",
        value_name = "path",
        default_value = "configs/server.yaml"
    )]
    config_path: PathBuf,
}

#[derive(Debug, clap::Args)]
struct ClientListArgs {
    #[arg(long = "server", value_name = "host-or-ip")]
    server: String,

    #[arg(long = "port", value_name = "port")]
    port: Option<u16>,

    #[arg(
        long = "config",
        value_name = "path",
        default_value = "configs/server.yaml"
    )]
    config_path: PathBuf,
}

impl Cli {
    fn into_command(self) -> ServerCommand {
        match self.command {
            Some(ServerSubcommand::GenerateCerts(args)) => {
                ServerCommand::GenerateCerts(setup::GenerateCertsOptions {
                    server: Some(args.server),
                    config_path: args.config_path,
                    cert_dir: args.cert_dir,
                    force: args.force,
                })
            }
            Some(ServerSubcommand::AddClient(args)) => {
                ServerCommand::AddClient(setup::AddClientOptions {
                    name: Some(args.name),
                    server: args.server,
                    port: args.port,
                    config_path: args.config_path,
                })
            }
            Some(ServerSubcommand::ClientList(args)) => {
                ServerCommand::ClientList(setup::ClientListOptions {
                    server: args.server,
                    port: args.port,
                    config_path: args.config_path,
                })
            }
            None => ServerCommand::Run {
                config_path: self
                    .config_path
                    .unwrap_or_else(|| PathBuf::from("configs/server.yaml")),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, ServerCommand};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parse_cli_defaults_to_sample_server_config() {
        let command = Cli::try_parse_from(["shroud-server"])
            .expect("parse default config")
            .into_command();

        match command {
            ServerCommand::Run { config_path } => {
                assert_eq!(config_path, PathBuf::from("configs/server.yaml"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_cli_accepts_server_config_path() {
        let command = Cli::try_parse_from(["shroud-server", "custom-server.yaml"])
            .expect("parse custom config")
            .into_command();

        match command {
            ServerCommand::Run { config_path } => {
                assert_eq!(config_path, PathBuf::from("custom-server.yaml"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_cli_accepts_generate_certs_command() {
        let command = Cli::try_parse_from([
            "shroud-server",
            "generate-certs",
            "--server",
            "127.0.0.1",
            "--config",
            "configs/server-lab.yaml",
            "--cert-dir",
            "tmp-certs",
            "--force",
        ])
        .expect("parse generate-certs")
        .into_command();

        match command {
            ServerCommand::GenerateCerts(options) => {
                assert_eq!(options.server.as_deref(), Some("127.0.0.1"));
                assert_eq!(
                    options.config_path,
                    PathBuf::from("configs/server-lab.yaml")
                );
                assert_eq!(options.cert_dir, PathBuf::from("tmp-certs"));
                assert!(options.force);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_cli_accepts_add_client_command() {
        let command = Cli::try_parse_from([
            "shroud-server",
            "add-client",
            "--name",
            "laptop",
            "--server",
            "panel.example.com",
            "--port",
            "9443",
        ])
        .expect("parse add-client")
        .into_command();

        match command {
            ServerCommand::AddClient(options) => {
                assert_eq!(options.name.as_deref(), Some("laptop"));
                assert_eq!(options.server, "panel.example.com");
                assert_eq!(options.port, Some(9443));
                assert_eq!(options.config_path, PathBuf::from("configs/server.yaml"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_cli_accepts_client_list_alias() {
        let command = Cli::try_parse_from([
            "shroud-server",
            "list-clients",
            "--server",
            "panel.example.com",
            "--port",
            "8443",
        ])
        .expect("parse list-clients")
        .into_command();

        match command {
            ServerCommand::ClientList(options) => {
                assert_eq!(options.server, "panel.example.com");
                assert_eq!(options.port, Some(8443));
                assert_eq!(options.config_path, PathBuf::from("configs/server.yaml"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}

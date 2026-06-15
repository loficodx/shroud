use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use shroud_client::{routing, session, socks5, transport, tun};
use shroud_core::config::{LoggingConfig, TransportEndpointConfig, load_client_config_yaml};
use shroud_core::import::{decode_import_connection, render_client_yaml_from_import};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let command = Cli::parse().into_command()?;
    match command {
        ClientCommand::Run {
            config_path,
            log_format,
        } => run_client(config_path, log_format).await,
        ClientCommand::Import(options) => {
            init_tracing(LogFormat::Plain, &LoggingConfig::default());
            run_import_command(options)?;
            Ok(())
        }
    }
}

async fn run_client(config_path: PathBuf, log_format: LogFormat) -> Result<()> {
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {}", config_path.display()))?;
    let cfg = load_client_config_yaml(&raw)
        .with_context(|| format!("failed to load client config: {}", config_path.display()))?;
    init_tracing(log_format, &cfg.logging);
    info!(
        mode = ?cfg.transport.mode,
        server = %cfg.transport.server,
        port = cfg.transport.port,
        tls = cfg.transport.tls,
        "selected TCP transport mode"
    );

    let mut endpoint = TransportEndpointConfig::from(&cfg.transport);
    if cfg.inbounds.tun.enabled && cfg.inbounds.tun.auto_route {
        endpoint = tun::route::prepare_auto_route_outbound(endpoint)?;
    }

    let router = routing::Router::try_new(cfg.routing.clone()).context("invalid routing config")?;

    if cfg.inbounds.tun.enabled {
        let tcp_transport = transport::build_tcp_transport(
            cfg.transport.mode,
            endpoint.clone(),
            cfg.auth.clone(),
            cfg.timeouts,
        )
        .context("failed to build TCP transport")?;
        let session = session::SessionCore::new(
            router,
            tcp_transport,
            cfg.dns.clone(),
            cfg.timeouts,
            cfg.relay,
        );
        let device = tun::device::open(&cfg.inbounds.tun)
            .with_context(|| format!("failed to set up TUN device {}", cfg.inbounds.tun.name))?;
        info!(
            tun = device.name(),
            address = %cfg.inbounds.tun.address,
            mtu = cfg.inbounds.tun.mtu,
            auto_route = cfg.inbounds.tun.auto_route,
            "TUN device opened; starting smoltcp-backed packet engine"
        );
        let _route_guard =
            tun::route::setup_before_packet_engine(device.name(), &cfg.inbounds.tun, &endpoint)?;
        let fake_dns = tun::dns::FakeDns::new();
        let fake_dns_addr = tun::dns::listen_addr(&cfg.inbounds.tun);
        info!(
            listen = %fake_dns_addr,
            "starting TUN fake DNS listener"
        );
        tokio::spawn(tun::dns::serve(fake_dns_addr, fake_dns.clone()));

        info!(tun = device.name(), "starting TUN packet engine");
        return tun::engine::TunEngine::new(
            device,
            session,
            fake_dns,
            cfg.inbounds.tun.mtu,
            cfg.limits.max_concurrent_connections,
        )
        .run()
        .await;
    }

    let socks = cfg
        .inbounds
        .socks
        .as_ref()
        .filter(|socks| socks.enabled)
        .context("no enabled SOCKS inbound configured")?;

    info!(listen = %socks.listen, "starting shroud client");

    let tcp_transport = transport::build_tcp_transport(
        cfg.transport.mode,
        endpoint.clone(),
        cfg.auth.clone(),
        cfg.timeouts,
    )
    .context("failed to build TCP transport")?;
    let session = session::SessionCore::new(
        router,
        tcp_transport,
        cfg.dns.clone(),
        cfg.timeouts,
        cfg.relay,
    );

    socks5::serve(socks.listen, session, cfg.limits.max_concurrent_connections).await
}

fn init_tracing(log_format: LogFormat, logging: &LoggingConfig) {
    let filter = EnvFilter::new(logging.level.trim());
    match log_format {
        LogFormat::Plain => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}

#[derive(Debug, Parser)]
#[command(name = "shroud-client")]
struct Cli {
    #[arg(value_name = "config-path")]
    config_path: Option<PathBuf>,

    #[arg(
        short = 'c',
        long = "config",
        value_name = "path",
        conflicts_with = "config_path"
    )]
    config: Option<PathBuf>,

    #[arg(long = "log-format", value_enum, default_value = "plain")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Option<ClientSubcommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientCommand {
    Run {
        config_path: PathBuf,
        log_format: LogFormat,
    },
    Import(ImportOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportOptions {
    raw: String,
    output: Option<PathBuf>,
    force: bool,
}

#[derive(Debug, Subcommand)]
enum ClientSubcommand {
    Import(ImportArgs),
}

#[derive(Debug, clap::Args)]
struct ImportArgs {
    #[arg(value_name = "shrd:1:...")]
    raw: String,

    #[arg(short = 'o', long = "output", value_name = "path")]
    output: Option<PathBuf>,

    #[arg(long = "force")]
    force: bool,
}

impl Cli {
    fn into_command(self) -> Result<ClientCommand> {
        match self.command {
            Some(ClientSubcommand::Import(args)) => Ok(ClientCommand::Import(ImportOptions {
                raw: args.raw,
                output: args.output,
                force: args.force,
            })),
            None => Ok(ClientCommand::Run {
                config_path: self
                    .config
                    .or(self.config_path)
                    .unwrap_or_else(|| PathBuf::from("configs/client.yaml")),
                log_format: self.log_format,
            }),
        }
    }
}

fn run_import_command(options: ImportOptions) -> Result<()> {
    let conn = decode_import_connection(&options.raw)?;
    let default_file_name_source = conn
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&conn.server);
    let output_path = options.output.unwrap_or_else(|| {
        PathBuf::from(default_import_output_path(Some(default_file_name_source)))
    });
    let yaml = render_client_yaml_from_import(conn)?;
    create_parent_dir(&output_path)?;

    if options.force {
        fs::write(&output_path, yaml)
            .with_context(|| format!("failed to write client config: {}", output_path.display()))?;
    } else {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .with_context(|| {
                format!(
                    "failed to create client config: {}. Use --force to overwrite",
                    output_path.display()
                )
            })?;
        file.write_all(yaml.as_bytes())
            .with_context(|| format!("failed to write client config: {}", output_path.display()))?;
    }

    println!("Client config written: {}", output_path.display());
    Ok(())
}

fn create_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    Ok(())
}

fn default_import_output_path(name: Option<&str>) -> String {
    format!(
        "client-{}.yaml",
        sanitize_profile_name(name.unwrap_or("import"))
    )
}

fn sanitize_profile_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if (ch == '-' || ch == '_') && !out.is_empty() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "import".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, ClientCommand, ImportOptions, LogFormat, default_import_output_path,
        run_import_command,
    };
    use clap::Parser;
    use shroud_core::config::{TransportMode, load_client_config_yaml};
    use shroud_core::import::{ImportConnection, encode_import_connection};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parse_cli_defaults_to_sample_client_config() {
        let config_path = Cli::try_parse_from(["shroud-client"])
            .expect("parse default config")
            .into_command()
            .expect("build command");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_config_path() {
        let config_path = Cli::try_parse_from(["shroud-client", "custom-client.yaml"])
            .expect("parse custom config")
            .into_command()
            .expect("build command");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: PathBuf::from("custom-client.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_explicit_config_path() {
        let command =
            Cli::try_parse_from(["shroud-client", "--config", "configs/client-laptop.yaml"])
                .expect("parse --config")
                .into_command()
                .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client-laptop.yaml"),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_log_format() {
        let command = Cli::try_parse_from([
            "shroud-client",
            "--config",
            "configs/client-laptop.yaml",
            "--log-format",
            "json",
        ])
        .expect("parse --log-format")
        .into_command()
        .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: PathBuf::from("configs/client-laptop.yaml"),
                log_format: LogFormat::Json,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_import_command() {
        let command = Cli::try_parse_from([
            "shroud-client",
            "import",
            "shrd:1:test",
            "--output",
            "configs/client-laptop.yaml",
            "--force",
        ])
        .expect("parse import command")
        .into_command()
        .expect("build command");

        assert_eq!(
            command,
            ClientCommand::Import(ImportOptions {
                raw: "shrd:1:test".to_string(),
                output: Some(PathBuf::from("configs/client-laptop.yaml")),
                force: true,
            })
        );
    }

    #[test]
    fn import_output_path_uses_profile_name() {
        assert_eq!(
            default_import_output_path(Some("Work Laptop")),
            "client-work-laptop.yaml"
        );
        assert_eq!(
            default_import_output_path(Some("!!!")),
            "client-import.yaml"
        );
    }

    #[test]
    fn import_command_writes_valid_client_config_without_overwriting_by_default() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).expect("create temp dir");
        let output_path = dir.join("client-laptop.yaml");
        let raw = encode_import_connection(&ImportConnection {
            name: Some("laptop".to_string()),
            server: "127.0.0.1".to_string(),
            port: 8443,
            mode: TransportMode::RawTcp,
            tls: true,
            tls_server_name: Some("localhost".to_string()),
            tls_server_cert_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            client_id: "c1ce8312-7c35-4e70-867a-3af4ac7f68d7".to_string(),
            client_secret: "secret".to_string(),
        })
        .expect("encode import string");

        run_import_command(ImportOptions {
            raw: raw.clone(),
            output: Some(output_path.clone()),
            force: false,
        })
        .expect("import config");

        let yaml = fs::read_to_string(&output_path).expect("read imported config");
        let config = load_client_config_yaml(&yaml).expect("generated config is valid");
        assert_eq!(config.transport.server, "127.0.0.1");
        assert_eq!(config.auth.client_secret, "secret");

        let err = run_import_command(ImportOptions {
            raw,
            output: Some(output_path.clone()),
            force: false,
        })
        .expect_err("reject overwrite");
        assert!(err.to_string().contains("Use --force to overwrite"));

        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "shroud-client-import-test-{}-{now}",
            std::process::id()
        ))
    }
}

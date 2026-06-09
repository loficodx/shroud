use anyhow::{Context, Result, bail};
use shroud_client::{routing, session, socks5, transport, tun};
use shroud_core::config::load_client_config_yaml;
use shroud_core::import::{decode_import_connection, render_client_yaml_from_import};
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

// cargo run -p shroud-client -- configs/client.yaml

//DNS remote resolve
// curl --socks5-hostname 127.0.0.1:1080 https://example.com

//DNS leak
//curl -v --socks5 127.0.0.1:1080 https://example.com/

//TUN TEST
// cd /home/laptop/Projects/shroud
// sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh

//TUN TEST BUILD
// cd /home/laptop/Projects/shroud
// cargo build -p shroud-client -p shroud-server
// sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh
#[tokio::main]
async fn main() -> Result<()> {
    let command = parse_cli()?;
    match command {
        ClientCommand::Run {
            config_path,
            log_format,
        } => {
            init_tracing(log_format);
            run_client(config_path).await
        }
        ClientCommand::Import(options) => {
            init_tracing(LogFormat::Plain);
            run_import_command(options)?;
            Ok(())
        }
    }
}

async fn run_client(config_path: String) -> Result<()> {
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read client config: {config_path}"))?;
    let cfg = load_client_config_yaml(&raw)
        .with_context(|| format!("failed to load client config: {config_path}"))?;
    for warning in cfg.transport_compat_warnings() {
        warn!(warning = %warning, "deprecated client transport config");
    }
    info!(
        mode = ?cfg.transport.mode,
        server = %cfg.transport.server,
        port = cfg.transport.port,
        tls = cfg.transport.tls,
        "selected TCP transport mode"
    );

    let mut outbound = cfg.outbound.clone();
    if cfg.inbounds.tun.enabled && cfg.inbounds.tun.auto_route {
        outbound = tun::route::prepare_auto_route_outbound(outbound)?;
    }

    let router = routing::Router::try_new(cfg.routing.clone()).context("invalid routing config")?;

    if cfg.inbounds.tun.enabled {
        let tcp_transport = transport::build_tcp_transport(
            cfg.transport.mode,
            outbound.clone(),
            cfg.auth.clone(),
            cfg.timeouts,
        )
        .context("failed to build TCP transport")?;
        let session = session::SessionCore::new(router, tcp_transport, cfg.dns.clone(), cfg.relay);
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
            tun::route::setup_before_packet_engine(device.name(), &cfg.inbounds.tun, &outbound)?;
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
        outbound.clone(),
        cfg.auth.clone(),
        cfg.timeouts,
    )
    .context("failed to build TCP transport")?;
    let session = session::SessionCore::new(router, tcp_transport, cfg.dns.clone(), cfg.relay);

    socks5::serve(socks.listen, session, cfg.limits.max_concurrent_connections).await
}

fn init_tracing(log_format: LogFormat) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    match log_format {
        LogFormat::Plain => tracing_subscriber::fmt().with_env_filter(env_filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init(),
    }
}

fn parse_cli() -> Result<ClientCommand> {
    parse_cli_args(std::env::args().skip(1))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientCommand {
    Run {
        config_path: String,
        log_format: LogFormat,
    },
    Import(ImportOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportOptions {
    raw: String,
    output: Option<String>,
    force: bool,
}

fn parse_cli_args<I, S>(args: I) -> Result<ClientCommand>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter();
    let first = args.next();
    let first = first.map(Into::into);
    if matches!(
        first.as_deref(),
        Some("generate-credentials") | Some("gen-credentials")
    ) {
        bail!(
            "Credential generation moved to shroud-server provisioning.\nRun: shroud-server generate-certs --server <host>\nThen: shroud-server add-client --name <name> --server <host>"
        );
    }

    if matches!(first.as_deref(), Some("import")) {
        return parse_import_args(args.map(Into::into));
    }

    parse_run_args(first.into_iter().chain(args.map(Into::into)))
}

fn parse_run_args(args: impl Iterator<Item = String>) -> Result<ClientCommand> {
    let mut config_path = None;
    let mut log_format = LogFormat::Plain;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                set_config_path(&mut config_path, next_arg(&mut args, "--config")?)?
            }
            "--log-format" => log_format = parse_log_format(&next_arg(&mut args, "--log-format")?)?,
            "--help" | "-h" => bail!(
                "Usage: shroud-client [--config <path>] [--log-format plain|json]\n       shroud-client <config-path>\n       shroud-client import <shrd:1:...> [--output <path>] [--force]"
            ),
            unknown if unknown.starts_with('-') => bail!("unknown client option: {unknown}"),
            value => set_config_path(&mut config_path, value.to_string())?,
        }
    }

    Ok(ClientCommand::Run {
        config_path: config_path.unwrap_or_else(|| "configs/client.yaml".to_string()),
        log_format,
    })
}

fn set_config_path(config_path: &mut Option<String>, value: String) -> Result<()> {
    if config_path.replace(value).is_some() {
        bail!("client accepts only one config path");
    }
    Ok(())
}

fn parse_log_format(value: &str) -> Result<LogFormat> {
    match value {
        "plain" => Ok(LogFormat::Plain),
        "json" => Ok(LogFormat::Json),
        _ => bail!("unsupported log format: {value}. Expected plain or json"),
    }
}

fn parse_import_args(mut args: impl Iterator<Item = String>) -> Result<ClientCommand> {
    let mut raw = None;
    let mut output = None;
    let mut force = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" | "-o" => output = Some(next_arg(&mut args, "--output")?),
            "--force" => force = true,
            "--help" | "-h" => {
                bail!("Usage: shroud-client import <shrd:1:...> [--output <path>] [--force]")
            }
            unknown if unknown.starts_with('-') => bail!("unknown import option: {unknown}"),
            value => {
                if raw.replace(value.to_string()).is_some() {
                    bail!("import accepts exactly one import string");
                }
            }
        }
    }

    Ok(ClientCommand::Import(ImportOptions {
        raw: raw.ok_or_else(|| {
            anyhow::anyhow!(
                "import requires an import string.\nUsage: shroud-client import <shrd:1:...> [--output <path>] [--force]"
            )
        })?,
        output,
        force,
    }))
}

fn next_arg(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{option} requires a value"))
}

fn run_import_command(options: ImportOptions) -> Result<()> {
    let conn = decode_import_connection(&options.raw)?;
    let default_file_name_source = conn
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&conn.server);
    let output_path = options
        .output
        .unwrap_or_else(|| default_import_output_path(Some(default_file_name_source)));
    let yaml = render_client_yaml_from_import(conn)?;
    create_parent_dir(Path::new(&output_path))?;

    if options.force {
        fs::write(&output_path, yaml)
            .with_context(|| format!("failed to write client config: {output_path}"))?;
    } else {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .with_context(|| {
                format!("failed to create client config: {output_path}. Use --force to overwrite")
            })?;
        file.write_all(yaml.as_bytes())
            .with_context(|| format!("failed to write client config: {output_path}"))?;
    }

    println!("Client config written: {output_path}");
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
        ClientCommand, ImportOptions, LogFormat, default_import_output_path, parse_cli_args,
        run_import_command,
    };
    use shroud_core::config::{TransportMode, load_client_config_yaml};
    use shroud_core::import::{ImportConnection, encode_import_connection};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parse_cli_defaults_to_sample_client_config() {
        let config_path = parse_cli_args(std::iter::empty::<&str>()).expect("parse default config");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: "configs/client.yaml".to_string(),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_config_path() {
        let config_path = parse_cli_args(["custom-client.yaml"]).expect("parse custom config");

        assert_eq!(
            config_path,
            ClientCommand::Run {
                config_path: "custom-client.yaml".to_string(),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_explicit_config_path() {
        let command =
            parse_cli_args(["--config", "configs/client-laptop.yaml"]).expect("parse --config");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: "configs/client-laptop.yaml".to_string(),
                log_format: LogFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_log_format() {
        let command = parse_cli_args([
            "--config",
            "configs/client-laptop.yaml",
            "--log-format",
            "json",
        ])
        .expect("parse --log-format");

        assert_eq!(
            command,
            ClientCommand::Run {
                config_path: "configs/client-laptop.yaml".to_string(),
                log_format: LogFormat::Json,
            }
        );
    }

    #[test]
    fn parse_cli_accepts_import_command() {
        let command = parse_cli_args([
            "import",
            "shrd:1:test",
            "--output",
            "configs/client-laptop.yaml",
            "--force",
        ])
        .expect("parse import command");

        assert_eq!(
            command,
            ClientCommand::Import(ImportOptions {
                raw: "shrd:1:test".to_string(),
                output: Some("configs/client-laptop.yaml".to_string()),
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
            output: Some(output_path.to_string_lossy().into_owned()),
            force: false,
        })
        .expect("import config");

        let yaml = fs::read_to_string(&output_path).expect("read imported config");
        let config = load_client_config_yaml(&yaml).expect("generated config is valid");
        assert_eq!(config.transport.server, "127.0.0.1");
        assert_eq!(config.auth.client_secret, "secret");

        let err = run_import_command(ImportOptions {
            raw,
            output: Some(output_path.to_string_lossy().into_owned()),
            force: false,
        })
        .expect_err("reject overwrite");
        assert!(err.to_string().contains("Use --force to overwrite"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_cli_rejects_generate_credentials_command() {
        let err = parse_cli_args(["generate-credentials"]).expect_err("command must fail");

        assert_eq!(
            err.to_string(),
            "Credential generation moved to shroud-server provisioning.\nRun: shroud-server generate-certs --server <host>\nThen: shroud-server add-client --name <name> --server <host>"
        );
    }

    #[test]
    fn parse_cli_rejects_gen_credentials_alias() {
        let err = parse_cli_args(["gen-credentials"]).expect_err("alias must fail");

        assert_eq!(
            err.to_string(),
            "Credential generation moved to shroud-server provisioning.\nRun: shroud-server generate-certs --server <host>\nThen: shroud-server add-client --name <name> --server <host>"
        );
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

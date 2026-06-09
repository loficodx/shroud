use anyhow::{Context, Result, anyhow, bail};
use shroud_core::config::{generate_client_credentials, load_server_config_yaml};
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
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let Some(config_path) = parse_cli()? else {
        return Ok(());
    };
    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read server config: {config_path}"))?;
    let cfg = load_server_config_yaml(&raw)
        .with_context(|| format!("failed to load server config: {config_path}"))?;

    info!(
        listen = %cfg.listen,
        modes = ?cfg.transport.modes,
        "starting shroud server"
    );
    web::serve(cfg).await
}

fn parse_cli() -> Result<Option<String>> {
    let mut args = std::env::args().skip(1);
    let first = args.next();

    match first.as_deref() {
        Some("generate-certs") => {
            let rest = args.collect::<Vec<_>>();
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                print_generate_certs_usage();
                return Ok(None);
            }
            let options = parse_generate_certs_args(rest.into_iter())?;
            let output = setup::run_generate_certs(options)?;
            setup::print_generate_certs_output(&output);
            Ok(None)
        }
        Some("add-client") => {
            let rest = args.collect::<Vec<_>>();
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                print_add_client_usage();
                return Ok(None);
            }
            let options = parse_add_client_args(rest.into_iter())?;
            let output = setup::run_add_client(options)?;
            setup::print_add_client_output(&output);
            Ok(None)
        }
        Some("client-list") | Some("list-clients") => {
            let rest = args.collect::<Vec<_>>();
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                print_client_list_usage();
                return Ok(None);
            }
            let options = parse_client_list_args(rest.into_iter())?;
            let output = setup::run_client_list(options)?;
            setup::print_client_list_output(&output);
            Ok(None)
        }
        Some("setup") | Some("init") => {
            let rest = args.collect::<Vec<_>>();
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                print_setup_usage();
                return Ok(None);
            }
            let options = parse_setup_args(rest.into_iter())?;
            let output = setup::run_setup(options)?;
            setup::print_client_snippet(&output);
            Ok(None)
        }
        Some("generate-credentials") | Some("gen-credentials") => {
            let credentials = generate_client_credentials();
            println!("client_id: \"{}\"", credentials.client_id);
            println!("client_secret: \"{}\"", credentials.client_secret);
            Ok(None)
        }
        _ => Ok(Some(
            first.unwrap_or_else(|| "configs/server.yaml".to_string()),
        )),
    }
}

fn parse_setup_args(mut args: impl Iterator<Item = String>) -> Result<setup::SetupOptions> {
    let mut server = None;
    let mut port = None;
    let mut name = None;
    let mut config_path = PathBuf::from("configs/server.yaml");
    let mut cert_dir = PathBuf::from("certs");
    let mut force_certs = false;
    let mut force_client = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = Some(next_arg(&mut args, "--server")?),
            "--name" => name = Some(next_arg(&mut args, "--name")?),
            "--port" => {
                let raw = next_arg(&mut args, "--port")?;
                port = Some(
                    raw.parse::<u16>()
                        .with_context(|| format!("invalid --port value: {raw}"))?,
                );
            }
            "--config" => config_path = PathBuf::from(next_arg(&mut args, "--config")?),
            "--cert-dir" => cert_dir = PathBuf::from(next_arg(&mut args, "--cert-dir")?),
            "--force-certs" => force_certs = true,
            "--force-client" => force_client = true,
            unknown => bail!("unknown setup option: {unknown}"),
        }
    }

    Ok(setup::SetupOptions {
        server: server.ok_or_else(|| anyhow!("setup requires --server <host-or-ip>"))?,
        port: port.ok_or_else(|| anyhow!("setup requires --port <port>"))?,
        name,
        config_path,
        cert_dir,
        force_certs,
        force_client,
    })
}

fn parse_generate_certs_args(
    mut args: impl Iterator<Item = String>,
) -> Result<setup::GenerateCertsOptions> {
    let mut server = None;
    let mut config_path = PathBuf::from("configs/server.yaml");
    let mut cert_dir = PathBuf::from("certs");
    let mut force = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = Some(next_arg(&mut args, "--server")?),
            "--config" => config_path = PathBuf::from(next_arg(&mut args, "--config")?),
            "--cert-dir" => cert_dir = PathBuf::from(next_arg(&mut args, "--cert-dir")?),
            "--force" => force = true,
            unknown => bail!("unknown generate-certs option: {unknown}"),
        }
    }

    Ok(setup::GenerateCertsOptions {
        server,
        config_path,
        cert_dir,
        force,
    })
}

fn parse_add_client_args(
    mut args: impl Iterator<Item = String>,
) -> Result<setup::AddClientOptions> {
    let mut name = None;
    let mut server = None;
    let mut port = None;
    let mut config_path = PathBuf::from("configs/server.yaml");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = Some(next_arg(&mut args, "--name")?),
            "--server" => server = Some(next_arg(&mut args, "--server")?),
            "--port" => {
                let raw = next_arg(&mut args, "--port")?;
                port = Some(
                    raw.parse::<u16>()
                        .with_context(|| format!("invalid --port value: {raw}"))?,
                );
            }
            "--config" => config_path = PathBuf::from(next_arg(&mut args, "--config")?),
            unknown => bail!("unknown add-client option: {unknown}"),
        }
    }

    Ok(setup::AddClientOptions {
        name: Some(name.ok_or_else(|| anyhow!("add-client requires --name <name>"))?),
        server: server.ok_or_else(|| anyhow!("add-client requires --server <host-or-ip>"))?,
        port,
        config_path,
    })
}

fn parse_client_list_args(
    mut args: impl Iterator<Item = String>,
) -> Result<setup::ClientListOptions> {
    let mut server = None;
    let mut port = None;
    let mut config_path = PathBuf::from("configs/server.yaml");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = Some(next_arg(&mut args, "--server")?),
            "--port" => {
                let raw = next_arg(&mut args, "--port")?;
                port = Some(
                    raw.parse::<u16>()
                        .with_context(|| format!("invalid --port value: {raw}"))?,
                );
            }
            "--config" => config_path = PathBuf::from(next_arg(&mut args, "--config")?),
            unknown => bail!("unknown client-list option: {unknown}"),
        }
    }

    Ok(setup::ClientListOptions {
        server: server.ok_or_else(|| anyhow!("client-list requires --server <host-or-ip>"))?,
        port,
        config_path,
    })
}

fn next_arg(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow!("{option} requires a value"))
}

fn print_setup_usage() {
    println!("Usage:");
    println!("  shroud-server setup --server <host-or-ip> --port <port> [options]");
    println!();
    println!("Options:");
    println!("  --name <name>      Client display name stored in server.yaml");
    println!("  --config <path>    Server config path (default: configs/server.yaml)");
    println!("  --cert-dir <path>  Certificate directory (default: certs)");
    println!("  --force-certs      Regenerate server.crt and server.key");
    println!("  --force-client     Generate a new authorized client");
}

fn print_generate_certs_usage() {
    println!("Usage:");
    println!("  shroud-server generate-certs --server <host-or-ip> [options]");
    println!();
    println!("Options:");
    println!("  --config <path>    Server config path (default: configs/server.yaml)");
    println!("  --cert-dir <path>  Certificate directory (default: certs)");
    println!("  --force            Regenerate server.crt and server.key");
}

fn print_add_client_usage() {
    println!("Usage:");
    println!("  shroud-server add-client --name <name> --server <host-or-ip> [options]");
    println!();
    println!("Options:");
    println!("  --port <port>      Public server port (default: server.yaml listen port)");
    println!("  --config <path>    Server config path (default: configs/server.yaml)");
}

fn print_client_list_usage() {
    println!("Usage:");
    println!("  shroud-server client-list --server <host-or-ip> [options]");
    println!();
    println!("Options:");
    println!("  --port <port>      Public server port (default: server.yaml listen port)");
    println!("  --config <path>    Server config path (default: configs/server.yaml)");
}

use anyhow::{Context, Result};
use args::{ClientCommand, ImportOptions, LogFormat};
use shroud_core::config::LoggingConfig;
use shroud_core::fs_util::create_parent_dir;
use shroud_core::import::{
    decode_import_connection, default_client_import_file_name, render_client_yaml_from_import,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod args;
mod cfg;
mod inbound;
mod runtime;

#[tokio::main]
async fn main() -> Result<()> {
    let command = args::parse()?;
    match command {
        ClientCommand::Run {
            config_path,
            log_format,
        } => run_client(config_path, log_format).await,
        ClientCommand::Import(options) => {
            run_import_command(options)?;
            Ok(())
        }
    }
}

async fn run_client(config_path: PathBuf, log_format: LogFormat) -> Result<()> {
    let cfg = cfg::load_client_config(&config_path)?;
    init_tracing(log_format, &cfg.logging);

    info!(
        mode = ?cfg.transport.mode,
        server = %cfg.transport.server,
        port = cfg.transport.port,
        tls = cfg.transport.tls,
        "selected TCP transport mode"
    );

    if cfg.inbounds.tun.enabled {
        inbound::tun::run(cfg).await
    } else {
        inbound::socks::run(cfg).await
    }
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

fn run_import_command(options: ImportOptions) -> Result<()> {
    let conn = decode_import_connection(&options.raw)?;
    let default_file_name_source = conn
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&conn.server);
    let output_path = options.output.unwrap_or_else(|| {
        PathBuf::from(default_client_import_file_name(Some(
            default_file_name_source,
        )))
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

#[cfg(test)]
mod tests {
    use super::{ImportOptions, run_import_command};
    use shroud_core::config::{TransportMode, load_client_config_yaml};
    use shroud_core::import::{ImportConnection, encode_import_connection};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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

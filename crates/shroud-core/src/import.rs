use crate::config::{
    ClientAuthConfig, ClientConfig, ClientDnsConfig, ClientInboundsConfig, LimitsConfig,
    LoggingConfig, RelayConfig, RoutingConfig, SocksInboundConfig, TimeoutsConfig, TransportConfig,
    TransportMode, TunInboundConfig,
};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const IMPORT_PREFIX: &str = "shrd:1:";
const IMPORT_SCHEME_PREFIX: &str = "shrd:";
const IMPORT_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportConnection {
    pub name: Option<String>,
    pub server: String,
    pub port: u16,
    pub mode: TransportMode,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub tls_server_cert_sha256: String,
    pub client_id: String,
    pub client_secret: String,
}

pub fn encode_import_connection(conn: &ImportConnection) -> Result<String> {
    let json = serde_json::to_vec(conn).context("failed to serialize import connection")?;
    Ok(format!("{IMPORT_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

pub fn decode_import_connection(raw: &str) -> Result<ImportConnection> {
    let body = raw
        .trim()
        .strip_prefix(IMPORT_SCHEME_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("invalid import string prefix, expected shrd:1:"))?;
    let (version, encoded) = body
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid import string prefix, expected shrd:1:"))?;
    if version != IMPORT_VERSION {
        if version.parse::<u64>().is_ok() {
            anyhow::bail!("unsupported import version: {version}");
        }
        anyhow::bail!("invalid import string prefix, expected shrd:1:");
    }

    let json = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("failed to decode import payload")?;
    serde_json::from_slice(&json).context("failed to parse import payload")
}

pub fn client_config_from_import(conn: ImportConnection) -> ClientConfig {
    ClientConfig::default_for_import(conn)
}

pub fn render_client_yaml_from_import(conn: ImportConnection) -> Result<String> {
    let yaml = ImportClientYaml::from(conn);
    serde_yaml::to_string(&yaml).context("failed to render client config yaml")
}

#[derive(Debug, Serialize)]
struct ImportClientYaml {
    inbounds: ClientInboundsConfig,
    transport: TransportConfig,
    auth: ClientAuthConfig,
    timeouts: TimeoutsConfig,
    relay: RelayConfig,
    limits: LimitsConfig,
    routing: RoutingConfig,
    dns: ClientDnsConfig,
    logging: LoggingConfig,
}

impl From<ImportConnection> for ImportClientYaml {
    fn from(conn: ImportConnection) -> Self {
        Self {
            inbounds: ClientInboundsConfig {
                socks: Some(SocksInboundConfig {
                    enabled: true,
                    listen: SocketAddr::from(([127, 0, 0, 1], 1080)),
                }),
                tun: TunInboundConfig::default(),
            },
            transport: TransportConfig {
                mode: conn.mode,
                server: conn.server,
                port: conn.port,
                tls: conn.tls,
                tls_server_name: conn.tls_server_name,
                tls_ca_cert_path: None,
                tls_server_cert_sha256: Some(conn.tls_server_cert_sha256),
                path: None,
            },
            auth: ClientAuthConfig {
                client_id: conn.client_id,
                client_secret: conn.client_secret,
            },
            timeouts: TimeoutsConfig::default(),
            relay: RelayConfig::default(),
            limits: LimitsConfig::default(),
            routing: RoutingConfig::default(),
            dns: ClientDnsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_client_config_yaml, validate_client_config};

    fn sample_import() -> ImportConnection {
        ImportConnection {
            name: Some("laptop".to_string()),
            server: "138.124.55.220".to_string(),
            port: 8443,
            mode: TransportMode::RawTcp,
            tls: true,
            tls_server_name: Some("138.124.55.220".to_string()),
            tls_server_cert_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            client_id: "c1ce8312-7c35-4e70-867a-3af4ac7f68d7".to_string(),
            client_secret: "secret".to_string(),
        }
    }

    #[test]
    fn import_string_round_trips() {
        let conn = sample_import();

        let encoded = encode_import_connection(&conn).expect("encode import");
        let decoded = decode_import_connection(&encoded).expect("decode import");

        assert!(encoded.starts_with("shrd:1:"));
        assert_eq!(decoded, conn);
    }

    #[test]
    fn rejects_invalid_import_prefix() {
        let err = decode_import_connection("not-shrd:1:abc").expect_err("reject prefix");

        assert!(
            err.to_string()
                .contains("invalid import string prefix, expected shrd:1:")
        );
    }

    #[test]
    fn rejects_unsupported_import_version() {
        let err = decode_import_connection("shrd:2:abc").expect_err("reject version");

        assert!(err.to_string().contains("unsupported import version: 2"));
    }

    #[test]
    fn rejects_broken_import_base64() {
        let err = decode_import_connection("shrd:1:%%%").expect_err("reject base64");

        assert!(err.to_string().contains("failed to decode import payload"));
    }

    #[test]
    fn rejects_broken_import_json() {
        let encoded = format!("shrd:1:{}", URL_SAFE_NO_PAD.encode(b"not-json"));
        let err = decode_import_connection(&encoded).expect_err("reject json");

        assert!(err.to_string().contains("failed to parse import payload"));
    }

    #[test]
    fn builds_valid_client_config_from_import() {
        let config = client_config_from_import(sample_import());

        validate_client_config(&config).expect("valid generated config");
        assert_eq!(config.transport.server, "138.124.55.220");
        assert_eq!(config.transport.port, 8443);
        assert_eq!(
            config.transport.tls_server_name.as_deref(),
            Some("138.124.55.220")
        );
        assert_eq!(
            config.transport.tls_server_cert_sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            config.auth.client_id,
            "c1ce8312-7c35-4e70-867a-3af4ac7f68d7"
        );
        assert_eq!(config.auth.client_secret, "secret");
        let socks = config
            .inbounds
            .socks
            .as_ref()
            .expect("default socks inbound");
        assert!(socks.enabled);
        assert_eq!(socks.listen.to_string(), "127.0.0.1:1080");
        assert!(!config.inbounds.tun.enabled);
    }

    #[test]
    fn renders_valid_client_yaml_from_import() {
        let yaml = render_client_yaml_from_import(sample_import()).expect("render yaml");

        assert!(yaml.contains("transport:\n"));
        assert!(yaml.contains("server: 138.124.55.220\n"));
        load_client_config_yaml(&yaml).expect("generated yaml is valid");
    }
}

use anyhow::{Context, Result, anyhow, bail};
use rcgen::CertifiedKey;
use sha2::{Digest, Sha256};
use shroud_core::config::{
    AuthorizedClient, ServerConfig, ServerSecurityConfig, ServerTlsConfig, TimeoutsConfig,
    generate_client_credentials,
};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub server: String,
    pub port: u16,
    pub config_path: PathBuf,
    pub cert_dir: PathBuf,
    pub force_certs: bool,
    pub force_client: bool,
}

#[derive(Debug, Clone)]
pub struct SetupOutput {
    pub server: String,
    pub port: u16,
    pub config_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub cert_sha256: String,
    pub client_id: String,
    pub client_secret: String,
}

struct GeneratedServerCert {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
}

pub fn run_setup(options: SetupOptions) -> Result<SetupOutput> {
    if options.server.trim().is_empty() {
        bail!("--server must not be empty");
    }
    if options.port == 0 {
        bail!("--port must be greater than 0");
    }

    let target_cert_path = options.cert_dir.join("server.crt");
    let target_key_path = options.cert_dir.join("server.key");

    let mut config = read_or_create_server_config(&options)?;
    let mut config_changed = false;
    ensure_listen_port(&mut config, options.port, &mut config_changed);

    let (cert_path, key_path) = effective_cert_paths(
        &mut config,
        &target_cert_path,
        &target_key_path,
        options.force_certs,
        &mut config_changed,
    );

    let cert_der =
        ensure_server_certificate(&options.server, &cert_path, &key_path, options.force_certs)?;
    let cert_sha256 = fingerprint_sha256_hex(&cert_der);

    let client = ensure_authorized_client(&mut config, options.force_client, &mut config_changed);

    if config_changed || !options.config_path.exists() {
        write_server_config(&options.config_path, &config)?;
    }

    Ok(SetupOutput {
        server: options.server,
        port: options.port,
        config_path: options.config_path,
        server_cert_path: cert_path,
        server_key_path: key_path,
        cert_sha256,
        client_id: client.client_id,
        client_secret: client.client_secret,
    })
}

pub fn print_client_snippet(output: &SetupOutput) {
    println!("Shroud server setup complete.");
    println!();
    println!("Generated or reused:");
    println!("  server config: {}", output.config_path.display());
    println!("  server cert:   {}", output.server_cert_path.display());
    println!("  server key:    {}", output.server_key_path.display());
    println!();
    println!("Use this client config:");
    println!();
    println!("transport:");
    println!("  mode: raw_tcp");
    println!("  server: \"{}\"", output.server);
    println!("  port: {}", output.port);
    println!("  tls: true");
    println!("  tls_server_name: \"{}\"", output.server);
    println!("  tls_server_cert_sha256: \"{}\"", output.cert_sha256);
    println!();
    println!("auth:");
    println!("  client_id: \"{}\"", output.client_id);
    println!("  client_secret: \"{}\"", output.client_secret);
}

fn read_or_create_server_config(options: &SetupOptions) -> Result<ServerConfig> {
    if options.config_path.exists() {
        let raw = fs::read_to_string(&options.config_path).with_context(|| {
            format!(
                "failed to read server config {}",
                options.config_path.display()
            )
        })?;
        serde_yaml::from_str(&raw).with_context(|| {
            format!(
                "failed to parse server config {}",
                options.config_path.display()
            )
        })
    } else {
        Ok(default_server_config(options.port))
    }
}

fn default_server_config(port: u16) -> ServerConfig {
    ServerConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        tunnel_path: "/api/tunnel".to_string(),
        web_root: "./web".to_string(),
        transport: Default::default(),
        tls: ServerTlsConfig::default(),
        timeouts: TimeoutsConfig::default(),
        relay: Default::default(),
        limits: Default::default(),
        security: ServerSecurityConfig::default(),
        clients: Vec::new(),
    }
}

fn ensure_listen_port(config: &mut ServerConfig, port: u16, config_changed: &mut bool) {
    if config.listen.port() != port {
        config.listen.set_port(port);
        *config_changed = true;
    }
}

fn effective_cert_paths(
    config: &mut ServerConfig,
    target_cert_path: &Path,
    target_key_path: &Path,
    force_certs: bool,
    config_changed: &mut bool,
) -> (PathBuf, PathBuf) {
    let existing_cert = non_empty_path(config.tls.cert_path.as_deref());
    let existing_key = non_empty_path(config.tls.key_path.as_deref());

    let use_existing_paths = existing_cert.is_some() && existing_key.is_some() && !force_certs;
    let cert_path = existing_cert
        .filter(|_| use_existing_paths)
        .unwrap_or_else(|| target_cert_path.to_path_buf());
    let key_path = existing_key
        .filter(|_| use_existing_paths)
        .unwrap_or_else(|| target_key_path.to_path_buf());

    let cert_path_string = path_to_config_string(&cert_path);
    let key_path_string = path_to_config_string(&key_path);
    if !config.tls.enabled {
        config.tls.enabled = true;
        *config_changed = true;
    }
    if config.tls.cert_path.as_deref() != Some(cert_path_string.as_str()) {
        config.tls.cert_path = Some(cert_path_string);
        *config_changed = true;
    }
    if config.tls.key_path.as_deref() != Some(key_path_string.as_str()) {
        config.tls.key_path = Some(key_path_string);
        *config_changed = true;
    }

    (cert_path, key_path)
}

fn non_empty_path(value: Option<&str>) -> Option<PathBuf> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn path_to_config_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn ensure_server_certificate(
    server: &str,
    cert_path: &Path,
    key_path: &Path,
    force_certs: bool,
) -> Result<Vec<u8>> {
    if !force_certs && cert_path.exists() && key_path.exists() {
        return read_first_cert_der(cert_path);
    }

    let generated = generate_self_signed_server_cert(server)?;
    write_cert_pair(cert_path, key_path, &generated)?;
    Ok(generated.cert_der)
}

fn generate_self_signed_server_cert(server: &str) -> Result<GeneratedServerCert> {
    let mut subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if server != "localhost" && server != "127.0.0.1" {
        subject_alt_names.push(server.to_string());
    }

    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("failed to generate self-signed server certificate")?;

    Ok(GeneratedServerCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der: cert.der().to_vec(),
    })
}

fn write_cert_pair(
    cert_path: &Path,
    key_path: &Path,
    generated: &GeneratedServerCert,
) -> Result<()> {
    create_parent_dir(cert_path)?;
    create_parent_dir(key_path)?;
    fs::write(cert_path, &generated.cert_pem)
        .with_context(|| format!("failed to write server certificate {}", cert_path.display()))?;
    fs::write(key_path, &generated.key_pem)
        .with_context(|| format!("failed to write server private key {}", key_path.display()))?;
    chmod_public_cert(cert_path)?;
    chmod_private_key(key_path)?;
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

fn read_first_cert_der(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open server certificate {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| {
            anyhow!(
                "server certificate {} does not contain certificates",
                path.display()
            )
        })?
        .with_context(|| format!("failed to read server certificate {}", path.display()))
        .map(|cert| cert.as_ref().to_vec())
}

pub fn fingerprint_sha256_hex(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn ensure_authorized_client(
    config: &mut ServerConfig,
    force_client: bool,
    config_changed: &mut bool,
) -> AuthorizedClient {
    if !force_client {
        if let Some(client) = config.clients.first() {
            return client.clone();
        }
    }

    let credentials = generate_client_credentials();
    let client = AuthorizedClient {
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
    };

    if force_client {
        config.clients = vec![client.clone()];
    } else {
        config.clients.push(client.clone());
    }
    *config_changed = true;
    client
}

fn write_server_config(path: &Path, config: &ServerConfig) -> Result<()> {
    create_parent_dir(path)?;
    let raw = serde_yaml::to_string(config).context("failed to serialize server config")?;
    fs::write(path, raw)
        .with_context(|| format!("failed to write server config {}", path.display()))
}

#[cfg(unix)]
fn chmod_private_key(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_private_key(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn chmod_public_cert(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_public_cert(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn cert_fingerprint_is_64_char_hex() {
        let fp = fingerprint_sha256_hex(b"test der");

        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn setup_creates_server_config_cert_pair_and_client() {
        let dir = unique_temp_dir();
        let config_path = dir.join("configs/server.yaml");
        let cert_dir = dir.join("certs");

        let output = run_setup(SetupOptions {
            server: "127.0.0.1".to_string(),
            port: 8443,
            config_path: config_path.clone(),
            cert_dir: cert_dir.clone(),
            force_certs: false,
            force_client: false,
        })
        .expect("setup succeeds");

        assert!(config_path.is_file());
        assert!(output.server_cert_path.is_file());
        assert!(output.server_key_path.is_file());
        assert_eq!(output.cert_sha256.len(), 64);

        let raw = fs::read_to_string(&config_path).expect("read generated config");
        let config: ServerConfig = serde_yaml::from_str(&raw).expect("parse generated config");
        assert!(config.tls.enabled);
        assert_eq!(
            config.tls.cert_path.as_deref(),
            Some(cert_dir.join("server.crt").to_string_lossy().as_ref())
        );
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].client_id, output.client_id);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn setup_reuses_existing_client_and_updates_listen_port() {
        let dir = unique_temp_dir();
        let config_path = dir.join("server.yaml");
        let cert_dir = dir.join("certs");
        let cert_path = cert_dir.join("server.crt");
        let key_path = cert_dir.join("server.key");
        let cert_path_string = cert_path.to_string_lossy();
        let key_path_string = key_path.to_string_lossy();
        fs::create_dir_all(&cert_dir).expect("create cert dir");
        fs::write(
            &config_path,
            format!(
                r#"
listen: "127.0.0.1:9443"
tunnel_path: "/api/tunnel"
web_root: "./web"
transport:
  modes:
    - raw_tcp
tls:
  enabled: true
  cert_path: "{cert_path_string}"
  key_path: "{key_path_string}"
clients:
  - client_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "existing-secret"
"#
            ),
        )
        .expect("write existing config");

        let output = run_setup(SetupOptions {
            server: "localhost".to_string(),
            port: 8443,
            config_path: config_path.clone(),
            cert_dir,
            force_certs: false,
            force_client: false,
        })
        .expect("setup succeeds");

        let raw = fs::read_to_string(&config_path).expect("read updated config");
        let config: ServerConfig = serde_yaml::from_str(&raw).expect("parse updated config");

        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].client_id, output.client_id);
        assert_eq!(output.client_secret, "existing-secret");

        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("shroud-setup-test-{}-{now}", std::process::id()))
    }
}

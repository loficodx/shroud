use anyhow::{Context, Result, anyhow, bail};
use shroud_core::config::ServerTlsConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub(crate) fn build_tls_acceptor(tls: &ServerTlsConfig) -> Result<Option<TlsAcceptor>> {
    if !tls.enabled {
        return Ok(None);
    }

    let cert_path = tls
        .cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("server tls.enabled=true requires tls.cert_path"))?;
    let key_path = tls
        .key_path
        .as_deref()
        .ok_or_else(|| anyhow!("server tls.enabled=true requires tls.key_path"))?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build tls server config")?;

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certificates from {path}"))?;
    if certs.is_empty() {
        bail!("certificate file {path} does not contain certificates");
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("failed to open private key file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to read private key from {path}"))?
        .ok_or_else(|| anyhow!("private key file {path} does not contain a supported key"))
}

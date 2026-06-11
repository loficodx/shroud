use anyhow::{Context, Result, anyhow, bail};
use shroud_core::config::ServerTlsConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsAlpn {
    None,
    Http2,
}

pub(crate) fn build_tls_acceptor_with_alpn(
    tls: &ServerTlsConfig,
    alpn: TlsAlpn,
) -> Result<Option<TlsAcceptor>> {
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
    let config = apply_alpn(config, alpn);

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

fn apply_alpn(mut config: RustlsServerConfig, alpn: TlsAlpn) -> RustlsServerConfig {
    config.alpn_protocols = match alpn {
        TlsAlpn::None => Vec::new(),
        TlsAlpn::Http2 => vec![b"h2".to_vec()],
    };
    config
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_http2_alpn_sets_h2_protocol() {
        let config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
            ));
        let config = apply_alpn(config, TlsAlpn::Http2);

        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn disabled_tls_acceptor_stays_disabled_with_http2_alpn() {
        let tls = ServerTlsConfig::default();

        assert!(
            build_tls_acceptor_with_alpn(&tls, TlsAlpn::Http2)
                .unwrap()
                .is_none()
        );
    }
}

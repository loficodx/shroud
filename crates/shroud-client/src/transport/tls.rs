use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use shroud_core::config::TransportEndpointConfig;
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, OtherError,
    RootCertStore, SignatureScheme,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsAlpn {
    None,
    #[allow(dead_code)]
    Http2,
}

pub(crate) fn build_tls_client_config(outbound: &TransportEndpointConfig) -> Result<ClientConfig> {
    build_tls_client_config_with_alpn(outbound, TlsAlpn::None)
}

#[allow(dead_code)]
pub(crate) fn build_http2_tls_client_config(
    outbound: &TransportEndpointConfig,
) -> Result<ClientConfig> {
    build_tls_client_config_with_alpn(outbound, TlsAlpn::Http2)
}

pub(crate) fn build_tls_client_config_with_alpn(
    outbound: &TransportEndpointConfig,
    alpn: TlsAlpn,
) -> Result<ClientConfig> {
    let config = if let Some(pin) = &outbound.tls_server_cert_sha256 {
        build_pinned_tls_client_config(pin)?
    } else {
        build_root_store_tls_client_config(outbound)?
    };

    Ok(apply_alpn(config, alpn))
}

fn apply_alpn(mut config: ClientConfig, alpn: TlsAlpn) -> ClientConfig {
    config.alpn_protocols = match alpn {
        TlsAlpn::None => Vec::new(),
        TlsAlpn::Http2 => vec![b"h2".to_vec()],
    };
    config
}

fn build_root_store_tls_client_config(outbound: &TransportEndpointConfig) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = &outbound.tls_ca_cert_path {
        let certs = load_certs(path)?;
        let (_added, ignored) = root_store.add_parsable_certificates(certs);
        if ignored > 0 {
            bail!("ignored {ignored} invalid certificate(s) from tls_ca_cert_path={path}");
        }
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

fn build_pinned_tls_client_config(pin: &str) -> Result<ClientConfig> {
    let expected_sha256 = decode_sha256_hex(pin)?;
    let signature_verifier = build_webpki_signature_verifier()?;

    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier {
            expected_sha256,
            signature_verifier,
        }))
        .with_no_client_auth())
}

fn build_webpki_signature_verifier() -> Result<Arc<WebPkiServerVerifier>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .context("failed to build webpki signature verifier")
}

fn decode_sha256_hex(pin: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(pin.trim()).context("invalid tls_server_cert_sha256 hex")?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("tls_server_cert_sha256 must decode to 32 bytes"))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certificates from {path}"))
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    expected_sha256: [u8; 32],
    signature_verifier: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatch)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

struct PinMismatch;

impl fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server certificate sha256 pin mismatch")
    }
}

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("server certificate sha256 pin mismatch")
    }
}

impl StdError for PinMismatch {}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound_config() -> TransportEndpointConfig {
        TransportEndpointConfig {
            server: "localhost".to_string(),
            port: 443,
            tls: true,
            ..TransportEndpointConfig::default()
        }
    }

    #[test]
    fn default_tls_config_does_not_advertise_alpn() {
        let config = build_tls_client_config(&outbound_config()).unwrap();

        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn http2_tls_config_advertises_h2_alpn() {
        let config = build_http2_tls_client_config(&outbound_config()).unwrap();

        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }
}

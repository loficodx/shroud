use anyhow::{Context, Result, bail};
use shroud_core::config::OutboundConfig;
use std::fs::File;
use std::io::BufReader;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

pub(crate) fn build_tls_client_config(outbound: &OutboundConfig) -> Result<ClientConfig> {
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

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read certificates from {path}"))
}

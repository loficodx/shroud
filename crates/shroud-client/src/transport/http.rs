use crate::transport::BoxedIo;
use crate::transport::tls::build_tls_client_config;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use shroud_core::auth::compute_auth_tag;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::debug;

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const TUNNEL_ENDPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_UPGRADE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct LegacyHttpTransport {
    pub stream: BoxedIo,
}

pub(crate) async fn open_legacy_http_upgrade_transport(
    outbound: &OutboundConfig,
    auth: &ClientAuthConfig,
    target_host: &str,
    target_port: u16,
) -> Result<LegacyHttpTransport> {
    let server_connect_started = Instant::now();
    let stream = timeout(
        TUNNEL_ENDPOINT_CONNECT_TIMEOUT,
        TcpStream::connect((outbound.server.as_str(), outbound.port)),
    )
    .await
    .with_context(|| {
        format!(
            "timed out connecting to tunnel endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?
    .with_context(|| {
        format!(
            "failed to connect to tunnel endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;
    let server_tcp_connect_ms = elapsed_millis(server_connect_started.elapsed());
    debug!(
        server = %outbound.server,
        port = outbound.port,
        target_host,
        target_port,
        server_tcp_connect_ms,
        "tunnel server TCP connect finished"
    );

    stream.set_nodelay(true).with_context(|| {
        format!(
            "failed to enable TCP_NODELAY for tunnel endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;

    let mut stream: BoxedIo = if outbound.tls {
        let tls_started = Instant::now();
        let connector = TlsConnector::from(Arc::new(build_tls_client_config(outbound)?));
        let server_name = outbound
            .tls_server_name
            .as_deref()
            .unwrap_or(&outbound.server)
            .to_owned();
        let server_name = ServerName::try_from(server_name)
            .map_err(|err| anyhow!("invalid tls server name: {err}"))?;
        let tls_stream = timeout(
            TUNNEL_ENDPOINT_CONNECT_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        .with_context(|| {
            format!(
                "timed out establishing tls connection to {}:{}",
                outbound.server, outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to establish tls connection to {}:{}",
                outbound.server, outbound.port
            )
        })?;
        let elapsed_ms = elapsed_millis(tls_started.elapsed());
        debug!(
            server = %outbound.server,
            port = outbound.port,
            target_host,
            target_port,
            tls_handshake_ms = elapsed_ms,
            "tunnel TLS handshake finished"
        );
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs() as i64;

    let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
    let auth_tag = compute_auth_tag(
        auth.client_secret.as_bytes(),
        &nonce,
        timestamp,
        &auth.client_id,
    )
    .context("failed to compute auth tag")?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: Upgrade\r\nUpgrade: shroud-tunnel\r\nX-Shroud-Client-Id: {client_id}\r\nX-Shroud-Timestamp: {timestamp}\r\nX-Shroud-Nonce: {nonce}\r\nX-Shroud-Auth: {auth}\r\n\r\n",
        path = outbound.path,
        host = outbound.server,
        port = outbound.port,
        client_id = auth.client_id,
        timestamp = timestamp,
        nonce = STANDARD_NO_PAD.encode(&nonce),
        auth = auth_tag,
    );
    let http_upgrade_started = Instant::now();
    stream.write_all(request.as_bytes()).await?;

    let response = timeout(
        HTTP_UPGRADE_RESPONSE_TIMEOUT,
        read_http_headers(&mut stream),
    )
    .await
    .context("timed out waiting for HTTP upgrade response")??;
    let status = parse_status_code(&response).context("failed to parse tunnel response")?;
    let http_upgrade_ms = elapsed_millis(http_upgrade_started.elapsed());

    if status != 101 {
        bail!("tunnel endpoint rejected upgrade with HTTP status {status}");
    }

    debug!(
        server = %outbound.server,
        tunnel_path = %outbound.path,
        client_id = %auth.client_id,
        target_host,
        target_port,
        http_upgrade_ms,
        "tunnel upgrade accepted"
    );

    Ok(LegacyHttpTransport { stream })
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

async fn read_http_headers<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut data = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    while data.len() < MAX_HTTP_HEADERS {
        stream.read_exact(&mut byte).await?;
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            return Ok(data);
        }
    }

    bail!("http headers are too large");
}

fn parse_status_code(raw_headers: &[u8]) -> Result<u16> {
    let headers = std::str::from_utf8(raw_headers).context("http headers are not valid utf-8")?;
    let status_line = headers
        .split("\r\n")
        .next()
        .ok_or_else(|| anyhow!("empty HTTP response"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version in response"))?;
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP status code in response"))?;
    code.parse::<u16>()
        .context("HTTP status code is not a valid integer")
}

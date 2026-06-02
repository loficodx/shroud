use crate::transport::tls::build_tls_client_config;
use crate::transport::{BoxedIo, TcpTransport, TcpTransportConnect, TcpTransportMetrics};
use crate::tunnel::TunnelClient;
use anyhow::{Context, Result, anyhow, bail};
use futures_util::future::BoxFuture;
use shroud_core::auth::compute_auth_tag_bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::tcp_handshake::{
    ClientAuthProof, TcpConnectRequest, TcpConnectStatus, read_fast_connect_status,
    write_fast_connect_request,
};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::debug;

const FAST_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FAST_TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct FastTcpTransport {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
}

impl FastTcpTransport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self { outbound, auth }
    }

    pub fn from_tunnel(tunnel: TunnelClient) -> Self {
        let (outbound, auth) = tunnel.transport_parts();
        Self { outbound, auth }
    }
}

impl TcpTransport for FastTcpTransport {
    fn connect<'a>(
        &'a self,
        target_host: &'a str,
        target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move {
            connect_fast_tcp(&self.outbound, &self.auth, target_host, target_port).await
        })
    }
}

pub async fn connect_fast_tcp(
    outbound: &OutboundConfig,
    auth: &ClientAuthConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpTransportConnect> {
    let server_connect_started = Instant::now();
    let stream = timeout(
        FAST_TCP_CONNECT_TIMEOUT,
        TcpStream::connect((outbound.server.as_str(), outbound.port)),
    )
    .await
    .with_context(|| {
        format!(
            "timed out connecting to fast_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?
    .with_context(|| {
        format!(
            "failed to connect to fast_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;
    let server_tcp_connect_ms = elapsed_millis(server_connect_started.elapsed());

    stream.set_nodelay(true).with_context(|| {
        format!(
            "failed to enable TCP_NODELAY for fast_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;

    let mut tls_handshake_ms = None;
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
            FAST_TCP_CONNECT_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        .with_context(|| {
            format!(
                "timed out establishing tls connection to fast_tcp endpoint {}:{}",
                outbound.server, outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to establish tls connection to fast_tcp endpoint {}:{}",
                outbound.server, outbound.port
            )
        })?;
        let elapsed_ms = elapsed_millis(tls_started.elapsed());
        tls_handshake_ms = Some(elapsed_ms);
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    let req = TcpConnectRequest::new(target_host, target_port, build_auth_proof(auth)?);
    let target_connect_started = Instant::now();
    timeout(
        FAST_TCP_HANDSHAKE_TIMEOUT,
        write_fast_connect_request(&mut stream, &req),
    )
    .await
    .context("timed out writing fast_tcp connect request")?
    .context("failed to write fast_tcp connect request")?;

    let status = timeout(
        FAST_TCP_HANDSHAKE_TIMEOUT,
        read_fast_connect_status(&mut stream),
    )
    .await
    .context("timed out waiting for fast_tcp connect status")?
    .context("failed to read fast_tcp connect status")?;
    let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
    if status != TcpConnectStatus::Ok {
        bail!("fast_tcp connect rejected: {status}");
    }

    debug!(
        server = %outbound.server,
        port = outbound.port,
        target_host,
        target_port,
        server_tcp_connect_ms,
        tls_handshake_ms,
        target_tcp_connect_ms,
        "fast_tcp connect accepted"
    );

    Ok(TcpTransportConnect {
        stream,
        metrics: TcpTransportMetrics {
            server_tcp_connect_ms: Some(server_tcp_connect_ms),
            tls_handshake_ms,
            http_upgrade_ms: None,
            target_tcp_connect_ms,
        },
    })
}

fn build_auth_proof(auth: &ClientAuthConfig) -> Result<ClientAuthProof> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs() as i64;
    let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
    let auth_tag = compute_auth_tag_bytes(
        auth.client_secret.as_bytes(),
        &nonce,
        timestamp,
        &auth.client_id,
    )
    .context("failed to compute fast_tcp auth tag")?;

    Ok(ClientAuthProof::new(
        auth.client_id.clone(),
        timestamp,
        nonce,
        auth_tag,
    ))
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::auth::compute_auth_tag_bytes;
    use shroud_core::tcp_handshake::{read_fast_connect_request, write_fast_connect_status};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const CLIENT_SECRET: &str = "test-secret";

    fn auth_config() -> ClientAuthConfig {
        ClientAuthConfig {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        }
    }

    fn outbound_config(port: u16) -> OutboundConfig {
        OutboundConfig {
            server: "127.0.0.1".to_string(),
            port,
            tls: false,
            ..OutboundConfig::default()
        }
    }

    #[tokio::test]
    async fn returns_raw_stream_after_ok_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let req = read_fast_connect_request(&mut socket).await.unwrap();
            assert_eq!(req.host, "example.com");
            assert_eq!(req.port, 443);
            assert_eq!(req.auth.client_id, CLIENT_ID);
            let expected_tag = compute_auth_tag_bytes(
                CLIENT_SECRET.as_bytes(),
                &req.auth.nonce,
                req.auth.timestamp,
                CLIENT_ID,
            )
            .unwrap();
            assert_eq!(req.auth.auth_tag, expected_tag);

            write_fast_connect_status(&mut socket, TcpConnectStatus::Ok)
                .await
                .unwrap();

            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.unwrap();
        });

        let mut connected =
            connect_fast_tcp(&outbound_config(port), &auth_config(), "example.com", 443)
                .await
                .unwrap();
        assert!(connected.metrics.server_tcp_connect_ms.is_some());
        assert!(connected.metrics.http_upgrade_ms.is_none());
        connected.stream.write_all(b"ping").await.unwrap();

        let mut buf = [0u8; 4];
        connected.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_non_ok_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _req = read_fast_connect_request(&mut socket).await.unwrap();
            write_fast_connect_status(&mut socket, TcpConnectStatus::AuthFailed)
                .await
                .unwrap();
        });

        let err = match connect_fast_tcp(&outbound_config(port), &auth_config(), "example.com", 443)
            .await
        {
            Ok(_) => panic!("fast_tcp connect unexpectedly succeeded"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("auth_failed"));

        server.await.unwrap();
    }
}

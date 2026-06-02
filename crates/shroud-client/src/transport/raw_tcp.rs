use crate::transport::tls::build_tls_client_config;
use crate::transport::{BoxedIo, TcpTransport, TcpTransportConnect, TcpTransportMetrics};
use anyhow::{Context, Result, anyhow, bail};
use futures_util::future::BoxFuture;
use shroud_core::auth::compute_auth_tag_bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig, TimeoutsConfig};
use shroud_core::tcp_handshake::{
    ClientAuthProof, TcpConnectRequest, TcpConnectStatus, read_raw_tcp_connect_status,
    write_raw_tcp_connect_request,
};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

#[derive(Clone)]
pub struct RawTcpTransport {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
    tls: Option<RawTcpTls>,
    timeouts: RawTcpClientTimeouts,
}

#[derive(Clone)]
struct RawTcpTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

#[derive(Clone, Copy)]
struct RawTcpClientTimeouts {
    server_connect: Duration,
    tls_handshake: Duration,
    raw_tcp_handshake: Duration,
}

impl RawTcpTransport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        Self::with_timeouts(outbound, auth, TimeoutsConfig::default())
    }

    pub fn with_timeouts(
        outbound: OutboundConfig,
        auth: ClientAuthConfig,
        timeouts: TimeoutsConfig,
    ) -> Result<Self> {
        let tls = if outbound.tls {
            Some(RawTcpTls::new(&outbound)?)
        } else {
            None
        };
        let timeouts = RawTcpClientTimeouts::from(timeouts);

        Ok(Self {
            outbound,
            auth,
            tls,
            timeouts,
        })
    }

    async fn open_tcp(&self, target_host: &str, target_port: u16) -> Result<TcpTransportConnect> {
        connect_raw_tcp_with_cached_tls(
            &self.outbound,
            &self.auth,
            self.tls.as_ref(),
            self.timeouts,
            target_host,
            target_port,
        )
        .await
    }
}

impl RawTcpTls {
    fn new(outbound: &OutboundConfig) -> Result<Self> {
        let connector = TlsConnector::from(Arc::new(build_tls_client_config(outbound)?));
        let server_name = outbound
            .tls_server_name
            .as_deref()
            .unwrap_or(&outbound.server)
            .to_owned();
        let server_name = ServerName::try_from(server_name)
            .map_err(|err| anyhow!("invalid tls server name: {err}"))?;

        Ok(Self {
            connector,
            server_name,
        })
    }
}

impl From<TimeoutsConfig> for RawTcpClientTimeouts {
    fn from(timeouts: TimeoutsConfig) -> Self {
        Self {
            server_connect: Duration::from_millis(timeouts.server_connect_ms),
            tls_handshake: Duration::from_millis(timeouts.tls_handshake_ms),
            raw_tcp_handshake: Duration::from_millis(timeouts.raw_tcp_handshake_ms),
        }
    }
}

impl TcpTransport for RawTcpTransport {
    fn connect<'a>(
        &'a self,
        target_host: &'a str,
        target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move { self.open_tcp(target_host, target_port).await })
    }
}

pub async fn connect_raw_tcp(
    outbound: &OutboundConfig,
    auth: &ClientAuthConfig,
    target_host: &str,
    target_port: u16,
) -> Result<TcpTransportConnect> {
    let transport = RawTcpTransport::new(outbound.clone(), auth.clone())?;
    transport.open_tcp(target_host, target_port).await
}

async fn connect_raw_tcp_with_cached_tls(
    outbound: &OutboundConfig,
    auth: &ClientAuthConfig,
    tls: Option<&RawTcpTls>,
    timeouts: RawTcpClientTimeouts,
    target_host: &str,
    target_port: u16,
) -> Result<TcpTransportConnect> {
    let server_connect_started = Instant::now();
    let stream = timeout(
        timeouts.server_connect,
        TcpStream::connect((outbound.server.as_str(), outbound.port)),
    )
    .await
    .with_context(|| {
        format!(
            "timed out connecting to raw_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?
    .with_context(|| {
        format!(
            "failed to connect to raw_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;
    let server_tcp_connect_ms = elapsed_millis(server_connect_started.elapsed());

    stream.set_nodelay(true).with_context(|| {
        format!(
            "failed to enable TCP_NODELAY for raw_tcp endpoint {}:{}",
            outbound.server, outbound.port
        )
    })?;

    let mut tls_handshake_ms = None;
    let mut stream: BoxedIo = if let Some(tls) = tls {
        let tls_started = Instant::now();
        let tls_stream = timeout(
            timeouts.tls_handshake,
            tls.connector.connect(tls.server_name.clone(), stream),
        )
        .await
        .with_context(|| {
            format!(
                "timed out establishing tls connection to raw_tcp endpoint {}:{}",
                outbound.server, outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to establish tls connection to raw_tcp endpoint {}:{}",
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
    let raw_tcp_handshake_started = Instant::now();
    timeout(
        timeouts.raw_tcp_handshake,
        write_raw_tcp_connect_request(&mut stream, &req),
    )
    .await
    .context("timed out writing raw_tcp connect request")?
    .context("failed to write raw_tcp connect request")?;

    let status = timeout(
        timeouts.raw_tcp_handshake,
        read_raw_tcp_connect_status(&mut stream),
    )
    .await
    .context("timed out waiting for raw_tcp connect status")?
    .context("failed to read raw_tcp connect status")?;
    let raw_tcp_handshake_ms = elapsed_millis(raw_tcp_handshake_started.elapsed());
    if status != TcpConnectStatus::Ok {
        bail!("raw_tcp connect rejected: {status}");
    }

    Ok(TcpTransportConnect {
        stream,
        metrics: TcpTransportMetrics {
            server_tcp_connect_ms: Some(server_tcp_connect_ms),
            tls_handshake_ms,
            raw_tcp_handshake_ms: Some(raw_tcp_handshake_ms),
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
    .context("failed to compute raw_tcp auth tag")?;

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
    use shroud_core::tcp_handshake::{read_raw_tcp_connect_request, write_raw_tcp_connect_status};
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

    #[test]
    fn builds_tls_state_at_transport_construction() {
        let mut outbound = outbound_config(443);
        outbound.server = "localhost".to_string();
        outbound.tls = true;

        let transport = RawTcpTransport::new(outbound, auth_config()).unwrap();

        assert!(transport.tls.is_some());
    }

    #[test]
    fn validates_tls_config_at_transport_construction() {
        let mut outbound = outbound_config(443);
        outbound.tls = true;
        outbound.tls_ca_cert_path = Some(format!(
            "/tmp/shroud-missing-ca-{}.pem",
            uuid::Uuid::new_v4()
        ));

        let err = match RawTcpTransport::new(outbound, auth_config()) {
            Ok(_) => panic!("raw_tcp transport unexpectedly accepted missing CA file"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to open certificate file"));
    }

    #[tokio::test]
    async fn returns_raw_stream_after_ok_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let req = read_raw_tcp_connect_request(&mut socket).await.unwrap();
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

            write_raw_tcp_connect_status(&mut socket, TcpConnectStatus::Ok)
                .await
                .unwrap();

            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.unwrap();
        });

        let mut connected =
            connect_raw_tcp(&outbound_config(port), &auth_config(), "example.com", 443)
                .await
                .unwrap();
        assert!(connected.metrics.server_tcp_connect_ms.is_some());
        assert!(connected.metrics.raw_tcp_handshake_ms.is_some());
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
            let _req = read_raw_tcp_connect_request(&mut socket).await.unwrap();
            write_raw_tcp_connect_status(&mut socket, TcpConnectStatus::AuthFailed)
                .await
                .unwrap();
        });

        let err = match connect_raw_tcp(&outbound_config(port), &auth_config(), "example.com", 443)
            .await
        {
            Ok(_) => panic!("raw_tcp connect unexpectedly succeeded"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("auth_failed"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn times_out_waiting_for_raw_tcp_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _req = read_raw_tcp_connect_request(&mut socket).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let transport = RawTcpTransport::with_timeouts(
            outbound_config(port),
            auth_config(),
            TimeoutsConfig {
                raw_tcp_handshake_ms: 10,
                ..TimeoutsConfig::default()
            },
        )
        .unwrap();

        let err = match transport.open_tcp("example.com", 443).await {
            Ok(_) => panic!("raw_tcp connect unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("timed out waiting for raw_tcp connect status")
        );
        server.await.unwrap();
    }
}

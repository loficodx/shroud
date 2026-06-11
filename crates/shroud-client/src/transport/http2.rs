use crate::transport::tls::build_http2_tls_client_config;
use crate::transport::{TcpTransport, TcpTransportConnect, TcpTransportMetrics};
use anyhow::{Context as AnyhowContext, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::{Buf, Bytes};
use futures_util::future::BoxFuture;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Version};
use shroud_core::auth::compute_auth_tag_bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig, TimeoutsConfig};
use shroud_core::http2_protocol::{
    DEFAULT_TUNNEL_PATH, HEADER_AUTH, HEADER_CLIENT_ID, HEADER_NONCE, HEADER_TARGET_HOST,
    HEADER_TARGET_PORT, HEADER_TIMESTAMP, LEGACY_TUNNEL_PATH,
};
use std::io;
use std::net::Ipv6Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, warn};

const MAX_H2_DATA_CHUNK: usize = 16 * 1024;

#[derive(Clone)]
pub struct Http2Transport {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
    tls: Http2Tls,
    timeouts: Http2ClientTimeouts,
    shared: Arc<Mutex<Option<Http2SharedConnection>>>,
}

#[derive(Clone)]
struct Http2Tls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

#[derive(Clone)]
struct Http2SharedConnection {
    sender: SendRequest<Bytes>,
}

#[derive(Clone, Copy)]
struct Http2ClientTimeouts {
    server_connect: Duration,
    tls_handshake: Duration,
    h2_handshake: Duration,
    response_headers: Duration,
}

struct Http2Connection {
    sender: SendRequest<Bytes>,
    metrics: TcpTransportMetrics,
}

struct Http2OpenStream {
    stream: H2StreamIo,
}

enum OpenStreamError {
    Retryable(anyhow::Error),
    Fatal(anyhow::Error),
}

pub struct H2StreamIo {
    send: SendStream<Bytes>,
    recv: RecvStream,
    read_buf: Bytes,
    write_capacity_requested: bool,
    send_closed: bool,
}

impl Http2Transport {
    pub fn with_timeouts(
        outbound: OutboundConfig,
        auth: ClientAuthConfig,
        timeouts: TimeoutsConfig,
    ) -> Result<Self> {
        if !outbound.tls {
            bail!("http2 transport requires tls=true");
        }

        let tls = Http2Tls::new(&outbound)?;
        let timeouts = Http2ClientTimeouts::from(timeouts);

        Ok(Self {
            outbound,
            auth,
            tls,
            timeouts,
            shared: Arc::new(Mutex::new(None)),
        })
    }

    async fn open_tcp(&self, target_host: &str, target_port: u16) -> Result<TcpTransportConnect> {
        debug!(target_host, target_port, "opening HTTP/2 stream to target");

        let mut last_retryable = None;
        for attempt in 0..2 {
            let (mut sender, metrics) = self.get_or_open_connection().await?;
            match self
                .open_stream_once(&mut sender, target_host, target_port)
                .await
            {
                Ok(opened) => {
                    debug!(
                        target_host,
                        target_port, "HTTP/2 stream established to target"
                    );
                    return Ok(TcpTransportConnect {
                        stream: Box::new(opened.stream),
                        metrics,
                    });
                }
                Err(OpenStreamError::Fatal(err)) => return Err(err),
                Err(OpenStreamError::Retryable(err)) => {
                    warn!(
                        target_host,
                        target_port,
                        attempt,
                        error = %err,
                        "HTTP/2 stream failed; resetting shared connection"
                    );
                    self.clear_connection().await;
                    last_retryable = Some(err);
                }
            }
        }

        Err(last_retryable.unwrap_or_else(|| anyhow!("HTTP/2 stream open failed")))
    }

    async fn get_or_open_connection(&self) -> Result<(SendRequest<Bytes>, TcpTransportMetrics)> {
        let mut shared = self.shared.lock().await;
        if let Some(connection) = shared.as_ref() {
            return Ok((connection.sender.clone(), TcpTransportMetrics::default()));
        }

        let connection = self.open_connection().await?;
        let sender = connection.sender.clone();
        let metrics = connection.metrics;
        *shared = Some(Http2SharedConnection {
            sender: connection.sender,
        });
        Ok((sender, metrics))
    }

    async fn clear_connection(&self) {
        *self.shared.lock().await = None;
    }

    async fn open_connection(&self) -> Result<Http2Connection> {
        debug!(
            server = %self.outbound.server,
            port = self.outbound.port,
            "opening HTTP/2 connection to server"
        );

        let server_connect_started = Instant::now();
        let tcp = timeout(
            self.timeouts.server_connect,
            TcpStream::connect((self.outbound.server.as_str(), self.outbound.port)),
        )
        .await
        .with_context(|| {
            format!(
                "timed out connecting to HTTP/2 endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to connect to HTTP/2 endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?;
        let server_tcp_connect_ms = elapsed_millis(server_connect_started.elapsed());

        tcp.set_nodelay(true).with_context(|| {
            format!(
                "failed to enable TCP_NODELAY for HTTP/2 endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?;

        let tls_started = Instant::now();
        let tls = timeout(
            self.timeouts.tls_handshake,
            self.tls
                .connector
                .connect(self.tls.server_name.clone(), tcp),
        )
        .await
        .with_context(|| {
            format!(
                "timed out establishing TLS connection to HTTP/2 endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?
        .with_context(|| {
            format!(
                "failed to establish TLS connection to HTTP/2 endpoint {}:{}",
                self.outbound.server, self.outbound.port
            )
        })?;
        let tls_handshake_ms = elapsed_millis(tls_started.elapsed());

        let (sender, connection) = timeout(self.timeouts.h2_handshake, h2::client::handshake(tls))
            .await
            .context("timed out establishing HTTP/2 client connection")?
            .context("failed to establish HTTP/2 client connection")?;

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                debug!(error = %err, "HTTP/2 client connection closed with error");
            }
        });

        debug!(
            server = %self.outbound.server,
            port = self.outbound.port,
            "HTTP/2 connection established"
        );

        Ok(Http2Connection {
            sender,
            metrics: TcpTransportMetrics {
                server_tcp_connect_ms: Some(server_tcp_connect_ms),
                tls_handshake_ms: Some(tls_handshake_ms),
                raw_tcp_handshake_ms: None,
            },
        })
    }

    async fn open_stream_once(
        &self,
        sender: &mut SendRequest<Bytes>,
        target_host: &str,
        target_port: u16,
    ) -> std::result::Result<Http2OpenStream, OpenStreamError> {
        let mut sender = sender.clone().ready().await.map_err(|err| {
            OpenStreamError::Retryable(anyhow!(err).context("HTTP/2 sender is not ready"))
        })?;

        let request = self
            .build_connect_request(target_host, target_port)
            .map_err(OpenStreamError::Fatal)?;
        let (response, send) = sender.send_request(request, false).map_err(|err| {
            OpenStreamError::Retryable(anyhow!(err).context("failed to send HTTP/2 tunnel request"))
        })?;

        let response = timeout(self.timeouts.response_headers, response)
            .await
            .map_err(|err| {
                OpenStreamError::Retryable(
                    anyhow!(err).context("timed out waiting for HTTP/2 tunnel response"),
                )
            })?
            .map_err(|err| {
                OpenStreamError::Retryable(
                    anyhow!(err).context("failed to receive HTTP/2 tunnel response"),
                )
            })?;

        if response.status() != StatusCode::OK {
            return Err(OpenStreamError::Fatal(anyhow!(
                "HTTP/2 tunnel rejected with status {}",
                response.status()
            )));
        }

        Ok(Http2OpenStream {
            stream: H2StreamIo::new(send, response.into_body()),
        })
    }

    fn build_connect_request(&self, target_host: &str, target_port: u16) -> Result<Request<()>> {
        let auth = build_http2_auth_headers(&self.auth)?;
        let uri = tunnel_uri(&self.outbound)?;

        Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri(uri)
            .header(HEADER_CLIENT_ID, auth.client_id)
            .header(HEADER_TIMESTAMP, auth.timestamp.to_string())
            .header(HEADER_NONCE, auth.nonce)
            .header(HEADER_AUTH, auth.auth_tag)
            .header(HEADER_TARGET_HOST, target_host)
            .header(HEADER_TARGET_PORT, target_port.to_string())
            .body(())
            .context("failed to build HTTP/2 tunnel request")
    }
}

impl Http2Tls {
    fn new(outbound: &OutboundConfig) -> Result<Self> {
        let connector = TlsConnector::from(Arc::new(build_http2_tls_client_config(outbound)?));
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

impl From<TimeoutsConfig> for Http2ClientTimeouts {
    fn from(timeouts: TimeoutsConfig) -> Self {
        let raw_tcp_handshake = Duration::from_millis(timeouts.raw_tcp_handshake_ms);
        let target_connect = Duration::from_millis(timeouts.target_connect_ms);
        Self {
            server_connect: Duration::from_millis(timeouts.server_connect_ms),
            tls_handshake: Duration::from_millis(timeouts.tls_handshake_ms),
            h2_handshake: raw_tcp_handshake,
            response_headers: raw_tcp_handshake.saturating_add(target_connect),
        }
    }
}

impl TcpTransport for Http2Transport {
    fn connect<'a>(
        &'a self,
        target_host: &'a str,
        target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move { self.open_tcp(target_host, target_port).await })
    }
}

impl H2StreamIo {
    fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            write_capacity_requested: false,
            send_closed: false,
        }
    }
}

impl AsyncRead for H2StreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_buf.has_remaining() {
                let len = self.read_buf.remaining().min(buf.remaining());
                if len == 0 {
                    return Poll::Ready(Ok(()));
                }

                buf.put_slice(&self.read_buf[..len]);
                self.read_buf.advance(len);
                return Poll::Ready(Ok(()));
            }

            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.read_buf = chunk;
                }
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::other(err)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2StreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 send stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut capacity = self.send.capacity();
        if capacity == 0 {
            if !self.write_capacity_requested {
                self.send.reserve_capacity(buf.len().min(MAX_H2_DATA_CHUNK));
                self.write_capacity_requested = true;
            }

            capacity = match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(io::Error::other(err))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP/2 send stream capacity is closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            };
            self.write_capacity_requested = false;
        }

        let len = buf.len().min(capacity).min(MAX_H2_DATA_CHUNK);
        self.send
            .send_data(Bytes::copy_from_slice(&buf[..len]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.send_closed {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.send_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

struct Http2AuthHeaders {
    client_id: String,
    timestamp: i64,
    nonce: String,
    auth_tag: String,
}

fn build_http2_auth_headers(auth: &ClientAuthConfig) -> Result<Http2AuthHeaders> {
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
    .context("failed to compute HTTP/2 auth tag")?;

    Ok(Http2AuthHeaders {
        client_id: auth.client_id.clone(),
        timestamp,
        nonce: STANDARD_NO_PAD.encode(nonce),
        auth_tag: STANDARD_NO_PAD.encode(auth_tag),
    })
}

fn tunnel_uri(outbound: &OutboundConfig) -> Result<http::Uri> {
    let scheme = if outbound.tls { "https" } else { "http" };
    let path = http2_tunnel_path(outbound);
    http::Uri::builder()
        .scheme(scheme)
        .authority(http_authority(outbound))
        .path_and_query(path)
        .build()
        .context("failed to build HTTP/2 tunnel URI")
}

fn http2_tunnel_path(outbound: &OutboundConfig) -> &str {
    if outbound.path.trim().is_empty() || outbound.path == LEGACY_TUNNEL_PATH {
        DEFAULT_TUNNEL_PATH
    } else {
        &outbound.path
    }
}

fn http_authority(outbound: &OutboundConfig) -> String {
    let host = outbound
        .tls_server_name
        .as_deref()
        .unwrap_or(&outbound.server);

    if host.starts_with('[') || host.parse::<Ipv6Addr>().is_err() {
        format!("{host}:{}", outbound.port)
    } else {
        format!("[{host}]:{}", outbound.port)
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::config::ClientAuthConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const CLIENT_SECRET: &str = "test-secret";

    fn auth_config() -> ClientAuthConfig {
        ClientAuthConfig {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        }
    }

    fn outbound_config() -> OutboundConfig {
        OutboundConfig {
            server: "localhost".to_string(),
            port: 443,
            tls: true,
            ..OutboundConfig::default()
        }
    }

    #[test]
    fn rejects_http2_without_tls() {
        let mut outbound = outbound_config();
        outbound.tls = false;

        let err =
            match Http2Transport::with_timeouts(outbound, auth_config(), TimeoutsConfig::default())
            {
                Ok(_) => panic!("HTTP/2 without TLS should be rejected"),
                Err(err) => err,
            };

        assert!(err.to_string().contains("requires tls=true"));
    }

    #[test]
    fn builds_connect_request_with_auth_and_target_headers() {
        let transport = Http2Transport::with_timeouts(
            outbound_config(),
            auth_config(),
            TimeoutsConfig::default(),
        )
        .unwrap();

        let request = transport
            .build_connect_request("example.com", 443)
            .expect("request");

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.version(), Version::HTTP_2);
        assert_eq!(request.uri().path(), DEFAULT_TUNNEL_PATH);
        assert_eq!(request.headers()[HEADER_CLIENT_ID], CLIENT_ID);
        assert_eq!(request.headers()[HEADER_TARGET_HOST], "example.com");
        assert_eq!(request.headers()[HEADER_TARGET_PORT], "443");
        assert!(request.headers().contains_key(HEADER_TIMESTAMP));
        assert!(request.headers().contains_key(HEADER_NONCE));
        assert!(request.headers().contains_key(HEADER_AUTH));
    }

    #[tokio::test]
    async fn h2_stream_io_relays_bytes() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (mut client_sender, client_connection) =
            h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            client_connection.await.unwrap();
        });

        let server = tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();

                let mut recv = request.into_body();
                let chunk = recv.data().await.unwrap().unwrap();
                assert_eq!(&chunk[..], b"ping");

                send.send_data(Bytes::from_static(b"pong"), false).unwrap();
                send.send_data(Bytes::new(), true).unwrap();
            });

            let driver = tokio::spawn(async move {
                while let Some(result) = server.accept().await {
                    result.unwrap();
                }
            });

            handler.await.unwrap();
            driver.abort();
        });

        client_sender = client_sender.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri("https://localhost/api/tunnel/h2")
            .body(())
            .unwrap();
        let (response, send) = client_sender.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        let mut stream = H2StreamIo::new(send, response.into_body());

        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
    }
}

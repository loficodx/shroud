use crate::auth::validate_auth;
use crate::transport::tcp_target::{TargetConnectError, connect_target};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use shroud_core::config::ServerConfig;
use shroud_core::http2_protocol::{
    DEFAULT_TUNNEL_PATH, HEADER_AUTH, HEADER_CLIENT_ID, HEADER_NONCE, HEADER_TARGET_HOST,
    HEADER_TARGET_PORT, HEADER_TIMESTAMP, LEGACY_TUNNEL_PATH,
};
use std::collections::HashMap;
use std::future::poll_fn;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::debug;

const ALLOWED_TIMESTAMP_SKEW_SECS: i64 = 120;
const NONCE_LEN: usize = 16;
const NONCE_HEADER_LEN: usize = 22;
const NONCE_CACHE_TTL_SECS: u64 = (ALLOWED_TIMESTAMP_SKEW_SECS as u64) * 2;
const MAX_H2_DATA_CHUNK: usize = 16 * 1024;

pub async fn handle_http2_connection<S>(
    stream: S,
    peer: SocketAddr,
    cfg: Arc<ServerConfig>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .context("failed to establish HTTP/2 server connection")?;
    let state = Arc::new(Http2ServerState::new(cfg));
    let mut active = JoinSet::new();

    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let Some(accepted) = accepted else {
                    break;
                };
                let (request, respond) = accepted.context("failed to accept HTTP/2 request")?;
                let state = state.clone();
                active.spawn(async move {
                    if let Err(err) = handle_http2_request(request, respond, peer, state).await {
                        debug!(%peer, error = %err, "HTTP/2 stream handler failed");
                    }
                });
            }
            result = active.join_next(), if !active.is_empty() => {
                if let Some(Err(err)) = result {
                    debug!(%peer, error = %err, "HTTP/2 stream task join failed");
                }
            }
        }
    }

    while let Some(result) = active.join_next().await {
        if let Err(err) = result {
            debug!(%peer, error = %err, "HTTP/2 stream task join failed");
        }
    }

    Ok(())
}

struct Http2ServerState {
    cfg: Arc<ServerConfig>,
    nonce_cache: Arc<Http2NonceCache>,
}

impl Http2ServerState {
    fn new(cfg: Arc<ServerConfig>) -> Self {
        Self {
            cfg,
            nonce_cache: Arc::new(Http2NonceCache::new(Duration::from_secs(
                NONCE_CACHE_TTL_SECS,
            ))),
        }
    }
}

async fn handle_http2_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: SocketAddr,
    state: Arc<Http2ServerState>,
) -> Result<()> {
    let started = Instant::now();
    let metadata = match validate_http2_request(&request, &state).await {
        Ok(metadata) => metadata,
        Err(rejection) => {
            send_error_response(&mut respond, rejection.status).await?;
            bail!(rejection.reason);
        }
    };

    let connected_target = match connect_target(
        &metadata.target_host,
        metadata.target_port,
        &state.cfg.security,
        Duration::from_millis(state.cfg.timeouts.target_connect_ms),
    )
    .await
    {
        Err(TargetConnectError::Timeout { connect_ms }) => {
            send_error_response(&mut respond, StatusCode::BAD_GATEWAY).await?;
            debug!(
                %peer,
                client_id = %metadata.client_id,
                target_host = %metadata.target_host,
                target_port = metadata.target_port,
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_connect_timeout",
                "HTTP/2 target connect timed out"
            );
            return Ok(());
        }
        Err(TargetConnectError::Forbidden { reason, connect_ms }) => {
            send_error_response(&mut respond, StatusCode::FORBIDDEN).await?;
            debug!(
                %peer,
                client_id = %metadata.client_id,
                target_host = %metadata.target_host,
                target_port = metadata.target_port,
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_forbidden",
                reason,
                "HTTP/2 target blocked by ACL"
            );
            return Ok(());
        }
        Err(err) => {
            let connect_ms = err.connect_ms();
            send_error_response(&mut respond, StatusCode::BAD_GATEWAY).await?;
            debug!(
                %peer,
                client_id = %metadata.client_id,
                target_host = %metadata.target_host,
                target_port = metadata.target_port,
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_connect_failed",
                error = %err,
                "HTTP/2 target connect failed"
            );
            return Ok(());
        }
        Ok(connected_target) => connected_target,
    };

    let target = connected_target.stream;
    target.set_nodelay(true).with_context(|| {
        format!(
            "failed to enable TCP_NODELAY for HTTP/2 target {}:{}",
            metadata.target_host, metadata.target_port
        )
    })?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("failed to build HTTP/2 OK response")?;
    let send = respond
        .send_response(response, false)
        .context("failed to send HTTP/2 OK response")?;

    let target_tcp_connect_ms = connected_target.connect_ms;
    let (upload_bytes, download_bytes) =
        relay_http2_stream(request.into_body(), send, target).await?;

    debug!(
        %peer,
        client_id = %metadata.client_id,
        target_host = %metadata.target_host,
        target_port = metadata.target_port,
        target_tcp_connect_ms,
        relay_duration_ms = elapsed_millis(started.elapsed()),
        relay_bytes_up = upload_bytes,
        relay_bytes_down = download_bytes,
        close_reason = "closed",
        "HTTP/2 server relay closed"
    );

    Ok(())
}

async fn validate_http2_request(
    request: &Request<RecvStream>,
    state: &Http2ServerState,
) -> std::result::Result<Http2RequestMetadata, Http2RequestRejection> {
    if request.method() != Method::POST || request.uri().path() != http2_tunnel_path(&state.cfg) {
        return Err(Http2RequestRejection::new(
            StatusCode::NOT_FOUND,
            "invalid HTTP/2 tunnel method or path",
        ));
    }

    let headers = request.headers();
    let client_id = required_header(headers, HEADER_CLIENT_ID, StatusCode::UNAUTHORIZED)?;
    let timestamp_raw = required_header(headers, HEADER_TIMESTAMP, StatusCode::UNAUTHORIZED)?;
    let nonce_raw = required_header(headers, HEADER_NONCE, StatusCode::UNAUTHORIZED)?;
    let auth_tag = required_header(headers, HEADER_AUTH, StatusCode::UNAUTHORIZED)?;
    let target_host = required_header(headers, HEADER_TARGET_HOST, StatusCode::BAD_REQUEST)?;
    let target_port_raw = required_header(headers, HEADER_TARGET_PORT, StatusCode::BAD_REQUEST)?;

    if target_host.trim().is_empty() {
        return Err(Http2RequestRejection::new(
            StatusCode::BAD_REQUEST,
            format!("empty {HEADER_TARGET_HOST} header"),
        ));
    }

    let target_port = target_port_raw.parse::<u16>().map_err(|err| {
        Http2RequestRejection::new(
            StatusCode::BAD_REQUEST,
            format!("invalid {HEADER_TARGET_PORT} header: {err}"),
        )
    })?;

    let timestamp = timestamp_raw.parse::<i64>().map_err(|err| {
        Http2RequestRejection::new(
            StatusCode::UNAUTHORIZED,
            format!("invalid {HEADER_TIMESTAMP} header: {err}"),
        )
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            Http2RequestRejection::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("system clock is before unix epoch: {err}"),
            )
        })?
        .as_secs() as i64;
    if (now - timestamp).abs() > ALLOWED_TIMESTAMP_SKEW_SECS {
        return Err(Http2RequestRejection::new(
            StatusCode::UNAUTHORIZED,
            "timestamp outside allowed skew window",
        ));
    }

    let nonce = decode_nonce(nonce_raw).map_err(|err| {
        Http2RequestRejection::new(StatusCode::UNAUTHORIZED, format!("invalid nonce: {err}"))
    })?;
    if !validate_auth(&state.cfg.clients, client_id, &nonce, timestamp, auth_tag) {
        return Err(Http2RequestRejection::new(
            StatusCode::UNAUTHORIZED,
            "auth validation failed",
        ));
    }
    if !state.nonce_cache.insert_unique(client_id, &nonce).await {
        return Err(Http2RequestRejection::new(
            StatusCode::UNAUTHORIZED,
            "replayed nonce",
        ));
    }

    Ok(Http2RequestMetadata {
        client_id: client_id.to_string(),
        target_host: target_host.to_string(),
        target_port,
    })
}

async fn relay_http2_stream(
    request_body: RecvStream,
    response_body: SendStream<Bytes>,
    target: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<(u64, u64)> {
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let upload = tokio::spawn(async move {
        let mut request_body = request_body;
        let mut bytes = 0u64;
        while let Some(chunk) = request_body.data().await {
            let chunk = chunk.context("failed to read HTTP/2 request body")?;
            bytes = bytes.saturating_add(chunk.len() as u64);
            target_write
                .write_all(&chunk)
                .await
                .context("failed to write HTTP/2 body chunk to target")?;
        }
        target_write
            .shutdown()
            .await
            .context("failed to shutdown target write half after HTTP/2 EOF")?;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let download = tokio::spawn(async move {
        let mut response_body = response_body;
        let mut bytes = 0u64;
        let mut buf = vec![0u8; MAX_H2_DATA_CHUNK];
        loop {
            let n = target_read
                .read(&mut buf)
                .await
                .context("failed to read from target for HTTP/2 response body")?;
            if n == 0 {
                send_h2_data(&mut response_body, Bytes::new(), true).await?;
                return Ok::<u64, anyhow::Error>(bytes);
            }

            bytes = bytes.saturating_add(n as u64);
            send_h2_data(&mut response_body, Bytes::copy_from_slice(&buf[..n]), false)
                .await
                .context("failed to send target bytes to HTTP/2 response body")?;
        }
    });

    tokio::pin!(upload);
    tokio::pin!(download);

    let (upload_bytes, download_bytes) = tokio::select! {
        upload_result = &mut upload => {
            match flatten_join_result(upload_result, "HTTP/2 upload task") {
                Ok(upload_bytes) => {
                    let download_bytes = flatten_join_result(download.await, "HTTP/2 download task")?;
                    (upload_bytes, download_bytes)
                }
                Err(err) => {
                    download.abort();
                    let _ = download.await;
                    return Err(err);
                }
            }
        }
        download_result = &mut download => {
            match flatten_join_result(download_result, "HTTP/2 download task") {
                Ok(download_bytes) => {
                    let upload_bytes = finish_or_abort_upload(upload).await?;
                    (upload_bytes, download_bytes)
                }
                Err(err) => {
                    upload.abort();
                    let _ = upload.await;
                    return Err(err);
                }
            }
        }
    };

    Ok((upload_bytes, download_bytes))
}

async fn finish_or_abort_upload(
    upload: Pin<&mut tokio::task::JoinHandle<Result<u64>>>,
) -> Result<u64> {
    if upload.is_finished() {
        return flatten_join_result(upload.await, "HTTP/2 upload task");
    }

    upload.abort();
    match upload.await {
        Err(err) if err.is_cancelled() => Ok(0),
        result => flatten_join_result(result, "HTTP/2 upload task"),
    }
}

async fn send_h2_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<()> {
    while data.has_remaining() {
        let desired = data.remaining().min(MAX_H2_DATA_CHUNK);
        let mut capacity = send.capacity();
        if capacity == 0 {
            send.reserve_capacity(desired);
            capacity = poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| anyhow!("HTTP/2 response stream capacity closed"))?
                .context("HTTP/2 response stream capacity failed")?;
        }

        let len = data.remaining().min(capacity).min(MAX_H2_DATA_CHUNK);
        send.send_data(data.split_to(len), false)
            .context("failed to send HTTP/2 response data")?;
    }

    if end_stream {
        send.send_data(Bytes::new(), true)
            .context("failed to end HTTP/2 response stream")?;
    }

    Ok(())
}

async fn send_error_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> Result<()> {
    let response = Response::builder()
        .status(status)
        .body(())
        .context("failed to build HTTP/2 error response")?;
    respond
        .send_response(response, true)
        .context("failed to send HTTP/2 error response")?;
    Ok(())
}

fn flatten_join_result(
    result: std::result::Result<Result<u64>, tokio::task::JoinError>,
    task_name: &str,
) -> Result<u64> {
    result
        .with_context(|| format!("{task_name} join failed"))?
        .with_context(|| format!("{task_name} failed"))
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    status: StatusCode,
) -> std::result::Result<&'a str, Http2RequestRejection> {
    let value = headers.get(name).ok_or_else(|| {
        Http2RequestRejection::new(status, format!("missing required header {name}"))
    })?;
    value
        .to_str()
        .map_err(|err| Http2RequestRejection::new(status, format!("invalid header {name}: {err}")))
}

fn http2_tunnel_path(cfg: &ServerConfig) -> &str {
    if cfg.tunnel_path.trim().is_empty() || cfg.tunnel_path == LEGACY_TUNNEL_PATH {
        DEFAULT_TUNNEL_PATH
    } else {
        &cfg.tunnel_path
    }
}

fn decode_nonce(nonce_raw: &str) -> Result<Vec<u8>> {
    if nonce_raw.len() != NONCE_HEADER_LEN {
        bail!("invalid x-shroud-nonce length");
    }

    if !nonce_raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    {
        bail!("invalid x-shroud-nonce format");
    }

    let nonce = STANDARD_NO_PAD
        .decode(nonce_raw)
        .context("invalid base64 nonce in x-shroud-nonce")?;
    if nonce.len() != NONCE_LEN {
        bail!("invalid x-shroud-nonce decoded length");
    }

    Ok(nonce)
}

struct Http2RequestMetadata {
    client_id: String,
    target_host: String,
    target_port: u16,
}

struct Http2RequestRejection {
    status: StatusCode,
    reason: String,
}

impl Http2RequestRejection {
    fn new(status: StatusCode, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Eq)]
struct Http2NonceKey {
    client_id: String,
    nonce: Vec<u8>,
}

impl PartialEq for Http2NonceKey {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id && self.nonce == other.nonce
    }
}

impl Hash for Http2NonceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client_id.hash(state);
        self.nonce.hash(state);
    }
}

struct Http2NonceCache {
    ttl: Duration,
    entries: Mutex<HashMap<Http2NonceKey, Instant>>,
}

impl Http2NonceCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn insert_unique(&self, client_id: &str, nonce: &[u8]) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_key, expires_at| *expires_at > now);

        let key = Http2NonceKey {
            client_id: client_id.to_string(),
            nonce: nonce.to_vec(),
        };
        if entries.contains_key(&key) {
            return false;
        }

        entries.insert(key, now + self.ttl);
        true
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::config::{
        AuthorizedClient, RelayConfig, ServerSecurityConfig, ServerTlsConfig,
        ServerTransportConfig, TimeoutsConfig, TransportMode,
    };

    const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const CLIENT_SECRET: &str = "test-secret";

    fn cfg() -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tunnel_path: "/api/tunnel".to_string(),
            web_root: ".".to_string(),
            logging: Default::default(),
            transport: ServerTransportConfig {
                modes: vec![TransportMode::Http2],
            },
            tls: ServerTlsConfig::default(),
            timeouts: TimeoutsConfig::default(),
            relay: RelayConfig::default(),
            limits: Default::default(),
            security: ServerSecurityConfig {
                deny_private_ips: false,
                allow_ports: Vec::new(),
            },
            clients: vec![AuthorizedClient {
                name: None,
                client_id: CLIENT_ID.to_string(),
                client_secret: CLIENT_SECRET.to_string(),
                created_at: None,
            }],
        })
    }

    #[test]
    fn default_server_tunnel_path_matches_client_http2_default() {
        assert_eq!(http2_tunnel_path(&cfg()), DEFAULT_TUNNEL_PATH);
    }

    #[tokio::test]
    async fn rejects_wrong_http2_method() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(handle_http2_connection(
            server_io,
            "127.0.0.1:12345".parse().unwrap(),
            cfg(),
        ));
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });

        client = client.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://localhost/api/tunnel/h2")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        send.send_data(Bytes::new(), true).ok();
        drop(response);
        drop(send);
        drop(client);
        connection.await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relays_http2_stream_to_target() {
        let (target_for_relay, mut target_peer) = tokio::io::duplex(64 * 1024);
        let target = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            target_peer.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            target_peer.write_all(b"pong").await.unwrap();
        });

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = server.accept().await.unwrap().unwrap();
            let handler = tokio::spawn(async move {
                let response = Response::builder().status(StatusCode::OK).body(()).unwrap();
                let send = respond.send_response(response, false).unwrap();
                relay_http2_stream(request.into_body(), send, target_for_relay)
                    .await
                    .unwrap()
            });

            let driver = tokio::spawn(async move {
                while let Some(result) = server.accept().await {
                    result.unwrap();
                }
            });

            let result = handler.await.unwrap();
            driver.abort();
            result
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });

        client = client.ready().await.unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/api/tunnel/h2")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        send.send_data(Bytes::from_static(b"ping"), true).unwrap();
        let mut body = response.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
        }
        assert_eq!(&received, b"pong");

        drop(body);
        drop(send);
        drop(client);
        connection.await.unwrap();
        assert_eq!(server.await.unwrap(), (4, 4));
        target.await.unwrap();
    }
}

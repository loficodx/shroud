use crate::transport::http2::handle_http2_connection;
use crate::transport::raw_tcp::{RawTcpServerState, handle_raw_tcp_connection};
use crate::transport::tls::{TlsAlpn, build_tls_acceptor_with_alpn};
use anyhow::{Context, Result, anyhow, bail};
use shroud_core::config::{ServerConfig, TransportMode};
use shroud_core::tcp_handshake::RAW_TCP_MAGIC;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const MAX_HTTP_HEADERS: usize = 16 * 1024;
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptedProtocol {
    H2,
    Http1,
    Unknown,
}

impl AcceptedProtocol {
    fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(b"h2") => Self::H2,
            Some(b"http/1.1") => Self::Http1,
            _ => Self::Unknown,
        }
    }
}

pub async fn serve(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let tls_alpn = if cfg.transport.modes.contains(&TransportMode::Http2) {
        TlsAlpn::Http2
    } else {
        TlsAlpn::None
    };
    let tls_acceptor = build_tls_acceptor_with_alpn(&cfg.tls, tls_alpn)?;
    let raw_tcp_state = RawTcpServerState::with_relay_config(
        cfg.clients.clone(),
        cfg.timeouts,
        cfg.security.clone(),
        cfg.relay,
    );
    let connection_slots = Arc::new(Semaphore::new(cfg.limits.max_concurrent_connections));
    let mut active = JoinSet::new();
    info!(
        listen = %cfg.listen,
        tls = cfg.tls.enabled,
        max_concurrent_connections = cfg.limits.max_concurrent_connections,
        "server listener started"
    );

    loop {
        tokio::select! {
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.context("failed to listen for Ctrl+C")?;
                info!(listen = %cfg.listen, active_sessions = active.len(), "server listener shutting down");
                break;
            }
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;

                stream.set_nodelay(true)
                    .context("failed to enable TCP_NODELAY for accepted tunnel socket")?;

                let cfg = cfg.clone();
                let tls_acceptor = tls_acceptor.clone();
                let raw_tcp_state = raw_tcp_state.clone();
                let permit = connection_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .context("server connection limit semaphore closed")?;

                active.spawn(async move {
                    let _permit = permit;
                    let result = if let Some(acceptor) = tls_acceptor {
                        let tls_started = Instant::now();
                        match timeout(
                            Duration::from_millis(cfg.timeouts.tls_handshake_ms),
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Err(_) => {
                                warn!(
                                    %peer,
                                    tls_handshake_ms = elapsed_millis(tls_started.elapsed()),
                                    "server TLS handshake timed out"
                                );
                                Err(anyhow!("tls handshake timed out"))
                            }
                            Ok(Ok(stream)) => {
                                let accepted_protocol = AcceptedProtocol::from_alpn(
                                    stream.get_ref().1.alpn_protocol(),
                                );
                                debug!(
                                    %peer,
                                    tls_handshake_ms = elapsed_millis(tls_started.elapsed()),
                                    ?accepted_protocol,
                                    "server TLS handshake finished"
                                );
                                handle_connection(
                                    stream,
                                    peer,
                                    cfg,
                                    raw_tcp_state,
                                    accepted_protocol,
                                )
                                .await
                            }
                            Ok(Err(err)) => {
                                warn!(
                                    %peer,
                                    tls_handshake_ms = elapsed_millis(tls_started.elapsed()),
                                    error = %err,
                                    "server TLS handshake failed"
                                );
                                Err(anyhow!(err)).context("tls handshake failed")
                            }
                        }
                    } else {
                        handle_connection(
                            stream,
                            peer,
                            cfg,
                            raw_tcp_state,
                            AcceptedProtocol::Unknown,
                        )
                        .await
                    };

                    if let Err(err) = result {
                        debug!(
                            %peer,
                            error = format!("{err:#}"),
                            "failed to handle incoming connection"
                        );
                    }
                });
            }
            result = active.join_next(), if !active.is_empty() => {
                if let Some(Err(err)) = result {
                    debug!(
                        error = format!("{err:#}"),
                        "server connection task join failed"
                    );
                }
            }
        }
    }

    active.abort_all();
    let _ = timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = active.join_next().await {
            if let Err(err) = result {
                debug!(
                    error = format!("{err:#}"),
                    "server connection task stopped during shutdown"
                );
            }
        }
    })
    .await;

    Ok(())
}

async fn handle_connection<S>(
    stream: S,
    peer: std::net::SocketAddr,
    cfg: ServerConfig,
    raw_tcp_state: RawTcpServerState,
    accepted_protocol: AcceptedProtocol,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw_tcp_enabled = cfg.transport.modes.contains(&TransportMode::RawTcp);
    let http2_enabled = cfg.transport.modes.contains(&TransportMode::Http2);
    if raw_tcp_enabled {
        let (stream, is_raw_tcp) = sniff_raw_tcp_magic(
            stream,
            Duration::from_millis(cfg.timeouts.raw_tcp_handshake_ms),
        )
        .await?;
        if is_raw_tcp {
            return handle_raw_tcp_connection(stream, peer, raw_tcp_state).await;
        }
        if http2_enabled && accepted_protocol == AcceptedProtocol::H2 {
            return handle_http2_connection(stream, peer, Arc::new(cfg)).await;
        }

        return handle_http_connection(stream, cfg).await;
    }

    if http2_enabled && accepted_protocol == AcceptedProtocol::H2 {
        return handle_http2_connection(stream, peer, Arc::new(cfg)).await;
    }

    handle_http_connection(stream, cfg).await
}

async fn handle_http_connection<S>(mut stream: S, cfg: ServerConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_raw = read_http_headers(&mut stream).await?;
    let request_text =
        std::str::from_utf8(&request_raw).context("request headers are not utf-8")?;
    let parsed = parse_http_request(request_text)?;

    if parsed.method == "GET" && parsed.path == "/api/status" {
        return serve_health_status(&mut stream).await;
    }

    if parsed.method == "GET" || parsed.method == "HEAD" {
        return serve_static_file(
            &mut stream,
            &cfg.web_root,
            &parsed.path,
            parsed.method == "HEAD",
        )
        .await;
    }

    write_error_response(&mut stream, 404, false).await?;
    Ok(())
}

async fn sniff_raw_tcp_magic<S>(
    mut stream: S,
    sniff_timeout: Duration,
) -> Result<(PrefixedStream<S>, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = [0u8; RAW_TCP_MAGIC.len()];
    timeout(sniff_timeout, stream.read_exact(&mut prefix))
        .await
        .context("timed out reading connection prefix")?
        .context("failed to read connection prefix")?;
    let is_raw_tcp = prefix == RAW_TCP_MAGIC;
    Ok((PrefixedStream::new(stream, prefix.to_vec()), is_raw_tcp))
}

struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let available = &self.prefix[self.prefix_pos..];
            let len = available.len().min(buf.remaining());
            if len == 0 {
                return Poll::Ready(Ok(()));
            }

            buf.put_slice(&available[..len]);
            self.prefix_pos += len;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn serve_health_status<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    write_response(
        stream,
        200,
        "application/json; charset=utf-8",
        b"{\"status\":\"ok\"}\n",
        false,
    )
    .await
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

async fn serve_static_file<S>(
    stream: &mut S,
    web_root: &str,
    request_path: &str,
    head_only: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let Some(candidate) = resolve_web_path(web_root, request_path) else {
        write_error_response(stream, 404, head_only).await?;
        return Ok(());
    };

    let root = match fs::canonicalize(web_root).await {
        Ok(root) => root,
        Err(_) => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let candidate = match fs::metadata(&candidate).await {
        Ok(metadata) if metadata.is_dir() => candidate.join("index.html"),
        Ok(_) => candidate,
        Err(_) => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let file_path = match fs::canonicalize(&candidate).await {
        Ok(path) if path.starts_with(&root) => path,
        _ => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let metadata = match fs::metadata(&file_path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            write_error_response(stream, 404, head_only).await?;
            return Ok(());
        }
    };

    let content_type = content_type_for_path(&file_path);
    if head_only {
        write_response_headers(stream, 200, content_type, metadata.len() as usize).await?;
        return Ok(());
    }

    let body = match fs::read(&file_path).await {
        Ok(body) => body,
        Err(_) => {
            write_error_response(stream, 404, false).await?;
            return Ok(());
        }
    };

    write_response(stream, 200, content_type, &body, false).await?;
    Ok(())
}

fn resolve_web_path(web_root: &str, request_path: &str) -> Option<PathBuf> {
    let relative = sanitize_request_path(request_path)?;
    let mut path = PathBuf::from(web_root);

    if relative.as_os_str().is_empty() {
        path.push("index.html");
    } else {
        path.push(relative);
    }

    Some(path)
}

fn sanitize_request_path(request_path: &str) -> Option<PathBuf> {
    if !request_path.starts_with('/') {
        return None;
    }

    let decoded = percent_decode_path(request_path)?;
    if decoded.as_bytes().contains(&0) {
        return None;
    }

    let relative = decoded.trim_start_matches('/');
    let mut out = PathBuf::new();

    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str()?;
                if part.contains('\\') {
                    return None;
                }
                out.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    Some(out)
}

fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let high = hex_value(bytes[i + 1])?;
            let low = hex_value(bytes[i + 2])?;
            out.push((high << 4) | low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

async fn write_error_response<S>(stream: &mut S, status_code: u16, head_only: bool) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let body = match status_code {
        403 => b"<!doctype html><html><body><h1>Forbidden</h1></body></html>".as_slice(),
        404 => b"<!doctype html><html><body><h1>Not Found</h1></body></html>".as_slice(),
        _ => b"<!doctype html><html><body><h1>Error</h1></body></html>".as_slice(),
    };
    write_response(
        stream,
        status_code,
        "text/html; charset=utf-8",
        body,
        head_only,
    )
    .await
}

async fn write_response<S>(
    stream: &mut S,
    status_code: u16,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    write_response_headers(stream, status_code, content_type, body.len()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    Ok(())
}

async fn write_response_headers<S>(
    stream: &mut S,
    status_code: u16,
    content_type: &str,
    content_len: usize,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let response = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {content_len}\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        reason = reason_phrase(status_code),
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    }
}

async fn read_http_headers<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
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

    bail!("request headers too large")
}

struct ParsedHttpRequest {
    method: String,
    path: String,
}

fn parse_http_request(raw_request: &str) -> Result<ParsedHttpRequest> {
    let mut lines = raw_request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .ok_or_else(|| anyhow!("missing method in request line"))?
        .to_string();
    let path = request_line_parts
        .next()
        .ok_or_else(|| anyhow!("missing path in request line"))?
        .split('?')
        .next()
        .ok_or_else(|| anyhow!("missing path before query in request line"))?
        .to_string();

    for line in lines {
        if line.is_empty() {
            break;
        }

        let (_name, _value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid header line: {line}"))?;
    }

    Ok(ParsedHttpRequest { method, path })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::config::{
        AuthorizedClient, ServerSecurityConfig, ServerTlsConfig, ServerTransportConfig,
        TransportMode,
    };
    use shroud_core::tcp_handshake::{TcpConnectStatus, read_raw_tcp_connect_status};
    use std::fs as std_fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static TEMP_WEB_ROOT_ID: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn raw_tcp_sniff_times_out_when_prefix_stalls() {
        let (_client, server) = tokio::io::duplex(64);

        let err = match sniff_raw_tcp_magic(server, Duration::from_millis(10)).await {
            Ok(_) => panic!("sniff unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("timed out reading connection prefix")
        );
    }

    #[tokio::test]
    async fn handle_connection_dispatches_raw_magic_to_raw_tcp_when_http2_is_enabled() {
        let web_root = TempWebRoot::new();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let cfg = test_config(&web_root, vec![TransportMode::RawTcp, TransportMode::Http2]);
        let raw_tcp_state = test_raw_tcp_state(&cfg);

        let handle = tokio::spawn(async move {
            handle_connection(
                server,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                cfg,
                raw_tcp_state,
                AcceptedProtocol::H2,
            )
            .await
        });

        client
            .write_all(&RAW_TCP_MAGIC)
            .await
            .expect("write raw_tcp magic");
        client.shutdown().await.expect("shutdown raw_tcp request");

        let status = read_raw_tcp_connect_status(&mut client)
            .await
            .expect("read raw_tcp status");
        let err = handle
            .await
            .expect("join handler")
            .expect_err("incomplete raw_tcp request should fail in raw_tcp handler");

        assert_eq!(status, TcpConnectStatus::InvalidRequest);
        assert!(
            err.to_string()
                .contains("failed to read raw_tcp connect request")
        );
    }

    #[tokio::test]
    async fn handle_connection_dispatches_non_raw_tcp_prefix_to_http2_with_h2_protocol() {
        let web_root = TempWebRoot::new();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let cfg = test_config(&web_root, vec![TransportMode::RawTcp, TransportMode::Http2]);
        let raw_tcp_state = test_raw_tcp_state(&cfg);

        let handle = tokio::spawn(async move {
            handle_connection(
                server,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                cfg,
                raw_tcp_state,
                AcceptedProtocol::H2,
            )
            .await
        });

        let (mut h2_client, connection) = h2::client::handshake(client).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });

        h2_client = h2_client.ready().await.unwrap();
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://localhost/api/tunnel/h2")
            .body(())
            .unwrap();
        let (response, mut send) = h2_client.send_request(request, true).unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
        send.send_data(bytes::Bytes::new(), true).ok();
        drop(response);
        drop(send);
        drop(h2_client);

        connection.await.unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn handle_connection_dispatches_http1_to_fallback_when_raw_tcp_and_http2_enabled() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let (response, result) = run_dispatch_http_request(
            &web_root,
            vec![TransportMode::RawTcp, TransportMode::Http2],
            AcceptedProtocol::Http1,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        result.expect("handler should use HTTP/1.1 fallback");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("{\"status\":\"ok\"}\n"));
    }

    #[tokio::test]
    async fn handle_connection_dispatches_raw_tcp_only_http1_request_to_http_fallback() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let (response, result) = run_dispatch_http_request(
            &web_root,
            vec![TransportMode::RawTcp],
            AcceptedProtocol::Unknown,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        result.expect("handler should use HTTP/1.1 fallback");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("{\"status\":\"ok\"}\n"));
    }

    #[tokio::test]
    async fn handle_connection_dispatches_http2_only_h2_protocol_to_http2() {
        let web_root = TempWebRoot::new();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let cfg = test_config(&web_root, vec![TransportMode::Http2]);
        let raw_tcp_state = test_raw_tcp_state(&cfg);

        let handle = tokio::spawn(async move {
            handle_connection(
                server,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                cfg,
                raw_tcp_state,
                AcceptedProtocol::H2,
            )
            .await
        });

        let (mut h2_client, connection) = h2::client::handshake(client).await.unwrap();
        let connection = tokio::spawn(async move { connection.await.unwrap() });

        h2_client = h2_client.ready().await.unwrap();
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://localhost/api/tunnel/h2")
            .body(())
            .unwrap();
        let (response, mut send) = h2_client.send_request(request, true).unwrap();
        let response = response.await.unwrap();

        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
        send.send_data(bytes::Bytes::new(), true).ok();
        drop(response);
        drop(send);
        drop(h2_client);

        connection.await.unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn handle_connection_dispatches_unknown_protocol_to_http_fallback() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let (response, result) = run_dispatch_http_request(
            &web_root,
            vec![TransportMode::Http2],
            AcceptedProtocol::Unknown,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;

        result.expect("handler should use HTTP/1.1 fallback");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("{\"status\":\"ok\"}\n"));
    }

    #[tokio::test]
    async fn fallback_serves_index_for_root() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8"));
        assert!(response.ends_with("fallback index"));
    }

    #[tokio::test]
    async fn fallback_serves_static_asset_with_content_type() {
        let web_root = TempWebRoot::new();
        web_root.write("assets/app.js", b"console.log('ok');");

        let response = run_request(
            &web_root,
            "GET /assets/app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: application/javascript; charset=utf-8"));
        assert!(response.ends_with("console.log('ok');"));
    }

    #[tokio::test]
    async fn fallback_strips_query_before_file_lookup() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /?v=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("fallback index"));
    }

    #[tokio::test]
    async fn health_status_returns_minimal_neutral_json() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: application/json; charset=utf-8"));
        assert!(response.ends_with("{\"status\":\"ok\"}\n"));
        assert!(!response.to_ascii_lowercase().contains("proxy"));
        assert!(!response.to_ascii_lowercase().contains("tunnel"));
        assert!(!response.to_ascii_lowercase().contains("auth"));
    }

    #[tokio::test]
    async fn fallback_head_returns_headers_without_body() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Length: 14"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.contains("fallback index"));
    }

    #[tokio::test]
    async fn fallback_missing_path_returns_neutral_404() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response.contains("<h1>Not Found</h1>"));
        assert!(!response.to_ascii_lowercase().contains("proxy"));
        assert!(!response.to_ascii_lowercase().contains("shroud"));
    }

    #[tokio::test]
    async fn fallback_rejects_path_traversal() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");
        let outside = web_root.path.parent().expect("parent").join("secret.txt");
        std_fs::write(&outside, b"secret outside web root").expect("write secret");

        let response = run_request(
            &web_root,
            "GET /../secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        let _ = std_fs::remove_file(outside);
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("secret outside web root"));
    }

    #[tokio::test]
    async fn fallback_rejects_encoded_path_traversal() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "GET /%2e%2e/Cargo.toml HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(!response.contains("[workspace]"));
    }

    #[tokio::test]
    async fn legacy_http_upgrade_tunnel_path_returns_404() {
        let web_root = TempWebRoot::new();
        web_root.write("index.html", b"fallback index");

        let response = run_request(
            &web_root,
            "POST /api/tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    struct TempWebRoot {
        path: std::path::PathBuf,
    }

    impl TempWebRoot {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let id = TEMP_WEB_ROOT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "shroud-web-test-{}-{unique}-{id}",
                std::process::id()
            ));
            std_fs::create_dir_all(&path).expect("create temp web root");
            Self { path }
        }

        fn write(&self, relative: &str, body: &[u8]) {
            let path = self.path.join(relative);
            if let Some(parent) = path.parent() {
                std_fs::create_dir_all(parent).expect("create parent dir");
            }
            std_fs::write(path, body).expect("write fixture");
        }
    }

    impl Drop for TempWebRoot {
        fn drop(&mut self) {
            let _ = std_fs::remove_dir_all(&self.path);
        }
    }

    fn test_config(web_root: &TempWebRoot, modes: Vec<TransportMode>) -> ServerConfig {
        ServerConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            web_root: web_root.path.to_string_lossy().into_owned(),
            logging: Default::default(),
            transport: ServerTransportConfig { modes },
            tls: ServerTlsConfig::default(),
            timeouts: Default::default(),
            relay: Default::default(),
            limits: Default::default(),
            security: ServerSecurityConfig::default(),
            clients: vec![AuthorizedClient {
                name: None,
                client_id: "11111111-1111-1111-1111-111111111111".to_string(),
                client_secret: "test-secret".to_string(),
                created_at: None,
            }],
        }
    }

    fn test_raw_tcp_state(cfg: &ServerConfig) -> RawTcpServerState {
        RawTcpServerState::with_relay_config(
            cfg.clients.clone(),
            cfg.timeouts,
            cfg.security.clone(),
            cfg.relay,
        )
    }

    async fn run_dispatch_http_request(
        web_root: &TempWebRoot,
        modes: Vec<TransportMode>,
        accepted_protocol: AcceptedProtocol,
        request: &str,
    ) -> (String, Result<()>) {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let cfg = test_config(web_root, modes);
        let raw_tcp_state = test_raw_tcp_state(&cfg);

        let handle = tokio::spawn(async move {
            handle_connection(
                server,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                cfg,
                raw_tcp_state,
                accepted_protocol,
            )
            .await
        });

        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client.shutdown().await.expect("shutdown request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");

        let result = handle.await.expect("join handler");
        (String::from_utf8_lossy(&response).into_owned(), result)
    }

    async fn run_request(web_root: &TempWebRoot, request: &str) -> String {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let cfg = test_config(web_root, vec![TransportMode::RawTcp]);
        let handle = tokio::spawn(async move { handle_http_connection(server, cfg).await });

        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client.shutdown().await.expect("shutdown request");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read response");

        let _ = handle.await.expect("join handler");
        String::from_utf8_lossy(&response).into_owned()
    }
}

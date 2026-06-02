use crate::session::{DnsPolicyResult, SessionContext, SessionCore, TcpOpenResult};
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info};

const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(
    listen: SocketAddr,
    session: SessionCore,
    max_concurrent_connections: usize,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let connection_slots = Arc::new(Semaphore::new(max_concurrent_connections));
    info!(
        %listen,
        max_concurrent_connections,
        "SOCKS5 inbound listener started"
    );
    let mut active = JoinSet::new();

    loop {
        tokio::select! {
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.context("failed to listen for Ctrl+C")?;
                info!(%listen, active_sessions = active.len(), "SOCKS5 listener shutting down");
                break;
            }
            accept_result = listener.accept() => {
                let (socket, peer) = accept_result?;
                socket.set_nodelay(true)
                    .context("failed to enable TCP_NODELAY for SOCKS client socket")?;

                debug!(%peer, "new connection");

                let session = session.clone();
                let permit = connection_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .context("SOCKS5 connection limit semaphore closed")?;

                active.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection(socket, peer, session).await {
                        debug!(%peer, error = %err, "connection handling failed");
                    }
                });
            }
            result = active.join_next(), if !active.is_empty() => {
                if let Some(Err(err)) = result {
                    debug!(error = %err, "SOCKS5 connection task join failed");
                }
            }
        }
    }

    active.abort_all();
    let _ = timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = active.join_next().await {
            if let Err(err) = result {
                debug!(error = %err, "SOCKS5 connection task stopped during shutdown");
            }
        }
    })
    .await;

    Ok(())
}

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    session: SessionCore,
) -> Result<()> {
    timeout(SOCKS_HANDSHAKE_TIMEOUT, handshake(&mut socket))
        .await
        .context("SOCKS handshake timed out")??;
    let request = timeout(SOCKS_REQUEST_TIMEOUT, read_request(&mut socket))
        .await
        .context("SOCKS request timed out")??;
    let ConnectRequest { host, port } = match request {
        SocksRequest::Connect(request) => request,
        SocksRequest::UdpAssociate(request) => {
            write_reply(&mut socket, ReplyCode::CommandNotSupported).await?;
            debug!(
                %peer,
                client_declared_udp_host = %request.host,
                client_declared_udp_port = request.port,
                "SOCKS UDP ASSOCIATE rejected"
            );
            bail!("UDP ASSOCIATE is not supported in current MVP");
        }
        SocksRequest::Bind(request) => {
            write_reply(&mut socket, ReplyCode::CommandNotSupported).await?;
            bail!(
                "SOCKS BIND is not supported: {}:{}",
                request.host,
                request.port
            );
        }
    };
    let target_host = host.as_str();
    let target_port = port;

    if matches!(
        session.check_dns_policy(
            target_host,
            target_port,
            SessionContext {
                inbound: "socks5",
                peer: Some(peer),
            },
        ),
        DnsPolicyResult::BlockedIpTarget
    ) {
        write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
        debug!(%peer, target_host, target_port, "blocked IP target by DNS policy");
        return Ok(());
    }

    let outbound = match session.open_tcp(target_host, target_port).await {
        Ok(TcpOpenResult::Opened(outbound)) => outbound,
        Ok(TcpOpenResult::Blocked) => {
            write_reply(&mut socket, ReplyCode::ConnectionNotAllowed).await?;
            debug!(%peer, target_host, target_port, "blocked by route rule");
            return Ok(());
        }
        Err(err) => {
            write_reply(&mut socket, ReplyCode::GeneralFailure).await?;
            return Err(err);
        }
    };

    write_reply(&mut socket, ReplyCode::Succeeded).await?;
    let action = outbound.action;
    let metrics = outbound.metrics;
    let relay_started = Instant::now();
    let stats = session
        .relay_tcp(&mut socket, outbound)
        .await
        .with_context(|| format!("relay failed for {target_host}:{target_port}"))?;
    let relay_elapsed = relay_started.elapsed();
    let total_bytes = stats.total_bytes();
    let mbps = stats.mbps(relay_elapsed);

    debug!(
        %peer,
        target_host,
        target_port,
        route = ?action,
        server_tcp_connect_ms = metrics.server_tcp_connect_ms,
        tls_handshake_ms = metrics.tls_handshake_ms,
        http_upgrade_ms = metrics.http_upgrade_ms,
        target_tcp_connect_ms = metrics.target_tcp_connect_ms,
        client_to_upstream_bytes = stats.client_to_upstream_bytes,
        upstream_to_client_bytes = stats.upstream_to_client_bytes,
        total_bytes,
        duration_ms = elapsed_millis(relay_elapsed),
        mbps,
        "connection relay finished"
    );

    Ok(())
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectRequest {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SocksRequest {
    Connect(ConnectRequest),
    UdpAssociate(ConnectRequest),
    Bind(ConnectRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for SocksCommand {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            value => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

async fn handshake<T>(socket: &mut T) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("unsupported socks version: {}", header[0]);
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    if methods.contains(&0x00) {
        socket.write_all(&[0x05, 0x00]).await?;
        Ok(())
    } else {
        socket.write_all(&[0x05, 0xFF]).await?;
        bail!("no supported auth method from client")
    }
}

async fn read_request<T>(socket: &mut T) -> Result<SocksRequest>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        bail!("unsupported request socks version: {}", header[0]);
    }
    if header[2] != 0x00 {
        write_reply(socket, ReplyCode::GeneralFailure).await?;
        bail!("invalid socks request reserved byte: {}", header[2]);
    }

    let command = match SocksCommand::try_from(header[1]) {
        Ok(command) => command,
        Err(command) => {
            skip_request_address(socket, header[3]).await?;
            write_reply(socket, ReplyCode::CommandNotSupported).await?;
            bail!("unsupported socks command: {command}");
        }
    };

    let request = read_request_address(socket, header[3]).await?;
    Ok(match command {
        SocksCommand::Connect => SocksRequest::Connect(request),
        SocksCommand::UdpAssociate => SocksRequest::UdpAssociate(request),
        SocksCommand::Bind => SocksRequest::Bind(request),
    })
}

async fn read_request_address<T>(socket: &mut T, atyp: u8) -> Result<ConnectRequest>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let host = match atyp {
        0x01 => {
            let mut raw = [0u8; 4];
            socket.read_exact(&mut raw).await?;
            IpAddr::V4(Ipv4Addr::from(raw)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            socket.read_exact(&mut raw).await?;
            String::from_utf8(raw).context("invalid utf-8 domain in socks request")?
        }
        0x04 => {
            let mut raw = [0u8; 16];
            socket.read_exact(&mut raw).await?;
            IpAddr::V6(Ipv6Addr::from(raw)).to_string()
        }
        _ => {
            write_reply(socket, ReplyCode::AddressTypeNotSupported).await?;
            bail!("unsupported socks address type: {atyp}");
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(ConnectRequest { host, port })
}

async fn skip_request_address<T>(socket: &mut T, atyp: u8) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match atyp {
        0x01 => {
            let mut raw = [0u8; 4 + 2];
            socket.read_exact(&mut raw).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut raw).await?;
        }
        0x04 => {
            let mut raw = [0u8; 16 + 2];
            socket.read_exact(&mut raw).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn write_reply<T>(socket: &mut T, code: ReplyCode) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let reply = [
        0x05, code as u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    socket.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn parser_reads_connect_request() {
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::Connect(ConnectRequest {
                host: "example.com".to_string(),
                port: 443,
            })
        );
    }

    #[tokio::test]
    async fn parser_reads_udp_associate_request() {
        let request = [0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x13, 0x88];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::UdpAssociate(ConnectRequest {
                host: "127.0.0.1".to_string(),
                port: 5000,
            })
        );
    }

    #[tokio::test]
    async fn parser_reads_bind_as_unsupported_command_variant() {
        let request = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        let parsed = parse_request_from_bytes(&request).await;

        assert_eq!(
            parsed,
            SocksRequest::Bind(ConnectRequest {
                host: "127.0.0.1".to_string(),
                port: 80,
            })
        );
    }

    async fn parse_request_from_bytes(bytes: &[u8]) -> SocksRequest {
        let (mut client, mut server) = duplex(64);
        client.write_all(bytes).await.expect("write request");
        read_request(&mut server).await.expect("parse request")
    }
}

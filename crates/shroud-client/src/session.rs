use crate::routing::Router;
use crate::transport::{BoxedIo, TcpTransport, TcpTransportMetrics};
use anyhow::{Context, Result};
use shroud_core::config::{ClientDnsConfig, RelayConfig, RouteAction};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

const DIRECT_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Clone)]
pub struct SessionCore {
    router: Router,
    tcp_transport: Arc<dyn TcpTransport>,
    dns: ClientDnsConfig,
    relay: RelayConfig,
}

impl SessionCore {
    pub fn new(
        router: Router,
        tcp_transport: Arc<dyn TcpTransport>,
        dns: ClientDnsConfig,
        relay: RelayConfig,
    ) -> Self {
        Self {
            router,
            tcp_transport,
            dns,
            relay,
        }
    }

    pub fn check_dns_policy(
        &self,
        target_host: &str,
        target_port: u16,
        context: SessionContext<'_>,
    ) -> DnsPolicyResult {
        if let Ok(target_ip) = target_host.parse::<IpAddr>() {
            if self.dns.warn_on_ip_targets {
                warn!(
                    inbound = context.inbound,
                    peer = ?context.peer,
                    %target_ip,
                    target_port,
                    remote_by_default = self.dns.remote_by_default,
                    block_ip_targets = self.dns.block_ip_targets,
                    "target is an IP address; remote DNS cannot be applied because the application likely resolved the name locally"
                );
            }

            if self.dns.block_ip_targets {
                return DnsPolicyResult::BlockedIpTarget;
            }
        } else if self.dns.remote_by_default {
            debug!(
                inbound = context.inbound,
                peer = ?context.peer,
                target_host,
                target_port,
                "target is a domain; preserving it for remote resolution"
            );
        }

        DnsPolicyResult::Allowed
    }

    pub fn decide(&self, target_host: &str, target_port: u16) -> RouteAction {
        self.router.decide(target_host, target_port)
    }

    pub async fn open_tcp(&self, target_host: &str, target_port: u16) -> Result<TcpOpenResult> {
        let action = self.decide(target_host, target_port);

        match action {
            RouteAction::Proxy => {
                let transport = self
                    .tcp_transport
                    .connect(target_host, target_port)
                    .await
                    .context("proxy transport connect failed")?;
                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    metrics: TcpOpenMetrics::from(transport.metrics),
                    stream: TcpOutboundStream::Proxy(transport.stream),
                }))
            }
            RouteAction::Direct => {
                let target_connect_started = Instant::now();
                let stream = timeout(
                    DIRECT_TARGET_CONNECT_TIMEOUT,
                    TcpStream::connect((target_host, target_port)),
                )
                .await
                .with_context(|| {
                    format!(
                        "timed out opening direct tcp connection to {target_host}:{target_port}"
                    )
                })?
                .with_context(|| {
                    format!("failed to open direct tcp connection to {target_host}:{target_port}")
                })?;
                let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());

                stream.set_nodelay(true).with_context(|| {
                    format!(
                        "failed to enable TCP_NODELAY for direct tcp connection to {target_host}:{target_port}"
                    )
                })?;

                Ok(TcpOpenResult::Opened(TcpOutbound {
                    action,
                    metrics: TcpOpenMetrics {
                        target_tcp_connect_ms: Some(target_tcp_connect_ms),
                        ..TcpOpenMetrics::default()
                    },
                    stream: TcpOutboundStream::Direct(stream),
                }))
            }
            RouteAction::Block => Ok(TcpOpenResult::Blocked),
        }
    }

    pub async fn relay_tcp<S>(
        &self,
        client_stream: &mut S,
        outbound: TcpOutbound,
    ) -> Result<RelayStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match outbound.stream {
            TcpOutboundStream::Proxy(mut upstream) => self
                .relay_raw_tcp(client_stream, &mut upstream)
                .await
                .context("proxy relay failed"),
            TcpOutboundStream::Direct(mut upstream) => self
                .relay_raw_tcp(client_stream, &mut upstream)
                .await
                .context("direct relay failed"),
        }
    }

    async fn relay_raw_tcp<S, U>(
        &self,
        client_stream: &mut S,
        upstream: &mut U,
    ) -> Result<RelayStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let (client_to_upstream_bytes, upstream_to_client_bytes) =
            tokio::io::copy_bidirectional_with_sizes(
                client_stream,
                upstream,
                self.relay.upload_buffer_size,
                self.relay.download_buffer_size,
            )
            .await
            .context("raw TCP relay failed")?;

        Ok(RelayStats {
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionContext<'a> {
    pub inbound: &'a str,
    pub peer: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicyResult {
    Allowed,
    BlockedIpTarget,
}

pub enum TcpOpenResult {
    Opened(TcpOutbound),
    Blocked,
}

pub struct TcpOutbound {
    pub action: RouteAction,
    pub metrics: TcpOpenMetrics,
    stream: TcpOutboundStream,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOpenMetrics {
    pub server_tcp_connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    pub raw_tcp_handshake_ms: Option<u64>,
    pub target_tcp_connect_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

impl From<TcpTransportMetrics> for TcpOpenMetrics {
    fn from(metrics: TcpTransportMetrics) -> Self {
        Self {
            server_tcp_connect_ms: metrics.server_tcp_connect_ms,
            tls_handshake_ms: metrics.tls_handshake_ms,
            raw_tcp_handshake_ms: metrics.raw_tcp_handshake_ms,
            target_tcp_connect_ms: None,
        }
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

enum TcpOutboundStream {
    Proxy(BoxedIo),
    Direct(TcpStream),
}

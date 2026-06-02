use crate::transport::{TcpTransport, TcpTransportConnect, TcpTransportMetrics};
use crate::tunnel::TunnelClient;
use anyhow::Result;
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use tokio::io::duplex;
use tracing::debug;

const LEGACY_BRIDGE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone)]
pub struct FastTcpTransport {
    tunnel: TunnelClient,
}

impl FastTcpTransport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self {
            tunnel: TunnelClient::new(outbound, auth),
        }
    }

    pub fn from_tunnel(tunnel: TunnelClient) -> Self {
        Self { tunnel }
    }
}

impl TcpTransport for FastTcpTransport {
    fn connect<'a>(
        &'a self,
        target_host: &'a str,
        target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move {
            let tunnel = self
                .tunnel
                .connect_target_via_tunnel_with_timings(target_host, target_port)
                .await?;
            let metrics = TcpTransportMetrics {
                server_tcp_connect_ms: Some(tunnel.timings.server_tcp_connect_ms),
                tls_handshake_ms: tunnel.timings.tls_handshake_ms,
                http_upgrade_ms: Some(tunnel.timings.http_upgrade_ms),
                target_tcp_connect_ms: tunnel.timings.target_tcp_connect_ms,
            };

            let tunnel_client = self.tunnel.clone();
            let mut upstream = tunnel.stream;
            let (client_side, mut relay_side) = duplex(LEGACY_BRIDGE_BUFFER_SIZE);
            let target_host = target_host.to_owned();

            tokio::spawn(async move {
                if let Err(err) = tunnel_client
                    .relay_over_tunnel_stream(&mut relay_side, &mut upstream)
                    .await
                {
                    debug!(
                        target_host,
                        target_port,
                        error = %err,
                        "legacy framed fast_tcp bridge closed with relay error"
                    );
                }
            });

            Ok(TcpTransportConnect {
                stream: Box::new(client_side),
                metrics,
            })
        })
    }
}

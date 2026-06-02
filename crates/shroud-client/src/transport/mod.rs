pub mod balanced_tcp;
pub mod fast_tcp;
pub mod http;
pub mod tls;

use anyhow::Result;
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig, TcpTransportMode};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type BoxedIo = Box<dyn AsyncReadWrite + Send + Unpin>;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransportMetrics {
    pub server_tcp_connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    pub http_upgrade_ms: Option<u64>,
    pub target_tcp_connect_ms: u64,
}

pub struct TcpTransportConnect {
    pub stream: BoxedIo,
    pub metrics: TcpTransportMetrics,
}

pub trait TcpTransport: Send + Sync {
    fn connect<'a>(
        &'a self,
        target_host: &'a str,
        target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>>;
}

pub fn build_tcp_transport(
    mode: TcpTransportMode,
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
) -> Result<Arc<dyn TcpTransport>> {
    match mode {
        TcpTransportMode::FastTcp => Ok(Arc::new(fast_tcp::FastTcpTransport::new(outbound, auth))),
        TcpTransportMode::BalancedTcp => Ok(Arc::new(balanced_tcp::BalancedTcpTransport::new(
            outbound, auth,
        ))),
    }
}

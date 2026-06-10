pub mod raw_tcp;
pub(crate) mod tls;

use anyhow::{Result, bail};
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig, TimeoutsConfig, TransportMode};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type BoxedIo = Box<dyn AsyncReadWrite + Send + Unpin>;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransportMetrics {
    pub server_tcp_connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    pub raw_tcp_handshake_ms: Option<u64>,
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
    mode: TransportMode,
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
    timeouts: TimeoutsConfig,
) -> Result<Arc<dyn TcpTransport>> {
    match mode {
        TransportMode::RawTcp => Ok(Arc::new(raw_tcp::RawTcpTransport::with_timeouts(
            outbound, auth, timeouts,
        )?)),
        TransportMode::Http2 => bail!("http2 transport is reserved but not implemented yet"),
        TransportMode::Http3 => bail!("http3 transport is reserved but not implemented yet"),
    }
}

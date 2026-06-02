use crate::transport::{TcpTransport, TcpTransportConnect};
use anyhow::{Result, bail};
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};

#[derive(Clone)]
pub struct Http2Transport {
    _outbound: OutboundConfig,
    _auth: ClientAuthConfig,
}

impl Http2Transport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self {
            _outbound: outbound,
            _auth: auth,
        }
    }
}

impl TcpTransport for Http2Transport {
    fn connect<'a>(
        &'a self,
        _target_host: &'a str,
        _target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move { bail!("http2 transport is not implemented yet") })
    }
}

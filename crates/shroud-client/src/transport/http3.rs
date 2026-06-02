use crate::transport::{TcpTransport, TcpTransportConnect};
use anyhow::{Result, bail};
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};

#[derive(Clone)]
pub struct Http3Transport {
    _outbound: OutboundConfig,
    _auth: ClientAuthConfig,
}

impl Http3Transport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self {
            _outbound: outbound,
            _auth: auth,
        }
    }
}

impl TcpTransport for Http3Transport {
    fn connect<'a>(
        &'a self,
        _target_host: &'a str,
        _target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move { bail!("http3 transport is reserved but not implemented yet") })
    }
}

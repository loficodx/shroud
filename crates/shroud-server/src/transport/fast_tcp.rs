use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handle_fast_tcp_connection<S>(_inbound: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    bail!("fast_tcp server transport is not implemented yet")
}

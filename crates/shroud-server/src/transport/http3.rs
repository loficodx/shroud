use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handle_http3_connection<S>(_inbound: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    bail!("http3 server transport is reserved but not implemented yet")
}

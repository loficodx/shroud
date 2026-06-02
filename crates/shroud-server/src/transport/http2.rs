use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handle_http2_connection<S>(_inbound: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    bail!("http2 server transport is not implemented yet")
}

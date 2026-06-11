use crate::auth::validate_auth_bytes;
use crate::transport::tcp_target::{TargetConnectError, connect_target};
use anyhow::{Context, Result};
use shroud_core::config::{AuthorizedClient, RelayConfig, ServerSecurityConfig, TimeoutsConfig};
use shroud_core::tcp_handshake::{
    ClientAuthProof, TcpConnectStatus, read_raw_tcp_connect_request, write_raw_tcp_connect_status,
};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

const RAW_TCP_ALLOWED_TIMESTAMP_SKEW: Duration = Duration::from_secs(120);
#[derive(Debug, Clone)]
pub struct RawTcpServerState {
    clients: Vec<AuthorizedClient>,
    request_read_timeout: Duration,
    target_connect_timeout: Duration,
    security: ServerSecurityConfig,
    relay: RelayConfig,
    nonce_cache: Arc<RawTcpNonceCache>,
}

impl RawTcpServerState {
    pub fn new(clients: Vec<AuthorizedClient>) -> Self {
        Self::with_timeouts(clients, TimeoutsConfig::default())
    }

    pub fn with_timeouts(clients: Vec<AuthorizedClient>, timeouts: TimeoutsConfig) -> Self {
        Self::with_config(clients, timeouts, ServerSecurityConfig::default())
    }

    pub fn with_config(
        clients: Vec<AuthorizedClient>,
        timeouts: TimeoutsConfig,
        security: ServerSecurityConfig,
    ) -> Self {
        Self::with_relay_config(clients, timeouts, security, RelayConfig::default())
    }

    pub fn with_relay_config(
        clients: Vec<AuthorizedClient>,
        timeouts: TimeoutsConfig,
        security: ServerSecurityConfig,
        relay: RelayConfig,
    ) -> Self {
        Self {
            clients,
            request_read_timeout: Duration::from_millis(timeouts.raw_tcp_handshake_ms),
            target_connect_timeout: Duration::from_millis(timeouts.target_connect_ms),
            security,
            relay,
            nonce_cache: Arc::new(RawTcpNonceCache::new(
                RAW_TCP_ALLOWED_TIMESTAMP_SKEW.saturating_mul(2),
            )),
        }
    }
}

pub async fn handle_raw_tcp_connection<S>(
    mut inbound: S,
    peer: SocketAddr,
    state: RawTcpServerState,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = match timeout(
        state.request_read_timeout,
        read_raw_tcp_connect_request(&mut inbound),
    )
    .await
    {
        Err(_) => {
            let _ =
                write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::InvalidRequest).await;
            return Err(anyhow::anyhow!("timed out reading raw_tcp connect request"));
        }
        Ok(Ok(req)) => req,
        Ok(Err(err)) => {
            let _ =
                write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::InvalidRequest).await;
            return Err(err).context("failed to read raw_tcp connect request");
        }
    };

    if !verify_raw_tcp_auth(&state, &req.auth).await? {
        write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::AuthFailed)
            .await
            .context("failed to write raw_tcp auth failure status")?;
        debug!(
            %peer,
            target_host = %req.host,
            target_port = req.port,
            auth_result = "failed",
            close_reason = "auth_failed",
            "raw_tcp request rejected"
        );
        return Ok(());
    }

    let connected_target = match connect_target(
        &req.host,
        req.port,
        &state.security,
        state.target_connect_timeout,
    )
    .await
    {
        Err(TargetConnectError::Timeout { connect_ms }) => {
            write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::ConnectFailed)
                .await
                .context("failed to write raw_tcp target timeout status")?;
            debug!(
                %peer,
                target_host = %req.host,
                target_port = req.port,
                auth_result = "ok",
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_connect_timeout",
                "raw_tcp target connect timed out"
            );
            return Ok(());
        }
        Err(TargetConnectError::Forbidden { reason, connect_ms }) => {
            write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::Forbidden)
                .await
                .context("failed to write raw_tcp target ACL status")?;
            debug!(
                %peer,
                target_host = %req.host,
                target_port = req.port,
                auth_result = "ok",
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_forbidden",
                reason,
                "raw_tcp target blocked by ACL"
            );
            return Ok(());
        }
        Err(err) => {
            let connect_ms = err.connect_ms();
            write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::ConnectFailed)
                .await
                .context("failed to write raw_tcp target failure status")?;
            debug!(
                %peer,
                target_host = %req.host,
                target_port = req.port,
                auth_result = "ok",
                target_tcp_connect_ms = connect_ms,
                close_reason = "target_connect_failed",
                error = %err,
                "raw_tcp target connect failed"
            );
            return Ok(());
        }
        Ok(connected_target) => connected_target,
    };

    let mut target = connected_target.stream;
    target.set_nodelay(true).with_context(|| {
        format!(
            "failed to enable TCP_NODELAY for raw_tcp target {}:{}",
            req.host, req.port
        )
    })?;

    write_raw_tcp_connect_status(&mut inbound, TcpConnectStatus::Ok)
        .await
        .context("failed to write raw_tcp OK status")?;

    let target_tcp_connect_ms = connected_target.connect_ms;
    let relay_started = Instant::now();
    let (bytes_up, bytes_down) = tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut target,
        state.relay.upload_buffer_size,
        state.relay.download_buffer_size,
    )
    .await
    .context("raw_tcp raw relay failed")?;

    debug!(
        %peer,
        target_host = %req.host,
        target_port = req.port,
        auth_result = "ok",
        target_tcp_connect_ms,
        relay_duration_ms = elapsed_millis(relay_started.elapsed()),
        relay_bytes_up = bytes_up,
        relay_bytes_down = bytes_down,
        close_reason = "closed",
        "raw_tcp server relay closed"
    );

    Ok(())
}

async fn verify_raw_tcp_auth(state: &RawTcpServerState, auth: &ClientAuthProof) -> Result<bool> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs() as i64;
    let allowed_skew = RAW_TCP_ALLOWED_TIMESTAMP_SKEW.as_secs() as i64;
    if (now - auth.timestamp).abs() > allowed_skew {
        return Ok(false);
    }

    if !validate_auth_bytes(
        &state.clients,
        &auth.client_id,
        &auth.nonce,
        auth.timestamp,
        &auth.auth_tag,
    ) {
        return Ok(false);
    }

    Ok(state
        .nonce_cache
        .insert_unique(&auth.client_id, &auth.nonce)
        .await)
}

#[derive(Debug, Clone, Eq)]
struct RawTcpNonceKey {
    client_id: String,
    nonce: Vec<u8>,
}

impl PartialEq for RawTcpNonceKey {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id && self.nonce == other.nonce
    }
}

impl Hash for RawTcpNonceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client_id.hash(state);
        self.nonce.hash(state);
    }
}

#[derive(Debug)]
struct RawTcpNonceCache {
    ttl: Duration,
    entries: Mutex<HashMap<RawTcpNonceKey, Instant>>,
}

impl RawTcpNonceCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn insert_unique(&self, client_id: &str, nonce: &[u8]) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_key, expires_at| *expires_at > now);

        let key = RawTcpNonceKey {
            client_id: client_id.to_string(),
            nonce: nonce.to_vec(),
        };
        if entries.contains_key(&key) {
            return false;
        }

        entries.insert(key, now + self.ttl);
        true
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::auth::compute_auth_tag_bytes;
    use shroud_core::tcp_handshake::{
        ClientAuthProof, TcpConnectRequest, read_raw_tcp_connect_status,
        write_raw_tcp_connect_request,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const CLIENT_SECRET: &str = "test-secret";

    fn clients() -> Vec<AuthorizedClient> {
        vec![AuthorizedClient {
            name: None,
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            created_at: None,
        }]
    }

    fn state() -> RawTcpServerState {
        RawTcpServerState::with_config(
            clients(),
            TimeoutsConfig::default(),
            ServerSecurityConfig {
                deny_private_ips: false,
                allow_ports: Vec::new(),
            },
        )
    }

    fn auth_proof(secret: &str) -> ClientAuthProof {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nonce = vec![7u8; 16];
        let auth_tag =
            compute_auth_tag_bytes(secret.as_bytes(), &nonce, timestamp, CLIENT_ID).unwrap();
        ClientAuthProof::new(CLIENT_ID, timestamp, nonce, auth_tag)
    }

    #[tokio::test]
    async fn relays_raw_bytes_after_ok_status() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target = tokio::spawn(async move {
            let (mut socket, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.unwrap();
        });

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let server = tokio::spawn(handle_raw_tcp_connection(server, peer, state()));

        write_raw_tcp_connect_request(
            &mut client,
            &TcpConnectRequest::new("127.0.0.1", target_port, auth_proof(CLIENT_SECRET)),
        )
        .await
        .unwrap();
        let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
        assert_eq!(status, TcpConnectStatus::Ok);

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        client.shutdown().await.unwrap();

        server.await.unwrap().unwrap();
        target.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_auth() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let server = tokio::spawn(handle_raw_tcp_connection(server, peer, state()));

        write_raw_tcp_connect_request(
            &mut client,
            &TcpConnectRequest::new("127.0.0.1", 443, auth_proof("wrong-secret")),
        )
        .await
        .unwrap();
        let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
        assert_eq!(status, TcpConnectStatus::AuthFailed);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn times_out_when_connect_request_stalls() {
        let (_client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let state = RawTcpServerState::with_timeouts(
            clients(),
            TimeoutsConfig {
                raw_tcp_handshake_ms: 10,
                ..TimeoutsConfig::default()
            },
        );

        let err = handle_raw_tcp_connection(server, peer, state)
            .await
            .expect_err("raw_tcp request read should time out");

        assert!(
            err.to_string()
                .contains("timed out reading raw_tcp connect request")
        );
    }

    #[tokio::test]
    async fn returns_connect_failed_when_target_is_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        drop(listener);

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let server = tokio::spawn(handle_raw_tcp_connection(server, peer, state()));

        write_raw_tcp_connect_request(
            &mut client,
            &TcpConnectRequest::new("127.0.0.1", target_port, auth_proof(CLIENT_SECRET)),
        )
        .await
        .unwrap();
        let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
        assert_eq!(status, TcpConnectStatus::ConnectFailed);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn returns_forbidden_when_target_ip_is_denied_by_acl() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let server = tokio::spawn(handle_raw_tcp_connection(
            server,
            peer,
            RawTcpServerState::new(clients()),
        ));

        write_raw_tcp_connect_request(
            &mut client,
            &TcpConnectRequest::new("127.0.0.1", 443, auth_proof(CLIENT_SECRET)),
        )
        .await
        .unwrap();
        let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
        assert_eq!(status, TcpConnectStatus::Forbidden);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn returns_forbidden_when_target_port_is_not_allowed() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let state = RawTcpServerState::with_config(
            clients(),
            TimeoutsConfig::default(),
            ServerSecurityConfig {
                deny_private_ips: false,
                allow_ports: vec![443],
            },
        );
        let server = tokio::spawn(handle_raw_tcp_connection(server, peer, state));

        write_raw_tcp_connect_request(
            &mut client,
            &TcpConnectRequest::new("203.0.113.7", 80, auth_proof(CLIENT_SECRET)),
        )
        .await
        .unwrap();
        let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
        assert_eq!(status, TcpConnectStatus::Forbidden);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_replayed_nonce() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        drop(listener);

        let state = state();
        let proof = auth_proof(CLIENT_SECRET);

        for expected_status in [
            TcpConnectStatus::ConnectFailed,
            TcpConnectStatus::AuthFailed,
        ] {
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let peer = "127.0.0.1:12345".parse().unwrap();
            let server = tokio::spawn(handle_raw_tcp_connection(server, peer, state.clone()));

            write_raw_tcp_connect_request(
                &mut client,
                &TcpConnectRequest::new("127.0.0.1", target_port, proof.clone()),
            )
            .await
            .unwrap();
            let status = read_raw_tcp_connect_status(&mut client).await.unwrap();
            assert_eq!(status, expected_status);

            server.await.unwrap().unwrap();
        }
    }
}

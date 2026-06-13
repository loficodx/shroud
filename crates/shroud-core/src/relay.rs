//! Shared relay helpers live here.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCloseReason {
    Closed,
    IdleTimeout,
}

impl RelayCloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IdleTimeout => "idle_timeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleRelayStats {
    pub a_to_b_bytes: u64,
    pub b_to_a_bytes: u64,
    pub close_reason: RelayCloseReason,
}

pub async fn copy_bidirectional_with_sizes_and_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b_buffer_size: usize,
    b_to_a_buffer_size: usize,
    idle_timeout: Duration,
) -> io::Result<IdleRelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));
    let a_to_b_bytes = Arc::new(AtomicU64::new(0));
    let b_to_a_bytes = Arc::new(AtomicU64::new(0));
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a_to_b = copy_one_direction(
        &mut a_read,
        &mut b_write,
        a_to_b_buffer_size,
        started,
        last_activity_ms.clone(),
        a_to_b_bytes.clone(),
    );
    let b_to_a = copy_one_direction(
        &mut b_read,
        &mut a_write,
        b_to_a_buffer_size,
        started,
        last_activity_ms.clone(),
        b_to_a_bytes.clone(),
    );
    let idle = idle_watchdog(started, last_activity_ms, idle_timeout);

    tokio::pin!(a_to_b);
    tokio::pin!(b_to_a);
    tokio::pin!(idle);

    let mut a_to_b_done = false;
    let mut b_to_a_done = false;

    loop {
        if a_to_b_done && b_to_a_done {
            return Ok(IdleRelayStats {
                a_to_b_bytes: a_to_b_bytes.load(Ordering::Relaxed),
                b_to_a_bytes: b_to_a_bytes.load(Ordering::Relaxed),
                close_reason: RelayCloseReason::Closed,
            });
        }

        tokio::select! {
            result = &mut a_to_b, if !a_to_b_done => {
                result?;
                a_to_b_done = true;
            }
            result = &mut b_to_a, if !b_to_a_done => {
                result?;
                b_to_a_done = true;
            }
            () = &mut idle => {
                return Ok(IdleRelayStats {
                    a_to_b_bytes: a_to_b_bytes.load(Ordering::Relaxed),
                    b_to_a_bytes: b_to_a_bytes.load(Ordering::Relaxed),
                    close_reason: RelayCloseReason::IdleTimeout,
                });
            }
        }
    }
}

async fn copy_one_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
    started: Instant,
    last_activity_ms: Arc<AtomicU64>,
    byte_counter: Arc<AtomicU64>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buffer_size];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        writer.write_all(&buf[..n]).await?;
        byte_counter.fetch_add(n as u64, Ordering::Relaxed);
        last_activity_ms.store(elapsed_millis(started.elapsed()), Ordering::Relaxed);
    }
}

async fn idle_watchdog(started: Instant, last_activity_ms: Arc<AtomicU64>, idle_timeout: Duration) {
    let idle_timeout_ms = elapsed_millis(idle_timeout);
    loop {
        let last_ms = last_activity_ms.load(Ordering::Relaxed);
        let now_ms = elapsed_millis(started.elapsed());
        let idle_ms = now_ms.saturating_sub(last_ms);
        if idle_ms >= idle_timeout_ms {
            return;
        }

        tokio::time::sleep(Duration::from_millis(idle_timeout_ms - idle_ms)).await;
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_relay_transfers_both_directions_until_closed() {
        let (mut left_app, mut left_relay) = tokio::io::duplex(4096);
        let (mut right_relay, mut right_app) = tokio::io::duplex(4096);

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_sizes_and_idle_timeout(
                &mut left_relay,
                &mut right_relay,
                1024,
                1024,
                Duration::from_secs(5),
            )
            .await
        });

        left_app.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        right_app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        right_app.write_all(b"pong").await.unwrap();
        left_app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        left_app.shutdown().await.unwrap();
        right_app.shutdown().await.unwrap();

        let stats = relay.await.unwrap().unwrap();
        assert_eq!(stats.a_to_b_bytes, 4);
        assert_eq!(stats.b_to_a_bytes, 4);
        assert_eq!(stats.close_reason, RelayCloseReason::Closed);
    }

    #[tokio::test]
    async fn idle_relay_closes_when_no_bytes_move() {
        let (_left_app, mut left_relay) = tokio::io::duplex(4096);
        let (mut right_relay, _right_app) = tokio::io::duplex(4096);

        let stats = copy_bidirectional_with_sizes_and_idle_timeout(
            &mut left_relay,
            &mut right_relay,
            1024,
            1024,
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert_eq!(stats.a_to_b_bytes, 0);
        assert_eq!(stats.b_to_a_bytes, 0);
        assert_eq!(stats.close_reason, RelayCloseReason::IdleTimeout);
    }
}

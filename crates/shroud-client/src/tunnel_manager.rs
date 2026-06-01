use crate::tunnel::{TunnelClient, TunnelStream};
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{
    FrameCommand, FrameType, encode_tcp_connect_payload, read_frame, write_frame,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

const WRITER_CHANNEL_CAPACITY: usize = 128;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD: Duration = Duration::from_millis(1);
const TCP_CONNECT_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const STREAM_SLOT_RETRY_DELAY: Duration = Duration::from_millis(25);
const SCALE_DOWN_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const METRICS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const LATENCY_WINDOW_CAPACITY: usize = 512;
const DATA_FRAMES_BEFORE_CONTROL_CHECK: usize = 8;
const WRITER_DRR_QUANTUM_BYTES: usize = 64 * 1024;
const RECENTLY_CLOSED_STREAM_TTL: Duration = Duration::from_secs(30);
const CONNECT_OK_FLAG: u16 = 0x0001;

type StreamTx = mpsc::Sender<StreamEvent>;

#[derive(Debug, PartialEq, Eq)]
enum StreamEvent {
    Connected,
    Data(Bytes),
    RemoteClosed,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
    LocalWriteClosed,
    RemoteWriteClosed,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    LocalClosed,
    RemoteClosed,
    ProtocolError,
    ConnectFailed,
    ReceiverDropped,
    TunnelBroken,
}

#[derive(Debug, Clone)]
struct ClosedStreamInfo {
    closed_at: Instant,
    reason: CloseReason,
    bytes_up: u64,
    bytes_down: u64,
    last_state: StreamState,
}

struct TunnelMetrics {
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    streams_opened: AtomicU64,
    streams_closed: AtomicU64,
    late_data: AtomicU64,
    unknown_stream_data: AtomicU64,
    late_close: AtomicU64,
    unknown_stream_close: AtomicU64,
    writer_wait: LatencyWindow,
    write_frame_duration: LatencyWindow,
}

struct LatencyWindow {
    samples: Mutex<VecDeque<u64>>,
    capacity: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct LatencySnapshot {
    p50_ms: u64,
    p95_ms: u64,
    samples: usize,
}

#[derive(Clone)]
struct WriterChannels {
    control_tx: mpsc::Sender<WriterCommand>,
    data_tx: mpsc::Sender<WriterCommand>,
    recent_writer_wait_ms: Arc<AtomicU64>,
    flow_control: Arc<TunnelFlowControl>,
    metrics: Arc<TunnelMetrics>,
}

struct WriterCommand {
    frame: FrameCommand,
    _flow_permit: Option<FlowPermit>,
}

struct FlowPermit {
    _stream_bytes: Option<OwnedSemaphorePermit>,
    _tunnel_bytes: Option<OwnedSemaphorePermit>,
    _stream_frame: OwnedSemaphorePermit,
}

struct StreamFlowControl {
    bytes: Arc<Semaphore>,
    frames: Arc<Semaphore>,
}

struct TunnelFlowControl {
    max_buffer_per_stream_bytes: usize,
    max_pending_frames_per_stream: usize,
    tunnel_bytes: Arc<Semaphore>,
    streams: Mutex<HashMap<u64, Arc<StreamFlowControl>>>,
}

impl TunnelMetrics {
    fn new() -> Self {
        Self {
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_closed: AtomicU64::new(0),
            late_data: AtomicU64::new(0),
            unknown_stream_data: AtomicU64::new(0),
            late_close: AtomicU64::new(0),
            unknown_stream_close: AtomicU64::new(0),
            writer_wait: LatencyWindow::new(LATENCY_WINDOW_CAPACITY),
            write_frame_duration: LatencyWindow::new(LATENCY_WINDOW_CAPACITY),
        }
    }

    async fn record_writer_wait(&self, wait_ms: u64) {
        self.writer_wait.record(wait_ms).await;
    }

    async fn record_write_frame_duration(&self, duration_ms: u64) {
        self.write_frame_duration.record(duration_ms).await;
    }
}

impl LatencyWindow {
    fn new(capacity: usize) -> Self {
        Self {
            samples: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    async fn record(&self, value: u64) {
        let mut samples = self.samples.lock().await;
        if samples.len() == self.capacity {
            samples.pop_front();
        }
        samples.push_back(value);
    }

    async fn snapshot(&self) -> LatencySnapshot {
        let mut samples = self
            .samples
            .lock()
            .await
            .iter()
            .copied()
            .collect::<Vec<_>>();
        if samples.is_empty() {
            return LatencySnapshot::default();
        }

        samples.sort_unstable();
        LatencySnapshot {
            p50_ms: percentile(&samples, 50),
            p95_ms: percentile(&samples, 95),
            samples: samples.len(),
        }
    }
}

fn percentile(sorted_samples: &[u64], percentile: usize) -> u64 {
    let index = sorted_samples
        .len()
        .saturating_sub(1)
        .saturating_mul(percentile)
        / 100;
    sorted_samples[index]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelState {
    Connecting,
    Connected,
    Disconnected,
    Retired,
}

impl TunnelState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Connecting => 0,
            Self::Connected => 1,
            Self::Disconnected => 2,
            Self::Retired => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Connected,
            2 => Self::Disconnected,
            3 => Self::Retired,
            _ => Self::Connecting,
        }
    }
}

#[derive(Clone)]
pub struct TunnelPool {
    tunnels: Arc<Mutex<Vec<Arc<TunnelManager>>>>,
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
    min_tunnels: usize,
    max_tunnels: usize,
    max_streams_per_tunnel: usize,
    stream_slot_wait_timeout: Duration,
    scale_up_writer_wait_ms: u64,
    scale_up_queue_depth_ratio: f64,
    scale_down_idle: Duration,
    next_tunnel_id: Arc<AtomicUsize>,
    scale_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<TunnelManagerInner>,
}

struct TunnelManagerInner {
    tunnel_id: usize,
    tunnel: TunnelClient,
    writer_tx: Mutex<Option<WriterChannels>>,
    flow_control: Arc<TunnelFlowControl>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    next_stream_id: AtomicU64,
    state: AtomicU8,
    generation: AtomicU64,
    reconnecting: AtomicBool,
    recent_writer_wait_ms: Arc<AtomicU64>,
    recent_write_frame_duration_ms: AtomicU64,
    last_pong_at_ms: AtomicU64,
    last_ping_sent_at_ms: AtomicU64,
    recent_pong_rtt_ms: AtomicU64,
    idle_since_ms: AtomicU64,
    metrics: Arc<TunnelMetrics>,
    stream_slots: Arc<Semaphore>,
    max_stream_slots: usize,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
    reconnect_enabled: AtomicBool,
}

pub struct TunnelStreamHandle {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    opened_at: Instant,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: Arc<TunnelFlowControl>,
    inbound_rx: mpsc::Receiver<StreamEvent>,
    closed: Arc<AtomicBool>,
    _stream_slot: Option<OwnedSemaphorePermit>,
}

pub struct TunnelStreamReadHalf {
    inbound_rx: mpsc::Receiver<StreamEvent>,
}

pub struct TunnelStreamWriteHalf {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: Arc<TunnelFlowControl>,
    closed: Arc<AtomicBool>,
    _stream_slot: Option<OwnedSemaphorePermit>,
}

struct TunnelSlot {
    tunnel: Arc<TunnelManager>,
    permit: OwnedSemaphorePermit,
}

impl TunnelPool {
    pub async fn connect(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        let min_tunnels = outbound.effective_min_tunnels();
        let max_tunnels = outbound.effective_max_tunnels();
        let max_streams_per_tunnel = outbound.max_streams_per_tunnel.max(1);
        let stream_slot_wait_timeout =
            Duration::from_millis(outbound.stream_slot_wait_timeout_ms.max(1));
        let scale_up_writer_wait_ms = outbound.scale_up_writer_wait_ms;
        let scale_up_queue_depth_ratio = outbound.scale_up_queue_depth_ratio;
        let scale_down_idle = Duration::from_secs(outbound.scale_down_idle_secs.max(1));
        let mut tunnels = Vec::with_capacity(min_tunnels);

        for tunnel_id in 0..min_tunnels {
            let tunnel = TunnelManager::connect_with_id(
                tunnel_id,
                outbound.clone(),
                auth.clone(),
                max_streams_per_tunnel,
            )
            .await
            .with_context(|| format!("failed to connect persistent tunnel manager {tunnel_id}"))?;
            tunnels.push(Arc::new(tunnel));
        }

        info!(
            min_tunnels,
            max_tunnels,
            legacy_multiplex_tunnels = outbound.multiplex_tunnels,
            max_streams_per_tunnel,
            stream_slot_wait_timeout_ms = elapsed_millis(stream_slot_wait_timeout),
            scale_up_writer_wait_ms = outbound.scale_up_writer_wait_ms,
            scale_up_queue_depth_ratio = outbound.scale_up_queue_depth_ratio,
            scale_down_idle_secs = outbound.scale_down_idle_secs,
            max_buffer_per_stream_bytes = outbound.max_buffer_per_stream_bytes,
            max_buffer_per_tunnel_bytes = outbound.max_buffer_per_tunnel_bytes,
            max_pending_frames_per_stream = outbound.max_pending_frames_per_stream,
            "persistent tunnel pool opened"
        );

        let pool = Self {
            tunnels: Arc::new(Mutex::new(tunnels)),
            outbound,
            auth,
            min_tunnels,
            max_tunnels,
            max_streams_per_tunnel,
            stream_slot_wait_timeout,
            scale_up_writer_wait_ms,
            scale_up_queue_depth_ratio,
            scale_down_idle,
            next_tunnel_id: Arc::new(AtomicUsize::new(min_tunnels)),
            scale_lock: Arc::new(Mutex::new(())),
        };
        pool.spawn_scale_down_loop();
        pool.spawn_metrics_log_loop();
        Ok(pool)
    }

    pub async fn open_tcp_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStreamHandle> {
        let slot = self
            .select_tunnel_slot()
            .await
            .context("persistent tunnel pool has no connected tunnels with free stream slots")?;
        slot.tunnel
            .open_tcp_stream_with_slot(target_host, target_port, Some(slot.permit))
            .await
    }

    async fn select_tunnel_slot(&self) -> Option<TunnelSlot> {
        let started = Instant::now();

        loop {
            if let Some(slot) = self.try_select_tunnel_slot(false).await {
                return Some(slot);
            }

            if self.should_scale_up().await && self.try_scale_up().await.is_some() {
                continue;
            }

            if let Some(slot) = self.try_select_tunnel_slot(true).await {
                return Some(slot);
            }

            if started.elapsed() >= self.stream_slot_wait_timeout {
                warn!(
                    max_streams_per_tunnel = self.max_streams_per_tunnel,
                    min_tunnels = self.min_tunnels,
                    max_tunnels = self.max_tunnels,
                    stream_slot_wait_timeout_ms = elapsed_millis(self.stream_slot_wait_timeout),
                    "timed out waiting for free persistent tunnel stream slot"
                );
                return None;
            }

            sleep(STREAM_SLOT_RETRY_DELAY).await;
        }
    }

    #[cfg(test)]
    async fn select_tunnel(&self) -> Option<Arc<TunnelManager>> {
        self.select_tunnel_slot().await.map(|slot| slot.tunnel)
    }

    async fn try_select_tunnel_slot(&self, allow_overloaded: bool) -> Option<TunnelSlot> {
        let mut least_under_limit: Option<TunnelSelection> = None;
        let tunnels = self.tunnels.lock().await.clone();

        for tunnel in tunnels.iter() {
            if tunnel.state() != TunnelState::Connected {
                continue;
            }

            let active_streams = tunnel.active_stream_slots().await;
            if active_streams >= self.max_streams_per_tunnel {
                continue;
            }

            let recent_writer_wait_ms = tunnel.recent_writer_wait_ms();
            let recent_write_frame_duration_ms = tunnel.recent_write_frame_duration_ms();
            let writer_queue_depth_ratio = tunnel.writer_queue_depth_ratio().await;
            let overloaded = recent_writer_wait_ms >= self.scale_up_writer_wait_ms
                || recent_write_frame_duration_ms >= self.scale_up_writer_wait_ms
                || writer_queue_depth_ratio >= self.scale_up_queue_depth_ratio;
            if overloaded && !allow_overloaded {
                continue;
            }

            let score = tunnel_pressure_score(
                active_streams,
                recent_writer_wait_ms,
                recent_write_frame_duration_ms,
                writer_queue_depth_ratio,
            );
            let selection = TunnelSelection {
                tunnel: Arc::clone(tunnel),
                active_streams,
                recent_writer_wait_ms,
                recent_write_frame_duration_ms,
                writer_queue_depth_ratio,
                score,
            };

            if least_under_limit
                .as_ref()
                .map_or(true, |best| selection.score < best.score)
            {
                least_under_limit = Some(selection.clone());
            }
        }

        let selected = least_under_limit?;
        let permit = match selected.tunnel.try_acquire_stream_slot() {
            Some(permit) => permit,
            None => return None,
        };
        debug!(
            selected_tunnel_id = selected.tunnel.tunnel_id(),
            active_streams = selected.active_streams,
            recent_writer_wait_ms = selected.recent_writer_wait_ms,
            recent_write_frame_duration_ms = selected.recent_write_frame_duration_ms,
            writer_queue_depth_ratio = selected.writer_queue_depth_ratio,
            score = selected.score,
            max_streams_per_tunnel = self.max_streams_per_tunnel,
            "selected persistent tunnel for new stream"
        );
        Some(TunnelSlot {
            tunnel: selected.tunnel,
            permit,
        })
    }

    async fn should_scale_up(&self) -> bool {
        let tunnels = self.tunnels.lock().await.clone();
        if tunnels.len() >= self.max_tunnels {
            return false;
        }

        let mut connected = 0usize;
        let mut all_slots_full = true;
        for tunnel in &tunnels {
            if tunnel.state() != TunnelState::Connected {
                continue;
            }
            connected += 1;

            if tunnel.active_stream_slots().await < self.max_streams_per_tunnel {
                all_slots_full = false;
            }

            if tunnel.recent_writer_wait_ms() >= self.scale_up_writer_wait_ms
                || tunnel.recent_write_frame_duration_ms() >= self.scale_up_writer_wait_ms
                || tunnel.writer_queue_depth_ratio().await >= self.scale_up_queue_depth_ratio
            {
                return true;
            }
        }

        connected == 0 || all_slots_full
    }

    async fn try_scale_up(&self) -> Option<Arc<TunnelManager>> {
        let _guard = self.scale_lock.lock().await;
        {
            let tunnels = self.tunnels.lock().await;
            if tunnels.len() >= self.max_tunnels {
                return None;
            }
        }

        let tunnel_id = self.next_tunnel_id.fetch_add(1, Ordering::AcqRel);
        match TunnelManager::connect_with_id(
            tunnel_id,
            self.outbound.clone(),
            self.auth.clone(),
            self.max_streams_per_tunnel,
        )
        .await
        {
            Ok(tunnel) => {
                let tunnel = Arc::new(tunnel);
                let pool_size = {
                    let mut tunnels = self.tunnels.lock().await;
                    tunnels.push(Arc::clone(&tunnel));
                    tunnels.len()
                };
                info!(
                    tunnel_id,
                    pool_size,
                    min_tunnels = self.min_tunnels,
                    max_tunnels = self.max_tunnels,
                    "persistent tunnel pool scaled up"
                );
                Some(tunnel)
            }
            Err(err) => {
                warn!(
                    tunnel_id,
                    error = %err,
                    "failed to scale up persistent tunnel pool"
                );
                None
            }
        }
    }

    fn spawn_scale_down_loop(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(SCALE_DOWN_CHECK_INTERVAL).await;
                pool.scale_down_idle_tunnels().await;
            }
        });
    }

    fn spawn_metrics_log_loop(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(METRICS_LOG_INTERVAL).await;
                pool.log_metrics_snapshot().await;
            }
        });
    }

    async fn log_metrics_snapshot(&self) {
        let tunnels = self.tunnels.lock().await.clone();
        let mut snapshots = Vec::with_capacity(tunnels.len());
        for tunnel in &tunnels {
            snapshots.push(tunnel.metrics_snapshot().await);
        }

        let tunnels_total = snapshots.len();
        let tunnels_connected = snapshots
            .iter()
            .filter(|snapshot| snapshot.state == TunnelState::Connected)
            .count();
        let active_streams_total: usize = snapshots
            .iter()
            .map(|snapshot| snapshot.active_streams)
            .sum();
        let bytes_up_total: u64 = snapshots.iter().map(|snapshot| snapshot.bytes_up).sum();
        let bytes_down_total: u64 = snapshots.iter().map(|snapshot| snapshot.bytes_down).sum();
        let streams_opened_total: u64 = snapshots
            .iter()
            .map(|snapshot| snapshot.streams_opened)
            .sum();
        let streams_closed_total: u64 = snapshots
            .iter()
            .map(|snapshot| snapshot.streams_closed)
            .sum();
        let late_data_total: u64 = snapshots.iter().map(|snapshot| snapshot.late_data).sum();
        let late_close_total: u64 = snapshots.iter().map(|snapshot| snapshot.late_close).sum();
        let unknown_stream_data_total: u64 = snapshots
            .iter()
            .map(|snapshot| snapshot.unknown_stream_data)
            .sum();
        let unknown_stream_close_total: u64 = snapshots
            .iter()
            .map(|snapshot| snapshot.unknown_stream_close)
            .sum();

        info!(
            tunnels_connected,
            tunnels_total,
            active_streams_total,
            active_streams_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.active_streams))
                .collect::<Vec<_>>(),
            writer_queue_control_depth_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.writer_queue_depth.control))
                .collect::<Vec<_>>(),
            writer_queue_data_depth_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.writer_queue_depth.data))
                .collect::<Vec<_>>(),
            writer_queue_wait_p50_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.writer_wait.p50_ms))
                .collect::<Vec<_>>(),
            writer_queue_wait_p95_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.writer_wait.p95_ms))
                .collect::<Vec<_>>(),
            writer_queue_wait_samples_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.writer_wait.samples))
                .collect::<Vec<_>>(),
            write_frame_duration_p50_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.write_frame_duration.p50_ms))
                .collect::<Vec<_>>(),
            write_frame_duration_p95_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.write_frame_duration.p95_ms))
                .collect::<Vec<_>>(),
            write_frame_duration_samples_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.write_frame_duration.samples))
                .collect::<Vec<_>>(),
            pong_rtt_ms_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.pong_rtt_ms))
                .collect::<Vec<_>>(),
            bytes_up_total,
            bytes_down_total,
            bytes_per_tunnel = ?snapshots
                .iter()
                .map(|snapshot| (snapshot.tunnel_id, snapshot.bytes_up, snapshot.bytes_down))
                .collect::<Vec<_>>(),
            streams_opened_total,
            streams_closed_total,
            late_data_total,
            late_close_total,
            unknown_stream_data_total,
            unknown_stream_close_total,
            "persistent tunnel pool metrics"
        );
    }

    async fn scale_down_idle_tunnels(&self) {
        loop {
            let candidate = {
                let tunnels = self.tunnels.lock().await;
                if tunnels.len() <= self.min_tunnels {
                    return;
                }

                tunnels
                    .iter()
                    .enumerate()
                    .filter(|(_, tunnel)| tunnel.state() == TunnelState::Connected)
                    .find_map(|(index, tunnel)| {
                        tunnel
                            .idle_for()
                            .filter(|idle_for| *idle_for >= self.scale_down_idle)
                            .map(|idle_for| (index, Arc::clone(tunnel), idle_for))
                    })
            };

            let Some((index, tunnel, idle_for)) = candidate else {
                return;
            };

            let removed = {
                let mut tunnels = self.tunnels.lock().await;
                if tunnels.len() <= self.min_tunnels || index >= tunnels.len() {
                    None
                } else if Arc::ptr_eq(&tunnels[index], &tunnel) {
                    Some(tunnels.remove(index))
                } else {
                    tunnels
                        .iter()
                        .position(|current| Arc::ptr_eq(current, &tunnel))
                        .map(|position| tunnels.remove(position))
                }
            };

            if let Some(tunnel) = removed {
                let tunnel_id = tunnel.tunnel_id();
                tunnel.retire().await;
                let pool_size = self.tunnels.lock().await.len();
                info!(
                    tunnel_id,
                    pool_size,
                    idle_ms = elapsed_millis(idle_for),
                    min_tunnels = self.min_tunnels,
                    "persistent tunnel pool scaled down idle tunnel"
                );
            } else {
                return;
            }
        }
    }
}

#[derive(Clone)]
struct TunnelSelection {
    tunnel: Arc<TunnelManager>,
    active_streams: usize,
    recent_writer_wait_ms: u64,
    recent_write_frame_duration_ms: u64,
    writer_queue_depth_ratio: f64,
    score: u64,
}

#[derive(Debug)]
struct TunnelMetricsSnapshot {
    tunnel_id: usize,
    state: TunnelState,
    active_streams: usize,
    writer_queue_depth: WriterQueueDepthSnapshot,
    writer_wait: LatencySnapshot,
    write_frame_duration: LatencySnapshot,
    pong_rtt_ms: u64,
    bytes_up: u64,
    bytes_down: u64,
    streams_opened: u64,
    streams_closed: u64,
    late_data: u64,
    late_close: u64,
    unknown_stream_data: u64,
    unknown_stream_close: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct WriterQueueDepthSnapshot {
    control: usize,
    data: usize,
}

fn tunnel_pressure_score(
    active_streams: usize,
    recent_writer_wait_ms: u64,
    recent_write_frame_duration_ms: u64,
    writer_queue_depth_ratio: f64,
) -> u64 {
    (active_streams as u64)
        .saturating_mul(1_000)
        .saturating_add((writer_queue_depth_ratio * 1_000.0).round() as u64)
        .saturating_add(recent_writer_wait_ms.saturating_mul(20))
        .saturating_add(recent_write_frame_duration_ms.saturating_mul(10))
}

impl TunnelManager {
    pub async fn connect(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        let max_streams_per_tunnel = outbound.max_streams_per_tunnel.max(1);
        Self::connect_with_id(0, outbound, auth, max_streams_per_tunnel).await
    }

    pub async fn connect_with_id(
        tunnel_id: usize,
        outbound: OutboundConfig,
        auth: ClientAuthConfig,
        max_streams_per_tunnel: usize,
    ) -> Result<Self> {
        let keepalive_interval = Duration::from_secs(outbound.keepalive_interval_secs);
        let keepalive_timeout = Duration::from_secs(outbound.keepalive_timeout_secs);
        let flow_control = Arc::new(TunnelFlowControl::new(
            outbound.max_buffer_per_stream_bytes,
            outbound.max_buffer_per_tunnel_bytes,
            outbound.max_pending_frames_per_stream,
        ));
        let metrics = Arc::new(TunnelMetrics::new());
        let tunnel = TunnelClient::new(outbound, auth);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let recently_closed_streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = Arc::new(TunnelManagerInner {
            tunnel_id,
            tunnel,
            writer_tx: Mutex::new(None),
            flow_control,
            streams,
            recently_closed_streams,
            next_stream_id: AtomicU64::new(1),
            state: AtomicU8::new(TunnelState::Connecting.as_u8()),
            generation: AtomicU64::new(0),
            reconnecting: AtomicBool::new(false),
            recent_writer_wait_ms: Arc::new(AtomicU64::new(0)),
            recent_write_frame_duration_ms: AtomicU64::new(0),
            last_pong_at_ms: AtomicU64::new(now_millis()),
            last_ping_sent_at_ms: AtomicU64::new(0),
            recent_pong_rtt_ms: AtomicU64::new(0),
            idle_since_ms: AtomicU64::new(now_millis()),
            metrics,
            stream_slots: Arc::new(Semaphore::new(max_streams_per_tunnel.max(1))),
            max_stream_slots: max_streams_per_tunnel.max(1),
            keepalive_interval,
            keepalive_timeout,
            reconnect_enabled: AtomicBool::new(true),
        });

        establish_physical_tunnel(Arc::clone(&inner))
            .await
            .with_context(|| format!("failed to open persistent physical tunnel {tunnel_id}"))?;
        tokio::spawn(keepalive_loop(Arc::clone(&inner)));

        info!(tunnel_id, "persistent physical tunnel opened");

        Ok(Self { inner })
    }

    pub fn tunnel_id(&self) -> usize {
        self.inner.tunnel_id
    }

    pub async fn active_streams(&self) -> usize {
        self.inner.streams.lock().await.len()
    }

    async fn active_stream_slots(&self) -> usize {
        let reserved = self
            .max_stream_slots()
            .saturating_sub(self.inner.stream_slots.available_permits());
        reserved.max(self.active_streams().await)
    }

    fn max_stream_slots(&self) -> usize {
        self.inner.max_stream_slots
    }

    fn try_acquire_stream_slot(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.inner.stream_slots)
            .try_acquire_owned()
            .ok()
    }

    async fn writer_queue_depth_ratio(&self) -> f64 {
        self.inner
            .current_writer_tx()
            .await
            .map(|writer_tx| writer_tx.queue_depth_ratio())
            .unwrap_or(1.0)
    }

    async fn metrics_snapshot(&self) -> TunnelMetricsSnapshot {
        let writer_queue_depth = self
            .inner
            .current_writer_tx()
            .await
            .map(|writer_tx| writer_tx.queue_depth_snapshot())
            .unwrap_or_default();
        let metrics = &self.inner.metrics;

        TunnelMetricsSnapshot {
            tunnel_id: self.inner.tunnel_id,
            state: self.state(),
            active_streams: self.active_stream_slots().await,
            writer_queue_depth,
            writer_wait: metrics.writer_wait.snapshot().await,
            write_frame_duration: metrics.write_frame_duration.snapshot().await,
            pong_rtt_ms: self.inner.recent_pong_rtt_ms.load(Ordering::Relaxed),
            bytes_up: metrics.bytes_up.load(Ordering::Relaxed),
            bytes_down: metrics.bytes_down.load(Ordering::Relaxed),
            streams_opened: metrics.streams_opened.load(Ordering::Relaxed),
            streams_closed: metrics.streams_closed.load(Ordering::Relaxed),
            late_data: metrics.late_data.load(Ordering::Relaxed),
            late_close: metrics.late_close.load(Ordering::Relaxed),
            unknown_stream_data: metrics.unknown_stream_data.load(Ordering::Relaxed),
            unknown_stream_close: metrics.unknown_stream_close.load(Ordering::Relaxed),
        }
    }

    fn idle_for(&self) -> Option<Duration> {
        if self.state() != TunnelState::Connected
            || self
                .max_stream_slots()
                .saturating_sub(self.inner.stream_slots.available_permits())
                > 0
        {
            self.inner.idle_since_ms.store(0, Ordering::Release);
            return None;
        }

        let now = now_millis();
        let mut idle_since = self.inner.idle_since_ms.load(Ordering::Acquire);
        if idle_since == 0 {
            self.inner.idle_since_ms.store(now, Ordering::Release);
            idle_since = now;
        }

        Some(Duration::from_millis(now.saturating_sub(idle_since)))
    }

    async fn retire(&self) {
        self.inner.reconnect_enabled.store(false, Ordering::Release);
        self.inner.set_state(TunnelState::Retired);
        {
            let mut writer_tx = self.inner.writer_tx.lock().await;
            *writer_tx = None;
        }
        clear_streams(
            &self.inner.streams,
            &self.inner.recently_closed_streams,
            &self.inner.flow_control,
            &self.inner.metrics,
            CloseReason::TunnelBroken,
        )
        .await;
    }

    fn state(&self) -> TunnelState {
        TunnelState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    fn recent_writer_wait_ms(&self) -> u64 {
        self.inner.recent_writer_wait_ms.load(Ordering::Relaxed)
    }

    fn recent_write_frame_duration_ms(&self) -> u64 {
        self.inner
            .recent_write_frame_duration_ms
            .load(Ordering::Relaxed)
    }

    pub async fn open_tcp_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStreamHandle> {
        self.open_tcp_stream_with_slot(target_host, target_port, None)
            .await
    }

    async fn open_tcp_stream_with_slot(
        &self,
        target_host: &str,
        target_port: u16,
        stream_slot: Option<OwnedSemaphorePermit>,
    ) -> Result<TunnelStreamHandle> {
        let stream_id = self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode TCP_CONNECT payload: {err}"))?;
        if self.state() != TunnelState::Connected {
            bail!(
                "persistent tunnel {} is not connected",
                self.inner.tunnel_id
            );
        }

        let writer_tx = self.inner.current_writer_tx().await.with_context(|| {
            format!(
                "persistent tunnel {} is not connected",
                self.inner.tunnel_id
            )
        })?;
        let (inbound_tx, mut inbound_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

        {
            let mut streams = self.inner.streams.lock().await;
            streams.insert(stream_id, inbound_tx);
            drop(streams);
            self.inner.flow_control.ensure_stream(stream_id).await;
            self.inner
                .metrics
                .streams_opened
                .fetch_add(1, Ordering::Relaxed);
            let streams = self.inner.streams.lock().await;
            self.inner.idle_since_ms.store(0, Ordering::Release);
            debug!(
                tunnel_id = self.inner.tunnel_id,
                stream_id,
                target_host,
                target_port,
                active_streams_on_tunnel = streams.len(),
                "logical TCP stream opened"
            );
        }

        if let Err(err) = send_writer_command(
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpConnect,
                stream_id,
                flags: 0,
                payload,
            },
            "TCP_CONNECT",
            self.inner.tunnel_id,
            Some(target_host),
            Some(target_port),
        )
        .await
        {
            remove_stream_with_recent(
                &self.inner.streams,
                &self.inner.recently_closed_streams,
                &self.inner.flow_control,
                &self.inner.metrics,
                stream_id,
                CloseReason::TunnelBroken,
                StreamState::Open,
            )
            .await;
            return Err(err).context("failed to queue TCP_CONNECT for persistent tunnel");
        }

        wait_for_connect_response(
            self.inner.tunnel_id,
            stream_id,
            target_host,
            target_port,
            &mut inbound_rx,
            &self.inner.streams,
            &self.inner.recently_closed_streams,
            &self.inner.flow_control,
            &self.inner.metrics,
        )
        .await?;

        Ok(TunnelStreamHandle {
            tunnel_id: self.inner.tunnel_id,
            stream_id,
            target_host: target_host.to_owned(),
            target_port,
            opened_at: Instant::now(),
            writer_tx,
            streams: Arc::clone(&self.inner.streams),
            recently_closed_streams: Arc::clone(&self.inner.recently_closed_streams),
            flow_control: Arc::clone(&self.inner.flow_control),
            inbound_rx,
            closed: Arc::new(AtomicBool::new(false)),
            _stream_slot: stream_slot,
        })
    }
}

impl TunnelManagerInner {
    async fn current_writer_tx(&self) -> Option<WriterChannels> {
        self.writer_tx.lock().await.clone()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn set_state(&self, state: TunnelState) {
        self.state.store(state.as_u8(), Ordering::Release);
    }
}

async fn establish_physical_tunnel(inner: Arc<TunnelManagerInner>) -> Result<()> {
    inner.set_state(TunnelState::Connecting);
    let stream = inner.tunnel.open_persistent_tunnel_transport().await?;
    let (read_half, write_half) = split(stream);
    let generation = inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
    let (writer_tx, control_rx, data_rx) = writer_channels(
        WRITER_CHANNEL_CAPACITY,
        Arc::clone(&inner.recent_writer_wait_ms),
        Arc::clone(&inner.flow_control),
        Arc::clone(&inner.metrics),
    );

    {
        let mut current = inner.writer_tx.lock().await;
        *current = Some(writer_tx);
    }

    inner.last_pong_at_ms.store(now_millis(), Ordering::Release);
    inner.set_state(TunnelState::Connected);

    tokio::spawn(tunnel_writer_loop(
        Arc::clone(&inner),
        generation,
        write_half,
        control_rx,
        data_rx,
    ));
    tokio::spawn(tunnel_reader_loop(
        Arc::clone(&inner),
        generation,
        read_half,
    ));

    info!(
        tunnel_id = inner.tunnel_id,
        generation, "persistent physical tunnel connected"
    );
    Ok(())
}

async fn mark_tunnel_broken(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    close_reason: &'static str,
    schedule_reconnect: bool,
) {
    if inner.generation() != generation {
        return;
    }

    let previous = TunnelState::from_u8(
        inner
            .state
            .swap(TunnelState::Disconnected.as_u8(), Ordering::AcqRel),
    );
    if previous == TunnelState::Disconnected {
        return;
    }

    {
        let mut writer_tx = inner.writer_tx.lock().await;
        *writer_tx = None;
    }

    let active_streams = clear_streams(
        &inner.streams,
        &inner.recently_closed_streams,
        &inner.flow_control,
        &inner.metrics,
        CloseReason::TunnelBroken,
    )
    .await;
    warn!(
        tunnel_id = inner.tunnel_id,
        generation,
        active_streams_on_tunnel = active_streams,
        close_reason,
        "persistent physical tunnel marked disconnected"
    );

    if schedule_reconnect && !inner.reconnecting.swap(true, Ordering::AcqRel) {
        spawn_reconnect_loop(inner);
    }
}

fn spawn_reconnect_loop(inner: Arc<TunnelManagerInner>) {
    tokio::spawn(async move {
        loop {
            sleep(TUNNEL_RECONNECT_DELAY).await;
            if !inner.reconnect_enabled.load(Ordering::Acquire) {
                inner.reconnecting.store(false, Ordering::Release);
                return;
            }
            match establish_physical_tunnel(Arc::clone(&inner)).await {
                Ok(()) => {
                    inner.reconnecting.store(false, Ordering::Release);
                    info!(
                        tunnel_id = inner.tunnel_id,
                        "persistent physical tunnel reconnected"
                    );
                    return;
                }
                Err(err) => {
                    inner.set_state(TunnelState::Disconnected);
                    warn!(
                        tunnel_id = inner.tunnel_id,
                        error = %err,
                        "persistent physical tunnel reconnect failed"
                    );
                }
            }
        }
    });
}

async fn keepalive_loop(inner: Arc<TunnelManagerInner>) {
    loop {
        sleep(inner.keepalive_interval).await;
        let state = TunnelState::from_u8(inner.state.load(Ordering::Acquire));
        if state == TunnelState::Retired {
            break;
        }
        if state != TunnelState::Connected {
            continue;
        }

        let Some(writer_tx) = inner.current_writer_tx().await else {
            continue;
        };
        let ping_sent_at_ms = now_millis();
        inner
            .last_ping_sent_at_ms
            .store(ping_sent_at_ms, Ordering::Release);
        if send_writer_command(
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::Ping,
                stream_id: 0,
                flags: 0,
                payload: Bytes::new(),
            },
            "PING",
            inner.tunnel_id,
            None,
            None,
        )
        .await
        .is_err()
        {
            mark_tunnel_broken(
                Arc::clone(&inner),
                inner.generation(),
                "keepalive_send_failed",
                true,
            )
            .await;
            continue;
        }

        sleep(inner.keepalive_timeout).await;
        if TunnelState::from_u8(inner.state.load(Ordering::Acquire)) == TunnelState::Connected
            && inner.last_pong_at_ms.load(Ordering::Acquire) < ping_sent_at_ms
        {
            warn!(
                tunnel_id = inner.tunnel_id,
                keepalive_timeout_ms = elapsed_millis(inner.keepalive_timeout),
                "persistent tunnel keepalive timed out"
            );
            mark_tunnel_broken(
                Arc::clone(&inner),
                inner.generation(),
                "keepalive_timeout",
                true,
            )
            .await;
        }
    }
}

impl TunnelStreamHandle {
    pub fn tunnel_id(&self) -> usize {
        self.tunnel_id
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    pub fn opened_at(&self) -> Instant {
        self.opened_at
    }

    pub fn into_split(self) -> (TunnelStreamReadHalf, TunnelStreamWriteHalf) {
        (
            TunnelStreamReadHalf {
                inbound_rx: self.inbound_rx,
            },
            TunnelStreamWriteHalf {
                tunnel_id: self.tunnel_id,
                stream_id: self.stream_id,
                target_host: self.target_host,
                target_port: self.target_port,
                writer_tx: self.writer_tx,
                streams: self.streams,
                recently_closed_streams: self.recently_closed_streams,
                flow_control: self.flow_control,
                closed: self.closed,
                _stream_slot: self._stream_slot,
            },
        )
    }

    pub async fn send_data(&self, bytes: Bytes) -> Result<()> {
        send_writer_command(
            &self.writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: self.stream_id,
                flags: 0,
                payload: bytes,
            },
            "TCP_DATA",
            self.tunnel_id,
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }

    pub async fn recv_data(&mut self) -> Option<Bytes> {
        recv_stream_data(&mut self.inbound_rx).await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(
            self.tunnel_id,
            self.stream_id,
            &self.writer_tx,
            &self.streams,
            &self.recently_closed_streams,
            &self.flow_control,
            &self.writer_tx.metrics,
            &self.closed,
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }
}

impl TunnelStreamReadHalf {
    pub async fn recv_data(&mut self) -> Option<Bytes> {
        recv_stream_data(&mut self.inbound_rx).await
    }
}

async fn wait_for_connect_response(
    tunnel_id: usize,
    stream_id: u64,
    target_host: &str,
    target_port: u16,
    inbound_rx: &mut mpsc::Receiver<StreamEvent>,
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: &Arc<TunnelFlowControl>,
    metrics: &Arc<TunnelMetrics>,
) -> Result<()> {
    let event = tokio::time::timeout(TCP_CONNECT_REPLY_TIMEOUT, inbound_rx.recv())
        .await
        .with_context(|| {
            format!("timed out waiting for TCP_CONNECT reply for {target_host}:{target_port}")
        })?;

    match event {
        Some(StreamEvent::Connected) => {
            debug!(
                tunnel_id,
                stream_id, target_host, target_port, "logical TCP stream connected"
            );
            Ok(())
        }
        Some(StreamEvent::Error(message)) => {
            remove_stream_with_recent(
                streams,
                recently_closed_streams,
                flow_control,
                metrics,
                stream_id,
                CloseReason::ConnectFailed,
                StreamState::Closed,
            )
            .await;
            bail!("server refused TCP_CONNECT: {message}");
        }
        Some(StreamEvent::RemoteClosed) => {
            remove_stream_with_recent(
                streams,
                recently_closed_streams,
                flow_control,
                metrics,
                stream_id,
                CloseReason::RemoteClosed,
                StreamState::RemoteWriteClosed,
            )
            .await;
            bail!("server closed stream before TCP_CONNECT completed");
        }
        Some(StreamEvent::Data(_)) => {
            remove_stream_with_recent(
                streams,
                recently_closed_streams,
                flow_control,
                metrics,
                stream_id,
                CloseReason::ProtocolError,
                StreamState::Closed,
            )
            .await;
            bail!("received TCP_DATA before TCP_CONNECT completed");
        }
        None => {
            remove_stream_with_recent(
                streams,
                recently_closed_streams,
                flow_control,
                metrics,
                stream_id,
                CloseReason::TunnelBroken,
                StreamState::Closed,
            )
            .await;
            bail!("persistent tunnel closed before TCP_CONNECT completed");
        }
    }
}

async fn recv_stream_data(inbound_rx: &mut mpsc::Receiver<StreamEvent>) -> Option<Bytes> {
    while let Some(event) = inbound_rx.recv().await {
        match event {
            StreamEvent::Data(bytes) => return Some(bytes),
            StreamEvent::Connected => {}
            StreamEvent::RemoteClosed => return None,
            StreamEvent::Error(message) => {
                debug!(error = %message, "logical TCP stream failed by peer");
                return None;
            }
        }
    }

    None
}

impl TunnelStreamWriteHalf {
    pub async fn send_data(&self, bytes: Bytes) -> Result<()> {
        send_writer_command(
            &self.writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: self.stream_id,
                flags: 0,
                payload: bytes,
            },
            "TCP_DATA",
            self.tunnel_id,
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(
            self.tunnel_id,
            self.stream_id,
            &self.writer_tx,
            &self.streams,
            &self.recently_closed_streams,
            &self.flow_control,
            &self.writer_tx.metrics,
            &self.closed,
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }

    pub async fn cleanup_local(&self) -> usize {
        self.closed.store(true, Ordering::Release);
        remove_stream_with_recent(
            &self.streams,
            &self.recently_closed_streams,
            &self.flow_control,
            &self.writer_tx.metrics,
            self.stream_id,
            CloseReason::LocalClosed,
            StreamState::Closed,
        )
        .await
    }

    pub fn tunnel_id(&self) -> usize {
        self.tunnel_id
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }
}

async fn close_stream(
    tunnel_id: usize,
    stream_id: u64,
    writer_tx: &WriterChannels,
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: &Arc<TunnelFlowControl>,
    metrics: &Arc<TunnelMetrics>,
    closed: &AtomicBool,
    target_host: Option<&str>,
    target_port: Option<u16>,
) -> Result<()> {
    if closed.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    if let Err(err) = send_writer_command(
        writer_tx,
        FrameCommand {
            frame_type: FrameType::TcpClose,
            stream_id,
            flags: 0,
            payload: Bytes::new(),
        },
        "TCP_CLOSE",
        tunnel_id,
        target_host,
        target_port,
    )
    .await
    {
        remove_stream_with_recent(
            streams,
            recently_closed_streams,
            flow_control,
            metrics,
            stream_id,
            CloseReason::TunnelBroken,
            StreamState::LocalWriteClosed,
        )
        .await;
        return Err(err).context("failed to queue TCP_CLOSE for persistent tunnel");
    }

    debug!(
        tunnel_id,
        stream_id,
        target_host = %target_host.unwrap_or("<unknown>"),
        target_port = target_port.unwrap_or_default(),
        close_reason = "client_closed",
        "logical TCP stream close queued"
    );

    Ok(())
}

async fn tunnel_writer_loop(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    mut write_half: WriteHalf<TunnelStream>,
    mut control_rx: mpsc::Receiver<WriterCommand>,
    mut data_rx: mpsc::Receiver<WriterCommand>,
) {
    let mut data_frames_since_control_check = 0usize;
    let mut data_scheduler = TunnelDataScheduler::default();
    while let Some(cmd) = recv_writer_command(
        &mut control_rx,
        &mut data_rx,
        &mut data_scheduler,
        &mut data_frames_since_control_check,
    )
    .await
    {
        let frame_type = cmd.frame.frame_type;
        let stream_id = cmd.frame.stream_id;
        let payload_len = cmd.frame.payload.len();
        let write_started = Instant::now();
        let result = write_frame(
            &mut write_half,
            frame_type,
            stream_id,
            cmd.frame.flags,
            cmd.frame.payload,
        )
        .await;
        let write_duration = write_started.elapsed();
        let write_duration_ms = elapsed_millis(write_duration);
        record_recent_writer_wait(&inner.recent_write_frame_duration_ms, write_duration_ms);
        inner
            .metrics
            .record_write_frame_duration(write_duration_ms)
            .await;
        if write_duration >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
            debug!(
                tunnel_id = inner.tunnel_id,
                generation,
                stream_id,
                frame_type = %frame_type,
                write_frame_payload_len = payload_len,
                write_frame_duration_ms = write_duration_ms,
                "persistent tunnel write_frame completed"
            );
        }
        drop(cmd._flow_permit);

        if let Err(err) = result {
            warn!(
                tunnel_id = inner.tunnel_id,
                generation,
                error = %err,
                "persistent physical tunnel closed after writer failure"
            );
            let reconnect_enabled = inner.reconnect_enabled.load(Ordering::Acquire);
            mark_tunnel_broken(
                Arc::clone(&inner),
                generation,
                "writer_failed",
                reconnect_enabled,
            )
            .await;
            break;
        }
    }

    debug!(
        tunnel_id = inner.tunnel_id,
        generation, "persistent tunnel writer finished"
    );
}

async fn tunnel_reader_loop(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    mut read_half: ReadHalf<TunnelStream>,
) {
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(frame) => frame,
            Err(err) => {
                warn!(
                    tunnel_id = inner.tunnel_id,
                    generation,
                    error = %err,
                    "persistent physical tunnel closed after reader failure"
                );
                let reconnect_enabled = inner.reconnect_enabled.load(Ordering::Acquire);
                mark_tunnel_broken(
                    Arc::clone(&inner),
                    generation,
                    "reader_failed",
                    reconnect_enabled,
                )
                .await;
                break;
            }
        };

        match frame.frame_type {
            FrameType::TcpData => {
                inner
                    .metrics
                    .bytes_down
                    .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                let tx = {
                    let streams = inner.streams.lock().await;
                    streams.get(&frame.stream_id).cloned()
                };

                if let Some(tx) = tx {
                    if tx.send(StreamEvent::Data(frame.payload)).await.is_err() {
                        let active_streams = remove_stream_with_recent(
                            &inner.streams,
                            &inner.recently_closed_streams,
                            &inner.flow_control,
                            &inner.metrics,
                            frame.stream_id,
                            CloseReason::ReceiverDropped,
                            StreamState::Open,
                        )
                        .await;
                        debug!(
                            tunnel_id = inner.tunnel_id,
                            stream_id = frame.stream_id,
                            active_streams_on_tunnel = active_streams,
                            "logical TCP stream removed after inbound receiver closed"
                        );
                    }
                } else {
                    log_unknown_or_recently_closed_tcp_data(
                        &inner,
                        frame.stream_id,
                        frame.payload.len(),
                    )
                    .await;
                }
            }
            FrameType::TcpClose => {
                let tx = {
                    let mut streams = inner.streams.lock().await;
                    let tx = streams.remove(&frame.stream_id);
                    let active_streams = streams.len();
                    drop(streams);
                    if tx.is_some() {
                        inner.metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
                        inner.flow_control.remove_stream(frame.stream_id).await;
                        remember_closed_stream(
                            &inner.recently_closed_streams,
                            frame.stream_id,
                            CloseReason::RemoteClosed,
                            StreamState::RemoteWriteClosed,
                        )
                        .await;
                    }
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        active_streams_on_tunnel = active_streams,
                        close_reason = "remote_closed",
                        "logical TCP stream closed by peer"
                    );
                    tx
                };

                if let Some(tx) = tx {
                    let _ = tx.send(StreamEvent::RemoteClosed).await;
                } else {
                    log_unknown_or_recently_closed_tcp_close(&inner, frame.stream_id).await;
                }
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let tx = {
                    let mut streams = inner.streams.lock().await;
                    let tx = streams.remove(&frame.stream_id);
                    let active_streams = streams.len();
                    drop(streams);
                    if tx.is_some() {
                        inner.metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
                        inner.flow_control.remove_stream(frame.stream_id).await;
                        remember_closed_stream(
                            &inner.recently_closed_streams,
                            frame.stream_id,
                            CloseReason::ProtocolError,
                            StreamState::Closed,
                        )
                        .await;
                    }
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        active_streams_on_tunnel = active_streams,
                        error = %message,
                        close_reason = "protocol_error",
                        "logical TCP stream failed by peer"
                    );
                    tx
                };

                if let Some(tx) = tx {
                    let _ = tx.send(StreamEvent::Error(message)).await;
                }
            }
            FrameType::TcpConnect => {
                let is_connected = (frame.flags & CONNECT_OK_FLAG) != 0;
                let tx = if is_connected {
                    let streams = inner.streams.lock().await;
                    streams.get(&frame.stream_id).cloned()
                } else {
                    let mut streams = inner.streams.lock().await;
                    let tx = streams.remove(&frame.stream_id);
                    drop(streams);
                    if tx.is_some() {
                        inner.metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
                        inner.flow_control.remove_stream(frame.stream_id).await;
                        remember_closed_stream(
                            &inner.recently_closed_streams,
                            frame.stream_id,
                            CloseReason::ConnectFailed,
                            StreamState::Closed,
                        )
                        .await;
                    }
                    tx
                };

                let event = if is_connected {
                    StreamEvent::Connected
                } else {
                    StreamEvent::Error(format!(
                        "server returned TCP_CONNECT without success flag; flags={}",
                        frame.flags
                    ))
                };

                if let Some(tx) = tx {
                    if tx.send(event).await.is_err() {
                        let active_streams = remove_stream_with_recent(
                            &inner.streams,
                            &inner.recently_closed_streams,
                            &inner.flow_control,
                            &inner.metrics,
                            frame.stream_id,
                            CloseReason::ReceiverDropped,
                            StreamState::Open,
                        )
                        .await;
                        debug!(
                            tunnel_id = inner.tunnel_id,
                            stream_id = frame.stream_id,
                            active_streams_on_tunnel = active_streams,
                            "logical TCP stream removed after connect receiver closed"
                        );
                    }
                } else {
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        flags = frame.flags,
                        "dropping TCP_CONNECT response for unknown stream"
                    );
                }
                debug!(
                    tunnel_id = inner.tunnel_id,
                    stream_id = frame.stream_id,
                    flags = frame.flags,
                    "persistent tunnel TCP_CONNECT response received"
                );
            }
            FrameType::Pong => {
                let now = now_millis();
                let last_ping_sent_at_ms = inner.last_ping_sent_at_ms.load(Ordering::Acquire);
                inner.last_pong_at_ms.store(now, Ordering::Release);
                if last_ping_sent_at_ms != 0 {
                    inner
                        .recent_pong_rtt_ms
                        .store(now.saturating_sub(last_ping_sent_at_ms), Ordering::Release);
                }
                debug!(
                    tunnel_id = inner.tunnel_id,
                    generation, "persistent tunnel PONG received"
                );
            }
            other => {
                debug!(
                    tunnel_id = inner.tunnel_id,
                    stream_id = frame.stream_id,
                    frame_type = %other,
                    "ignoring unsupported frame on persistent tunnel"
                );
            }
        }
    }
}

async fn send_writer_command(
    writer_tx: &WriterChannels,
    cmd: FrameCommand,
    operation: &'static str,
    tunnel_id: usize,
    target_host: Option<&str>,
    target_port: Option<u16>,
) -> Result<()> {
    let frame_type = cmd.frame_type;
    let stream_id = cmd.stream_id;
    let payload_len = cmd.payload.len();
    let flow_permit = if !is_control_frame(frame_type) {
        Some(
            writer_tx
                .flow_control
                .acquire(stream_id, payload_len)
                .await
                .with_context(|| {
                    format!("failed to reserve writer buffer for stream {stream_id}")
                })?,
        )
    } else {
        None
    };
    let sender = writer_tx.sender_for(frame_type);
    let queue = writer_queue_metrics(sender);
    let started = Instant::now();

    sender
        .send(WriterCommand {
            frame: cmd,
            _flow_permit: flow_permit,
        })
        .await
        .with_context(|| format!("failed to queue {operation} for persistent tunnel"))?;

    let wait = started.elapsed();
    let wait_ms = elapsed_millis(wait);
    record_recent_writer_wait(&writer_tx.recent_writer_wait_ms, wait_ms);
    writer_tx.metrics.record_writer_wait(wait_ms).await;
    if frame_type == FrameType::TcpData {
        writer_tx
            .metrics
            .bytes_up
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            tunnel_id,
            stream_id,
            target_host = %target_host.unwrap_or("<unknown>"),
            target_port = target_port.unwrap_or_default(),
            frame_type = %frame_type,
            payload_len,
            writer_queue_capacity = queue.capacity,
            writer_queue_available = queue.available,
            writer_queue_depth = queue.depth,
            writer_channel_send_wait_ms = wait_ms,
            "persistent tunnel writer channel send waited"
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct WriterQueueMetrics {
    capacity: usize,
    available: usize,
    depth: usize,
}

fn writer_queue_metrics(sender: &mpsc::Sender<WriterCommand>) -> WriterQueueMetrics {
    let capacity = sender.max_capacity();
    let available = sender.capacity();
    WriterQueueMetrics {
        capacity,
        available,
        depth: capacity.saturating_sub(available),
    }
}

fn writer_channels(
    capacity: usize,
    recent_writer_wait_ms: Arc<AtomicU64>,
    flow_control: Arc<TunnelFlowControl>,
    metrics: Arc<TunnelMetrics>,
) -> (
    WriterChannels,
    mpsc::Receiver<WriterCommand>,
    mpsc::Receiver<WriterCommand>,
) {
    let (control_tx, control_rx) = mpsc::channel(capacity);
    let (data_tx, data_rx) = mpsc::channel(capacity);
    (
        WriterChannels {
            control_tx,
            data_tx,
            recent_writer_wait_ms,
            flow_control,
            metrics,
        },
        control_rx,
        data_rx,
    )
}

impl WriterChannels {
    fn sender_for(&self, frame_type: FrameType) -> &mpsc::Sender<WriterCommand> {
        if is_control_frame(frame_type) {
            &self.control_tx
        } else {
            &self.data_tx
        }
    }

    fn queue_depth_ratio(&self) -> f64 {
        writer_queue_depth_ratio(&self.control_tx).max(writer_queue_depth_ratio(&self.data_tx))
    }

    fn queue_depth_snapshot(&self) -> WriterQueueDepthSnapshot {
        WriterQueueDepthSnapshot {
            control: writer_queue_metrics(&self.control_tx).depth,
            data: writer_queue_metrics(&self.data_tx).depth,
        }
    }
}

fn writer_queue_depth_ratio(sender: &mpsc::Sender<WriterCommand>) -> f64 {
    let metrics = writer_queue_metrics(sender);
    if metrics.capacity == 0 {
        0.0
    } else {
        metrics.depth as f64 / metrics.capacity as f64
    }
}

fn is_control_frame(frame_type: FrameType) -> bool {
    matches!(
        frame_type,
        FrameType::Ping
            | FrameType::Pong
            | FrameType::TcpConnect
            | FrameType::UdpAssociateRequest
            | FrameType::UdpAssociateResponse
            | FrameType::ErrorFrame
    )
}

impl TunnelFlowControl {
    fn new(
        max_buffer_per_stream_bytes: usize,
        max_buffer_per_tunnel_bytes: usize,
        max_pending_frames_per_stream: usize,
    ) -> Self {
        Self {
            max_buffer_per_stream_bytes,
            max_pending_frames_per_stream,
            tunnel_bytes: Arc::new(Semaphore::new(max_buffer_per_tunnel_bytes)),
            streams: Mutex::new(HashMap::new()),
        }
    }

    async fn ensure_stream(&self, stream_id: u64) -> Arc<StreamFlowControl> {
        let mut streams = self.streams.lock().await;
        streams
            .entry(stream_id)
            .or_insert_with(|| {
                Arc::new(StreamFlowControl {
                    bytes: Arc::new(Semaphore::new(self.max_buffer_per_stream_bytes)),
                    frames: Arc::new(Semaphore::new(self.max_pending_frames_per_stream)),
                })
            })
            .clone()
    }

    async fn acquire(&self, stream_id: u64, payload_len: usize) -> Result<FlowPermit> {
        let stream = self.ensure_stream(stream_id).await;
        let payload_len = payload_len.min(u32::MAX as usize) as u32;
        let stream_bytes = if payload_len == 0 {
            None
        } else {
            Some(
                Arc::clone(&stream.bytes)
                    .acquire_many_owned(payload_len)
                    .await?,
            )
        };
        let tunnel_bytes = if payload_len == 0 {
            None
        } else {
            Some(
                Arc::clone(&self.tunnel_bytes)
                    .acquire_many_owned(payload_len)
                    .await?,
            )
        };
        let stream_frame = Arc::clone(&stream.frames).acquire_owned().await?;

        Ok(FlowPermit {
            _stream_bytes: stream_bytes,
            _tunnel_bytes: tunnel_bytes,
            _stream_frame: stream_frame,
        })
    }

    async fn remove_stream(&self, stream_id: u64) {
        self.streams.lock().await.remove(&stream_id);
    }
}

#[derive(Default)]
struct TunnelDataScheduler {
    streams: HashMap<u64, StreamQueue>,
    ready_streams: VecDeque<u64>,
}

struct StreamQueue {
    queue: VecDeque<WriterCommand>,
    queued_bytes: usize,
    deficit: usize,
}

impl TunnelDataScheduler {
    fn is_empty(&self) -> bool {
        self.ready_streams.is_empty()
    }

    fn enqueue(&mut self, cmd: WriterCommand) {
        let stream_id = cmd.frame.stream_id;
        let payload_len = cmd.frame.payload.len();
        let stream_queue = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamQueue {
                queue: VecDeque::new(),
                queued_bytes: 0,
                deficit: 0,
            });
        let was_empty = stream_queue.queue.is_empty();
        stream_queue.queued_bytes = stream_queue.queued_bytes.saturating_add(payload_len);
        stream_queue.queue.push_back(cmd);

        if was_empty {
            self.ready_streams.push_back(stream_id);
        }
    }

    fn next_command(&mut self) -> Option<WriterCommand> {
        while let Some(stream_id) = self.ready_streams.pop_front() {
            let Some(stream_queue) = self.streams.get_mut(&stream_id) else {
                continue;
            };

            stream_queue.deficit = stream_queue
                .deficit
                .saturating_add(WRITER_DRR_QUANTUM_BYTES);
            let Some(frame_cost) = stream_queue.queue.front().map(frame_command_cost) else {
                self.streams.remove(&stream_id);
                continue;
            };

            if frame_cost > stream_queue.deficit {
                self.ready_streams.push_back(stream_id);
                continue;
            }

            let cmd = stream_queue
                .queue
                .pop_front()
                .expect("front command was checked");
            stream_queue.deficit = stream_queue.deficit.saturating_sub(frame_cost);
            stream_queue.queued_bytes = stream_queue
                .queued_bytes
                .saturating_sub(cmd.frame.payload.len());
            let queue_empty = stream_queue.queue.is_empty();

            if queue_empty {
                self.streams.remove(&stream_id);
            } else {
                self.ready_streams.push_back(stream_id);
            }

            return Some(cmd);
        }

        None
    }
}

fn frame_command_cost(cmd: &WriterCommand) -> usize {
    cmd.frame.payload.len().max(1)
}

fn drain_data_rx(
    data_rx: &mut mpsc::Receiver<WriterCommand>,
    data_scheduler: &mut TunnelDataScheduler,
    data_open: &mut bool,
) {
    while *data_open {
        match data_rx.try_recv() {
            Ok(cmd) => data_scheduler.enqueue(cmd),
            Err(mpsc::error::TryRecvError::Disconnected) => *data_open = false,
            Err(mpsc::error::TryRecvError::Empty) => break,
        }
    }
}

async fn recv_writer_command(
    control_rx: &mut mpsc::Receiver<WriterCommand>,
    data_rx: &mut mpsc::Receiver<WriterCommand>,
    data_scheduler: &mut TunnelDataScheduler,
    data_frames_since_control_check: &mut usize,
) -> Option<WriterCommand> {
    let mut control_open = true;
    let mut data_open = true;

    loop {
        if !control_open && !data_open && data_scheduler.is_empty() {
            return None;
        }

        if control_open {
            match control_rx.try_recv() {
                Ok(cmd) => {
                    *data_frames_since_control_check = 0;
                    return Some(cmd);
                }
                Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        drain_data_rx(data_rx, data_scheduler, &mut data_open);

        if *data_frames_since_control_check >= DATA_FRAMES_BEFORE_CONTROL_CHECK {
            *data_frames_since_control_check = 0;
            tokio::task::yield_now().await;
            if control_open {
                match control_rx.try_recv() {
                    Ok(cmd) => return Some(cmd),
                    Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }
        }

        if let Some(cmd) = data_scheduler.next_command() {
            *data_frames_since_control_check = (*data_frames_since_control_check).saturating_add(1);
            return Some(cmd);
        }

        if !control_open && !data_open {
            return None;
        }

        tokio::select! {
            biased;

            cmd = control_rx.recv(), if control_open => {
                if let Some(cmd) = cmd {
                    *data_frames_since_control_check = 0;
                    return Some(cmd);
                }
                control_open = false;
            }
            cmd = data_rx.recv(), if data_open => {
                if let Some(cmd) = cmd {
                    data_scheduler.enqueue(cmd);
                    continue;
                }
                data_open = false;
            }
        }
    }
}

fn record_recent_writer_wait(recent_writer_wait_ms: &AtomicU64, wait_ms: u64) {
    let mut current = recent_writer_wait_ms.load(Ordering::Relaxed);
    loop {
        let next = current
            .saturating_mul(7)
            .saturating_add(wait_ms)
            .saturating_div(8);
        match recent_writer_wait_ms.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

async fn clear_streams(
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: &Arc<TunnelFlowControl>,
    metrics: &Arc<TunnelMetrics>,
    reason: CloseReason,
) -> usize {
    let mut streams = streams.lock().await;
    let active_streams = streams.len();
    let closed_ids = streams.keys().copied().collect::<Vec<_>>();
    streams.clear();
    drop(streams);

    for stream_id in closed_ids {
        flow_control.remove_stream(stream_id).await;
        metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
        remember_closed_stream(
            recently_closed_streams,
            stream_id,
            reason,
            StreamState::Closed,
        )
        .await;
    }

    active_streams
}

async fn remove_stream_with_recent(
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    flow_control: &Arc<TunnelFlowControl>,
    metrics: &Arc<TunnelMetrics>,
    stream_id: u64,
    reason: CloseReason,
    last_state: StreamState,
) -> usize {
    let mut streams = streams.lock().await;
    let removed = streams.remove(&stream_id).is_some();
    let active_streams = streams.len();
    drop(streams);

    if removed {
        flow_control.remove_stream(stream_id).await;
        metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
        remember_closed_stream(recently_closed_streams, stream_id, reason, last_state).await;
    }

    active_streams
}

async fn remember_closed_stream(
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    stream_id: u64,
    reason: CloseReason,
    last_state: StreamState,
) {
    let now = Instant::now();
    let mut recently_closed = recently_closed_streams.lock().await;
    prune_recently_closed_streams(&mut recently_closed, now);
    recently_closed.insert(
        stream_id,
        ClosedStreamInfo {
            closed_at: now,
            reason,
            bytes_up: 0,
            bytes_down: 0,
            last_state,
        },
    );
}

async fn recently_closed_stream_info(
    recently_closed_streams: &Arc<Mutex<HashMap<u64, ClosedStreamInfo>>>,
    stream_id: u64,
) -> Option<ClosedStreamInfo> {
    let now = Instant::now();
    let mut recently_closed = recently_closed_streams.lock().await;
    prune_recently_closed_streams(&mut recently_closed, now);
    recently_closed.get(&stream_id).cloned()
}

fn prune_recently_closed_streams(
    recently_closed: &mut HashMap<u64, ClosedStreamInfo>,
    now: Instant,
) {
    recently_closed
        .retain(|_, info| now.duration_since(info.closed_at) <= RECENTLY_CLOSED_STREAM_TTL);
}

async fn log_unknown_or_recently_closed_tcp_data(
    inner: &TunnelManagerInner,
    stream_id: u64,
    payload_len: usize,
) {
    if let Some(info) = recently_closed_stream_info(&inner.recently_closed_streams, stream_id).await
    {
        inner.metrics.late_data.fetch_add(1, Ordering::Relaxed);
        debug!(
            tunnel_id = inner.tunnel_id,
            stream_id,
            closed_ago_ms = elapsed_millis(info.closed_at.elapsed()),
            closed_reason = ?info.reason,
            bytes_up = info.bytes_up,
            bytes_down = info.bytes_down,
            last_state = ?info.last_state,
            payload_len,
            "late TCP_DATA for recently closed stream"
        );
    } else {
        inner
            .metrics
            .unknown_stream_data
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            tunnel_id = inner.tunnel_id,
            stream_id, payload_len, "dropping TCP_DATA for unknown stream"
        );
    }
}

async fn log_unknown_or_recently_closed_tcp_close(inner: &TunnelManagerInner, stream_id: u64) {
    if let Some(info) = recently_closed_stream_info(&inner.recently_closed_streams, stream_id).await
    {
        inner.metrics.late_close.fetch_add(1, Ordering::Relaxed);
        debug!(
            tunnel_id = inner.tunnel_id,
            stream_id,
            closed_ago_ms = elapsed_millis(info.closed_at.elapsed()),
            closed_reason = ?info.reason,
            bytes_up = info.bytes_up,
            bytes_down = info.bytes_down,
            last_state = ?info.last_state,
            "late TCP_CLOSE for recently closed stream"
        );
    } else {
        inner
            .metrics
            .unknown_stream_close
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            tunnel_id = inner.tunnel_id,
            stream_id, "ignoring TCP_CLOSE for unknown stream"
        );
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{read_frame, write_frame};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::time::timeout;

    fn test_flow_control() -> Arc<TunnelFlowControl> {
        Arc::new(TunnelFlowControl::new(1_048_576, 16_777_216, 64))
    }

    fn test_writer_channels(
        capacity: usize,
    ) -> (
        WriterChannels,
        mpsc::Receiver<WriterCommand>,
        mpsc::Receiver<WriterCommand>,
    ) {
        writer_channels(
            capacity,
            Arc::new(AtomicU64::new(0)),
            test_flow_control(),
            Arc::new(TunnelMetrics::new()),
        )
    }

    fn test_writer_command(frame: FrameCommand) -> WriterCommand {
        WriterCommand {
            frame,
            _flow_permit: None,
        }
    }

    fn test_inner(
        tunnel_id: usize,
        writer_tx: Option<WriterChannels>,
        streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    ) -> Arc<TunnelManagerInner> {
        Arc::new(TunnelManagerInner {
            tunnel_id,
            tunnel: TunnelClient::new(OutboundConfig::default(), ClientAuthConfig::default()),
            writer_tx: Mutex::new(writer_tx),
            flow_control: test_flow_control(),
            streams,
            recently_closed_streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: AtomicU64::new(1),
            state: AtomicU8::new(TunnelState::Connected.as_u8()),
            generation: AtomicU64::new(1),
            reconnecting: AtomicBool::new(false),
            recent_writer_wait_ms: Arc::new(AtomicU64::new(0)),
            recent_write_frame_duration_ms: AtomicU64::new(0),
            last_pong_at_ms: AtomicU64::new(now_millis()),
            last_ping_sent_at_ms: AtomicU64::new(0),
            recent_pong_rtt_ms: AtomicU64::new(0),
            idle_since_ms: AtomicU64::new(now_millis()),
            metrics: Arc::new(TunnelMetrics::new()),
            stream_slots: Arc::new(Semaphore::new(16)),
            max_stream_slots: 16,
            keepalive_interval: Duration::from_secs(20),
            keepalive_timeout: Duration::from_secs(10),
            reconnect_enabled: AtomicBool::new(false),
        })
    }

    async fn test_manager_with_load(
        tunnel_id: usize,
        state: TunnelState,
        active_streams: usize,
        recent_writer_wait_ms: u64,
    ) -> Arc<TunnelManager> {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        for stream_id in 0..active_streams as u64 {
            let (tx, _rx) = mpsc::channel(1);
            streams.lock().await.insert(stream_id * 2 + 1, tx);
        }
        let inner = test_inner(tunnel_id, None, streams);
        inner.state.store(state.as_u8(), Ordering::Release);
        inner
            .recent_writer_wait_ms
            .store(recent_writer_wait_ms, Ordering::Release);
        Arc::new(TunnelManager { inner })
    }

    fn test_pool(tunnels: Vec<Arc<TunnelManager>>, max_streams_per_tunnel: usize) -> TunnelPool {
        TunnelPool {
            tunnels: Arc::new(Mutex::new(tunnels)),
            outbound: OutboundConfig::default(),
            auth: ClientAuthConfig::default(),
            min_tunnels: 1,
            max_tunnels: 1,
            max_streams_per_tunnel,
            stream_slot_wait_timeout: Duration::from_millis(50),
            scale_up_writer_wait_ms: 100,
            scale_up_queue_depth_ratio: 0.75,
            scale_down_idle: Duration::from_secs(60),
            next_tunnel_id: Arc::new(AtomicUsize::new(0)),
            scale_lock: Arc::new(Mutex::new(())),
        }
    }

    #[test]
    fn stream_ids_are_client_odd_ids() {
        let next_stream_id = AtomicU64::new(1);

        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 1);
        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 3);
        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn writer_loop_serializes_frame_commands() {
        let (stream, mut peer) = duplex(1024);
        let (_read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, None, Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            inner, 1, write_half, control_rx, data_rx,
        ));

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 3,
                flags: 0,
                payload: Bytes::from_static(b"hello"),
            }))
            .await
            .expect("send frame command");
        drop(tx);

        let frame = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read frame timeout")
            .expect("read frame");
        writer.await.expect("writer task");

        assert_eq!(frame.frame_type, FrameType::TcpData);
        assert_eq!(frame.stream_id, 3);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn writer_command_receive_keeps_tcp_close_in_data_order() {
        let (tx, mut control_rx, mut data_rx) = test_writer_channels(2);

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 3,
                flags: 0,
                payload: Bytes::from_static(b"data"),
            }))
            .await
            .expect("send data frame command");
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id: 3,
                flags: 0,
                payload: Bytes::new(),
            }))
            .await
            .expect("send control frame command");

        let mut data_frames_since_control_check = 0;
        let mut data_scheduler = TunnelDataScheduler::default();
        let frame = recv_writer_command(
            &mut control_rx,
            &mut data_rx,
            &mut data_scheduler,
            &mut data_frames_since_control_check,
        )
        .await
        .expect("writer command");
        assert_eq!(frame.frame.frame_type, FrameType::TcpData);
    }

    #[tokio::test]
    async fn writer_command_receive_schedules_data_fairly_between_streams() {
        let (tx, mut control_rx, mut data_rx) = test_writer_channels(4);

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 3,
                flags: 0,
                payload: Bytes::from_static(b"first"),
            }))
            .await
            .expect("send first stream frame");
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 3,
                flags: 0,
                payload: Bytes::from_static(b"second"),
            }))
            .await
            .expect("send second stream frame");
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 5,
                flags: 0,
                payload: Bytes::from_static(b"small"),
            }))
            .await
            .expect("send other stream frame");

        let mut data_scheduler = TunnelDataScheduler::default();
        let mut data_frames_since_control_check = 0;
        let first = recv_writer_command(
            &mut control_rx,
            &mut data_rx,
            &mut data_scheduler,
            &mut data_frames_since_control_check,
        )
        .await
        .expect("first writer command");
        let second = recv_writer_command(
            &mut control_rx,
            &mut data_rx,
            &mut data_scheduler,
            &mut data_frames_since_control_check,
        )
        .await
        .expect("second writer command");
        let third = recv_writer_command(
            &mut control_rx,
            &mut data_rx,
            &mut data_scheduler,
            &mut data_frames_since_control_check,
        )
        .await
        .expect("third writer command");

        assert_eq!(first.frame.stream_id, 3);
        assert_eq!(second.frame.stream_id, 5);
        assert_eq!(third.frame.stream_id, 3);
    }

    #[tokio::test]
    async fn flow_control_limits_buffer_bytes_per_stream() {
        let flow_control = Arc::new(TunnelFlowControl::new(4, 16, 4));
        let first = flow_control.acquire(3, 4).await.expect("first permit");

        let blocked = timeout(Duration::from_millis(25), flow_control.acquire(3, 1)).await;
        assert!(blocked.is_err());

        drop(first);
        flow_control
            .acquire(3, 1)
            .await
            .expect("permit after release");
    }

    #[tokio::test]
    async fn flow_control_limits_pending_frames_per_stream() {
        let flow_control = Arc::new(TunnelFlowControl::new(16, 16, 1));
        let first = flow_control.acquire(3, 0).await.expect("first frame");

        let blocked = timeout(Duration::from_millis(25), flow_control.acquire(3, 0)).await;
        assert!(blocked.is_err());

        drop(first);
        flow_control
            .acquire(3, 0)
            .await
            .expect("frame after release");
    }

    #[tokio::test]
    async fn tunnel_pool_selects_by_pressure_score() {
        let high_pressure = test_manager_with_load(0, TunnelState::Connected, 1, 1_000).await;
        let lower_score = test_manager_with_load(1, TunnelState::Connected, 3, 0).await;
        let pool = test_pool(
            vec![Arc::clone(&high_pressure), Arc::clone(&lower_score)],
            16,
        );

        let selected = pool.select_tunnel().await.expect("selected tunnel");

        assert_eq!(selected.tunnel_id(), 1);
    }

    #[tokio::test]
    async fn tunnel_pool_excludes_disconnected_tunnels() {
        let disconnected = test_manager_with_load(0, TunnelState::Disconnected, 0, 0).await;
        let connected = test_manager_with_load(1, TunnelState::Connected, 8, 0).await;
        let pool = test_pool(vec![Arc::clone(&disconnected), Arc::clone(&connected)], 16);

        let selected = pool.select_tunnel().await.expect("selected tunnel");

        assert_eq!(selected.tunnel_id(), 1);
    }

    #[tokio::test]
    async fn tunnel_pool_does_not_select_tunnel_at_stream_limit() {
        let full = test_manager_with_load(0, TunnelState::Connected, 2, 0).await;
        let pool = test_pool(vec![Arc::clone(&full)], 2);

        let selected = pool.select_tunnel_slot().await;

        assert!(selected.is_none());
    }

    #[tokio::test]
    async fn marking_tunnel_broken_clears_streams_and_disconnects() {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(19, stream_tx);
        let inner = test_inner(0, Some(writer_tx), Arc::clone(&streams));

        mark_tunnel_broken(Arc::clone(&inner), 1, "test_failure", false).await;

        assert_eq!(
            TunnelState::from_u8(inner.state.load(Ordering::Acquire)),
            TunnelState::Disconnected
        );
        assert!(inner.writer_tx.lock().await.is_none());
        assert!(streams.lock().await.is_empty());
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_data_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(
            &mut peer,
            FrameType::TcpData,
            5,
            0,
            Bytes::from_static(b"payload"),
        )
        .await
        .expect("write frame");
        drop(peer);

        let payload = timeout(Duration::from_secs(1), stream_rx.recv())
            .await
            .expect("receive payload timeout")
            .expect("receive payload");
        reader.await.expect("reader task");

        assert_eq!(payload, StreamEvent::Data(Bytes::from_static(b"payload")));
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_connect_success_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(
            &mut peer,
            FrameType::TcpConnect,
            5,
            CONNECT_OK_FLAG,
            Bytes::new(),
        )
        .await
        .expect("write frame");

        let event = timeout(Duration::from_secs(1), stream_rx.recv())
            .await
            .expect("receive connect event timeout")
            .expect("receive connect event");

        assert_eq!(event, StreamEvent::Connected);
        assert!(streams.lock().await.contains_key(&5));

        drop(peer);
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn open_tcp_stream_waits_for_tcp_connect_success() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (writer_tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, Some(writer_tx.clone()), Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            Arc::clone(&inner),
            1,
            write_half,
            control_rx,
            data_rx,
        ));
        let reader = tokio::spawn(tunnel_reader_loop(Arc::clone(&inner), 1, read_half));
        let manager = TunnelManager { inner };
        drop(writer_tx);
        let mut open =
            tokio::spawn(async move { manager.open_tcp_stream("example.com", 443).await });

        let connect = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read TCP_CONNECT timeout")
            .expect("read TCP_CONNECT");
        assert_eq!(connect.frame_type, FrameType::TcpConnect);
        assert_eq!(connect.stream_id, 1);

        assert!(
            timeout(Duration::from_millis(50), &mut open).await.is_err(),
            "open_tcp_stream returned before TCP_CONNECT response"
        );

        write_frame(
            &mut peer,
            FrameType::TcpConnect,
            connect.stream_id,
            CONNECT_OK_FLAG,
            Bytes::new(),
        )
        .await
        .expect("write TCP_CONNECT OK");

        let handle = timeout(Duration::from_secs(1), open)
            .await
            .expect("open stream timeout")
            .expect("open task")
            .expect("open stream");
        assert_eq!(handle.stream_id(), connect.stream_id);

        drop(handle);
        drop(peer);
        writer.await.expect("writer task");
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn open_tcp_stream_fails_on_error_frame() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (writer_tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, Some(writer_tx.clone()), Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            Arc::clone(&inner),
            1,
            write_half,
            control_rx,
            data_rx,
        ));
        let reader = tokio::spawn(tunnel_reader_loop(Arc::clone(&inner), 1, read_half));
        let manager = TunnelManager { inner };
        drop(writer_tx);
        let open = tokio::spawn(async move { manager.open_tcp_stream("example.com", 443).await });

        let connect = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read TCP_CONNECT timeout")
            .expect("read TCP_CONNECT");
        write_frame(
            &mut peer,
            FrameType::ErrorFrame,
            connect.stream_id,
            0,
            Bytes::from_static(b"target unavailable"),
        )
        .await
        .expect("write ERROR frame");

        let result = timeout(Duration::from_secs(1), open)
            .await
            .expect("open stream timeout")
            .expect("open task");
        let err = match result {
            Ok(_) => panic!("open stream must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("server refused TCP_CONNECT")
                && err.to_string().contains("target unavailable"),
            "unexpected error: {err:#}"
        );
        assert!(streams.lock().await.is_empty());

        drop(peer);
        writer.await.expect("writer task");
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn wait_for_connect_response_requires_tcp_connect_success() {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let stream_tx = streams.lock().await.get(&5).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Connected)
            .await
            .expect("send connected event");
        let recently_closed_streams = Arc::new(Mutex::new(HashMap::new()));
        let flow_control = test_flow_control();
        let metrics = Arc::new(TunnelMetrics::new());

        wait_for_connect_response(
            0,
            5,
            "example.com",
            443,
            &mut stream_rx,
            &streams,
            &recently_closed_streams,
            &flow_control,
            &metrics,
        )
        .await
        .expect("connect response");

        assert!(streams.lock().await.contains_key(&5));
    }

    #[tokio::test]
    async fn wait_for_connect_response_turns_error_into_open_failure() {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let stream_tx = streams.lock().await.get(&5).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Error("target unavailable".to_string()))
            .await
            .expect("send error event");
        let recently_closed_streams = Arc::new(Mutex::new(HashMap::new()));
        let flow_control = test_flow_control();
        let metrics = Arc::new(TunnelMetrics::new());

        let err = wait_for_connect_response(
            0,
            5,
            "example.com",
            443,
            &mut stream_rx,
            &streams,
            &recently_closed_streams,
            &flow_control,
            &metrics,
        )
        .await
        .expect_err("connect response must fail");

        assert!(
            err.to_string().contains("server refused TCP_CONNECT")
                && err.to_string().contains("target unavailable"),
            "unexpected error: {err:#}"
        );
        assert!(!streams.lock().await.contains_key(&5));
    }

    #[tokio::test]
    async fn reader_loop_removes_stream_on_tcp_close() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(7, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(&mut peer, FrameType::TcpClose, 7, 0, Bytes::new())
            .await
            .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(!streams.lock().await.contains_key(&7));
    }

    #[tokio::test]
    async fn reader_loop_removes_stream_on_error() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(9, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(
            &mut peer,
            FrameType::ErrorFrame,
            9,
            0,
            Bytes::from_static(b"target connect failed"),
        )
        .await
        .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(!streams.lock().await.contains_key(&9));
    }

    #[tokio::test]
    async fn reader_loop_ignores_unknown_tcp_data_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(
            &mut peer,
            FrameType::TcpData,
            11,
            0,
            Bytes::from_static(b"orphaned payload"),
        )
        .await
        .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(streams.lock().await.is_empty());
    }

    #[tokio::test]
    async fn close_stream_sends_tcp_close_without_dropping_inbound_dispatch() {
        let (writer_tx, _control_rx, mut data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let recently_closed_streams = Arc::new(Mutex::new(HashMap::new()));
        let flow_control = test_flow_control();
        let metrics = Arc::clone(&writer_tx.metrics);
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(15, stream_tx);
        let closed = AtomicBool::new(false);

        close_stream(
            0,
            15,
            &writer_tx,
            &streams,
            &recently_closed_streams,
            &flow_control,
            &metrics,
            &closed,
            Some("example.com"),
            Some(443),
        )
        .await
        .expect("close stream");

        let frame = data_rx.recv().await.expect("TCP_CLOSE frame");
        assert_eq!(frame.frame.frame_type, FrameType::TcpClose);
        assert_eq!(frame.frame.stream_id, 15);
        assert!(streams.lock().await.contains_key(&15));

        let stream_tx = streams.lock().await.get(&15).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Data(Bytes::from_static(b"late response")))
            .await
            .expect("late response send");
        assert_eq!(
            stream_rx.recv().await,
            Some(StreamEvent::Data(Bytes::from_static(b"late response")))
        );
    }

    #[tokio::test]
    async fn writer_loop_clears_streams_on_physical_write_failure() {
        let (stream, peer) = duplex(1024);
        drop(peer);
        let (_read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(17, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            inner, 1, write_half, control_rx, data_rx,
        ));

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 17,
                flags: 0,
                payload: Bytes::from_static(b"payload"),
            }))
            .await
            .expect("send frame command");
        drop(tx);
        writer.await.expect("writer task");

        assert!(streams.lock().await.is_empty());
    }
}

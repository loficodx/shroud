use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::config::ServerMultiplexConfig;
use shroud_core::protocol::{
    Frame, FrameCommand, FrameType, MAX_FRAME_PAYLOAD_LEN, ProtocolError, UdpDatagram,
    decode_tcp_connect_payload, decode_udp_datagram, encode_udp_associate_response_payload,
    encode_udp_datagram, read_frame, write_frame,
};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

const CONNECT_OK_FLAG: u16 = 0x0001;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const WRITER_CHANNEL_CAPACITY: usize = 128;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD: Duration = Duration::from_millis(1);
const COPY_BUF_SIZE: usize = 32 * 1024;
const DATA_FRAMES_BEFORE_CONTROL_CHECK: usize = 8;
const WRITER_DRR_QUANTUM_BYTES: usize = 64 * 1024;
const CLOSE_GRACE_PERIOD: Duration = Duration::from_secs(5);
const RECENTLY_CLOSED_STREAM_TTL: Duration = Duration::from_secs(30);
const METRICS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const LATENCY_WINDOW_CAPACITY: usize = 512;
static NEXT_MULTIPLEX_TUNNEL_ID: AtomicU64 = AtomicU64::new(0);

type TargetStreamTx = mpsc::Sender<Bytes>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
    ClientWriteClosed,
    TargetWriteClosed,
    BothWriteClosed,
    Closing { since: Instant, reason: CloseReason },
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    ClientClosed,
    TargetClosed,
    TargetConnectFailed,
    ProtocolError,
    TargetInputClosed,
    WriterChannelClosed,
    TunnelBroken,
    PhysicalTunnelClosed,
}

#[derive(Debug, Clone)]
struct StreamMeta {
    stream_id: u64,
    target_host: String,
    target_port: u16,
    created_at: Instant,
    bytes_up: u64,
    bytes_down: u64,
}

struct MultiplexStream {
    tx_to_target: Option<TargetStreamTx>,
    state: StreamState,
    meta: StreamMeta,
}

#[derive(Debug, Clone)]
struct ClosedStreamInfo {
    closed_at: Instant,
    reason: CloseReason,
    bytes_up: u64,
    bytes_down: u64,
    last_state: StreamState,
}

struct ServerTunnelMetrics {
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
    tunnel_id: u64,
    control_tx: mpsc::Sender<WriterCommand>,
    data_tx: mpsc::Sender<WriterCommand>,
    flow_control: Arc<TunnelFlowControl>,
    metrics: Arc<ServerTunnelMetrics>,
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

impl ServerTunnelMetrics {
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

struct ServerTunnelState {
    tunnel_id: u64,
    streams: Mutex<HashMap<u64, MultiplexStream>>,
    recently_closed_streams: Mutex<HashMap<u64, ClosedStreamInfo>>,
    writer_tx: WriterChannels,
    flow_control: Arc<TunnelFlowControl>,
    metrics: Arc<ServerTunnelMetrics>,
    tunnel_closed: AtomicBool,
}

pub async fn relay_multiplexed_tunnel<S>(tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_multiplexed_tunnel_with_config(tunnel_stream, peer, ServerMultiplexConfig::default())
        .await
}

pub async fn relay_multiplexed_tunnel_with_config<S>(
    tunnel_stream: S,
    peer: SocketAddr,
    config: ServerMultiplexConfig,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tunnel_id = NEXT_MULTIPLEX_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
    let opened_at = Instant::now();
    let (read_half, write_half) = tokio::io::split(tunnel_stream);
    let flow_control = Arc::new(TunnelFlowControl::new(
        config.max_buffer_per_stream_bytes,
        config.max_buffer_per_tunnel_bytes,
        config.max_pending_frames_per_stream,
    ));
    let metrics = Arc::new(ServerTunnelMetrics::new());
    let (writer_tx, control_rx, data_rx) = writer_channels(
        tunnel_id,
        WRITER_CHANNEL_CAPACITY,
        Arc::clone(&flow_control),
        Arc::clone(&metrics),
    );
    let state = Arc::new(ServerTunnelState {
        tunnel_id,
        streams: Mutex::new(HashMap::new()),
        recently_closed_streams: Mutex::new(HashMap::new()),
        writer_tx,
        flow_control,
        metrics,
        tunnel_closed: AtomicBool::new(false),
    });

    info!(
        %peer,
        tunnel_id,
        max_buffer_per_stream_bytes = config.max_buffer_per_stream_bytes,
        max_buffer_per_tunnel_bytes = config.max_buffer_per_tunnel_bytes,
        max_pending_frames_per_stream = config.max_pending_frames_per_stream,
        "multiplexed physical tunnel opened"
    );

    let writer_task = tokio::spawn(server_tunnel_writer_loop(
        tunnel_id,
        write_half,
        control_rx,
        data_rx,
        Arc::clone(&state.metrics),
    ));
    let metrics_task = tokio::spawn(server_tunnel_metrics_log_loop(Arc::clone(&state), peer));
    let result = server_tunnel_reader_loop(read_half, Arc::clone(&state), peer).await;

    state.tunnel_closed.store(true, Ordering::Release);
    let active_streams = clear_multiplexed_streams(&state).await;
    writer_task.abort();
    let _ = writer_task.await;
    metrics_task.abort();
    let _ = metrics_task.await;

    match &result {
        Ok(()) => info!(
            %peer,
            tunnel_id,
            duration_ms = elapsed_millis(opened_at.elapsed()),
            active_streams,
            close_reason = "remote_closed",
            "multiplexed physical tunnel closed"
        ),
        Err(err) => warn!(
            %peer,
            tunnel_id,
            duration_ms = elapsed_millis(opened_at.elapsed()),
            active_streams,
            error = %err,
            close_reason = "tunnel_broken",
            "multiplexed physical tunnel closed with error"
        ),
    }

    result
}

async fn server_tunnel_reader_loop<R>(
    mut read_half: tokio::io::ReadHalf<R>,
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut read_half)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(ProtocolError::Io(err))) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(%peer, "multiplexed tunnel peer closed connection");
                return Ok(());
            }
            Ok(Err(err)) => return Err(anyhow!("failed to read multiplexed tunnel frame: {err}")),
            Err(_) => bail!("multiplexed tunnel idle timeout while reading from peer {peer}"),
        };

        match frame.frame_type {
            FrameType::TcpConnect => {
                let (target_host, target_port) = decode_tcp_connect_payload(frame.payload.as_ref())
                    .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;
                handle_multiplexed_tcp_connect(
                    Arc::clone(&state),
                    peer,
                    frame.stream_id,
                    target_host,
                    target_port,
                )
                .await?;
            }
            FrameType::TcpData => {
                dispatch_tcp_data_to_target(Arc::clone(&state), peer, frame).await?;
            }
            FrameType::TcpClose => {
                match close_multiplexed_stream_client_write(&state, frame.stream_id).await {
                    Some(snapshot) => debug!(
                        %peer,
                        tunnel_id = state.tunnel_id,
                        stream_id = snapshot.meta.stream_id,
                        target_host = %snapshot.meta.target_host,
                        target_port = snapshot.meta.target_port,
                        duration_ms = elapsed_millis(snapshot.meta.created_at.elapsed()),
                        bytes_up = snapshot.meta.bytes_up,
                        bytes_down = snapshot.meta.bytes_down,
                        state = ?snapshot.state,
                        active_streams = snapshot.active_streams,
                        close_reason = "client_closed",
                        "multiplexed TCP stream client write side closed"
                    ),
                    None => {
                        log_unknown_or_recently_closed_tcp_close(
                            &state,
                            peer,
                            frame.stream_id,
                            CloseReason::ClientClosed,
                        )
                        .await;
                    }
                }
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let active_streams =
                    remove_multiplexed_stream(&state, frame.stream_id, CloseReason::ProtocolError)
                        .await;
                debug!(
                    %peer,
                    stream_id = frame.stream_id,
                    active_streams,
                    error = %message,
                    "multiplexed TCP stream failed by peer"
                );
            }
            FrameType::Ping => {
                send_writer_command(
                    &state.writer_tx,
                    FrameCommand {
                        frame_type: FrameType::Pong,
                        stream_id: frame.stream_id,
                        flags: 0,
                        payload: frame.payload,
                    },
                    "PONG",
                    WriterLogContext::empty(),
                )
                .await
                .context("failed to queue PONG for multiplexed tunnel")?;
            }
            other => {
                debug!(
                    %peer,
                    stream_id = frame.stream_id,
                    frame_type = %other,
                    "ignoring unsupported frame on multiplexed tunnel"
                );
            }
        }
    }
}

async fn server_tunnel_writer_loop<W>(
    tunnel_id: u64,
    mut write_half: tokio::io::WriteHalf<W>,
    mut control_rx: mpsc::Receiver<WriterCommand>,
    mut data_rx: mpsc::Receiver<WriterCommand>,
    metrics: Arc<ServerTunnelMetrics>,
) where
    W: AsyncWrite + Unpin,
{
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
        metrics.record_write_frame_duration(write_duration_ms).await;
        if write_duration >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
            debug!(
                tunnel_id,
                stream_id,
                frame_type = %frame_type,
                write_frame_payload_len = payload_len,
                write_frame_duration_ms = write_duration_ms,
                "multiplexed tunnel write_frame completed"
            );
        }
        drop(cmd._flow_permit);

        if let Err(err) = result {
            warn!(
                tunnel_id,
                error = %err,
                close_reason = "tunnel_broken",
                "multiplexed tunnel writer stopped"
            );
            break;
        }
    }

    debug!(tunnel_id, "multiplexed tunnel writer finished");
}

async fn server_tunnel_metrics_log_loop(state: Arc<ServerTunnelState>, peer: SocketAddr) {
    loop {
        sleep(METRICS_LOG_INTERVAL).await;
        if state.tunnel_closed.load(Ordering::Acquire) {
            break;
        }
        log_server_tunnel_metrics_snapshot(&state, peer).await;
    }
}

async fn log_server_tunnel_metrics_snapshot(state: &Arc<ServerTunnelState>, peer: SocketAddr) {
    let (active_streams, mut top_streams_by_down_bytes) = {
        let streams = state.streams.lock().await;
        let mut snapshots = streams
            .values()
            .map(|stream| {
                (
                    stream.meta.stream_id,
                    stream.meta.target_host.clone(),
                    stream.meta.target_port,
                    stream.meta.bytes_up,
                    stream.meta.bytes_down,
                    stream.state,
                )
            })
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| right.4.cmp(&left.4));
        snapshots.truncate(5);
        (streams.len(), snapshots)
    };
    top_streams_by_down_bytes.shrink_to_fit();

    let writer_queue_depth = state.writer_tx.queue_depth_snapshot();
    let writer_wait = state.metrics.writer_wait.snapshot().await;
    let write_frame_duration = state.metrics.write_frame_duration.snapshot().await;

    info!(
        %peer,
        tunnel_id = state.tunnel_id,
        active_streams,
        writer_queue_control_depth = writer_queue_depth.control,
        writer_queue_data_depth = writer_queue_depth.data,
        writer_queue_wait_p50_ms = writer_wait.p50_ms,
        writer_queue_wait_p95_ms = writer_wait.p95_ms,
        writer_queue_wait_samples = writer_wait.samples,
        write_frame_duration_p50_ms = write_frame_duration.p50_ms,
        write_frame_duration_p95_ms = write_frame_duration.p95_ms,
        write_frame_duration_samples = write_frame_duration.samples,
        bytes_up = state.metrics.bytes_up.load(Ordering::Relaxed),
        bytes_down = state.metrics.bytes_down.load(Ordering::Relaxed),
        streams_opened_total = state.metrics.streams_opened.load(Ordering::Relaxed),
        streams_closed_total = state.metrics.streams_closed.load(Ordering::Relaxed),
        late_data_total = state.metrics.late_data.load(Ordering::Relaxed),
        late_close_total = state.metrics.late_close.load(Ordering::Relaxed),
        unknown_stream_data_total = state.metrics.unknown_stream_data.load(Ordering::Relaxed),
        unknown_stream_close_total = state.metrics.unknown_stream_close.load(Ordering::Relaxed),
        top_streams_by_down_bytes = ?top_streams_by_down_bytes,
        "multiplexed tunnel metrics"
    );
}

async fn handle_multiplexed_tcp_connect(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    let (to_target_tx, to_target_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

    {
        let mut streams = state.streams.lock().await;
        if streams.contains_key(&stream_id) {
            let active_streams = streams.len();
            drop(streams);
            send_writer_command(
                &state.writer_tx,
                FrameCommand {
                    frame_type: FrameType::ErrorFrame,
                    stream_id,
                    flags: 0,
                    payload: Bytes::from_static(b"duplicate stream id"),
                },
                "duplicate stream id ERROR",
                WriterLogContext::target(&target_host, target_port, active_streams),
            )
            .await
            .context("failed to queue duplicate stream id error")?;
            return Ok(());
        }

        streams.insert(
            stream_id,
            MultiplexStream::new(stream_id, target_host.clone(), target_port, to_target_tx),
        );
        drop(streams);
        state.flow_control.ensure_stream(stream_id).await;
        state.metrics.streams_opened.fetch_add(1, Ordering::Relaxed);
        let streams = state.streams.lock().await;
        debug!(
            %peer,
            stream_id,
            target_host,
            target_port,
            active_streams = streams.len(),
            "multiplexed TCP stream opened"
        );
    }

    tokio::spawn(connect_and_relay_target(
        state,
        peer,
        stream_id,
        target_host,
        target_port,
        to_target_rx,
    ));

    Ok(())
}

async fn dispatch_tcp_data_to_target(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    frame: Frame,
) -> Result<()> {
    let dispatch = {
        let streams = state.streams.lock().await;
        match streams.get(&frame.stream_id) {
            Some(stream)
                if matches!(
                    stream.state,
                    StreamState::Open | StreamState::TargetWriteClosed
                ) && stream.tx_to_target.is_some() =>
            {
                TcpDataDispatch::Open(stream.tx_to_target.as_ref().expect("checked").clone())
            }
            Some(stream) => TcpDataDispatch::Closing {
                state: stream.state,
                meta: stream.meta.clone(),
                active_streams: streams.len(),
            },
            None => TcpDataDispatch::Unknown,
        }
    };

    let tx = match dispatch {
        TcpDataDispatch::Open(tx) => tx,
        TcpDataDispatch::Closing {
            state: stream_state,
            meta,
            active_streams,
        } => {
            state.metrics.late_data.fetch_add(1, Ordering::Relaxed);
            debug!(
                %peer,
                stream_id = meta.stream_id,
                target_host = %meta.target_host,
                target_port = meta.target_port,
                duration_ms = elapsed_millis(meta.created_at.elapsed()),
                bytes_up = meta.bytes_up,
                bytes_down = meta.bytes_down,
                state = ?stream_state,
                active_streams,
                payload_len = frame.payload.len(),
                "late TCP_DATA for closing multiplexed stream ignored"
            );
            return Ok(());
        }
        TcpDataDispatch::Unknown => {
            log_unknown_or_recently_closed_tcp_data(
                &state,
                peer,
                frame.stream_id,
                frame.payload.len(),
            )
            .await;
            return Ok(());
        }
    };

    let payload_len = frame.payload.len();
    if tx.send(frame.payload).await.is_err() {
        let active_streams =
            remove_multiplexed_stream(&state, frame.stream_id, CloseReason::TargetInputClosed)
                .await;
        debug!(
            %peer,
            stream_id = frame.stream_id,
            active_streams,
            "multiplexed TCP stream removed after target input closed"
        );
    } else {
        state
            .metrics
            .bytes_up
            .fetch_add(payload_len as u64, Ordering::Relaxed);
        record_multiplexed_stream_bytes(&state, frame.stream_id, payload_len as u64, 0).await;
    }

    Ok(())
}

enum TcpDataDispatch {
    Open(TargetStreamTx),
    Closing {
        state: StreamState,
        meta: StreamMeta,
        active_streams: usize,
    },
    Unknown,
}

async fn connect_and_relay_target(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    to_target_rx: mpsc::Receiver<Bytes>,
) {
    let opened_at = Instant::now();
    let tunnel_to_target_bytes = Arc::new(AtomicU64::new(0));
    let target_to_tunnel_bytes = Arc::new(AtomicU64::new(0));
    let target_connect_started = Instant::now();
    let target_stream = match timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    {
        Err(_) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("timed out connecting target {target_host}:{target_port}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "multiplexed target TCP connect timed out"
            );
            fail_multiplexed_stream(&state, stream_id, message).await;
            log_multiplexed_stream_closed(
                peer,
                state.tunnel_id,
                stream_id,
                &target_host,
                target_port,
                opened_at,
                tunnel_to_target_bytes.load(Ordering::Relaxed),
                target_to_tunnel_bytes.load(Ordering::Relaxed),
                active_multiplexed_streams(&state).await,
                "target_connect_failed",
            );
            return;
        }
        Ok(Ok(stream)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            if let Err(err) = stream.set_nodelay(true) {
                let message = format!(
                    "failed to enable TCP_NODELAY for target connection {target_host}:{target_port}: {err}"
                );
                fail_multiplexed_stream(&state, stream_id, message).await;
                log_multiplexed_stream_closed(
                    peer,
                    state.tunnel_id,
                    stream_id,
                    &target_host,
                    target_port,
                    opened_at,
                    tunnel_to_target_bytes.load(Ordering::Relaxed),
                    target_to_tunnel_bytes.load(Ordering::Relaxed),
                    active_multiplexed_streams(&state).await,
                    "target_connect_failed",
                );
                return;
            }

            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "multiplexed target TCP connect finished"
            );

            stream
        }
        Ok(Err(err)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                error = %err,
                "multiplexed target TCP connect failed"
            );
            fail_multiplexed_stream(&state, stream_id, message).await;
            log_multiplexed_stream_closed(
                peer,
                state.tunnel_id,
                stream_id,
                &target_host,
                target_port,
                opened_at,
                tunnel_to_target_bytes.load(Ordering::Relaxed),
                target_to_tunnel_bytes.load(Ordering::Relaxed),
                active_multiplexed_streams(&state).await,
                "target_connect_failed",
            );
            return;
        }
    };

    if !is_multiplexed_stream_active(&state, stream_id).await {
        debug!(
            %peer,
            stream_id,
            target_host,
            target_port,
            "multiplexed stream closed before target connect response"
        );
        log_multiplexed_stream_closed(
            peer,
            state.tunnel_id,
            stream_id,
            &target_host,
            target_port,
            opened_at,
            tunnel_to_target_bytes.load(Ordering::Relaxed),
            target_to_tunnel_bytes.load(Ordering::Relaxed),
            active_multiplexed_streams(&state).await,
            "client_closed",
        );
        return;
    }

    let active_streams = active_multiplexed_streams(&state).await;
    if send_writer_command(
        &state.writer_tx,
        FrameCommand {
            frame_type: FrameType::TcpConnect,
            stream_id,
            flags: CONNECT_OK_FLAG,
            payload: Bytes::new(),
        },
        "TCP_CONNECT response",
        WriterLogContext::target(&target_host, target_port, active_streams),
    )
    .await
    .is_err()
    {
        remove_multiplexed_stream(&state, stream_id, CloseReason::WriterChannelClosed).await;
        log_multiplexed_stream_closed(
            peer,
            state.tunnel_id,
            stream_id,
            &target_host,
            target_port,
            opened_at,
            tunnel_to_target_bytes.load(Ordering::Relaxed),
            target_to_tunnel_bytes.load(Ordering::Relaxed),
            active_multiplexed_streams(&state).await,
            "writer_channel_closed",
        );
        return;
    }

    let (target_read, target_write) = target_stream.into_split();
    let writer_tx = state.writer_tx.clone();
    let mut reader_task = tokio::spawn(target_reader_loop(
        Arc::clone(&state),
        stream_id,
        target_host.clone(),
        target_port,
        target_read,
        writer_tx,
        Arc::clone(&target_to_tunnel_bytes),
    ));
    let mut writer_task = tokio::spawn(target_writer_loop(
        stream_id,
        target_write,
        to_target_rx,
        Arc::clone(&tunnel_to_target_bytes),
    ));

    let close_reason = tokio::select! {
        result = &mut reader_task => {
            match result {
                Ok(Ok(bytes)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    target_to_tunnel_bytes = bytes,
                    close_reason = "target_closed",
                    "multiplexed target reader finished"
                ),
                Ok(Err(err)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason = "target_closed",
                    "multiplexed target reader failed"
                ),
                Err(err) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason = "target_closed",
                    "multiplexed target reader task failed"
                ),
            }
            let active_streams =
                mark_multiplexed_stream_target_write_closed(&state, stream_id).await
                    .map(|snapshot| snapshot.active_streams)
                    .unwrap_or_else(|| {
                        debug!(
                            %peer,
                            stream_id,
                            target_host,
                            target_port,
                            close_reason = "target_closed",
                            "target closed for unknown multiplexed stream"
                        );
                        0
                    });
            let _ = send_writer_command(&state.writer_tx, FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id,
                flags: 0,
                payload: Bytes::new(),
            }, "TCP_CLOSE", WriterLogContext::target(
                &target_host,
                target_port,
                active_streams,
            )).await;

            match timeout(CLOSE_GRACE_PERIOD, &mut writer_task).await {
                Ok(Ok(Ok(bytes))) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    tunnel_to_target_bytes = bytes,
                    close_reason = "target_closed",
                    "multiplexed target writer finished during close grace"
                ),
                Ok(Ok(Err(err))) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason = "target_closed",
                    "multiplexed target writer failed during close grace"
                ),
                Ok(Err(err)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason = "target_closed",
                    "multiplexed target writer task failed during close grace"
                ),
                Err(_) => {
                    mark_multiplexed_stream_closing(
                        &state,
                        stream_id,
                        CloseReason::TargetClosed,
                    )
                    .await;
                    writer_task.abort();
                    let _ = writer_task.await;
                }
            }
            remove_multiplexed_stream(&state, stream_id, CloseReason::TargetClosed).await;
            "target_closed"
        }
        result = &mut writer_task => {
            let writer_finished_cleanly = matches!(result, Ok(Ok(_)));
            let close_reason = if writer_finished_cleanly {
                "client_closed"
            } else {
                "tunnel_broken"
            };
            match result {
                Ok(Ok(bytes)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    tunnel_to_target_bytes = bytes,
                    close_reason,
                    "multiplexed target writer finished"
                ),
                Ok(Err(err)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason,
                    "multiplexed target writer failed"
                ),
                Err(err) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    close_reason,
                    "multiplexed target writer task failed"
                ),
            }

            if writer_finished_cleanly && !state.tunnel_closed.load(Ordering::Acquire) {
                match reader_task.await {
                    Ok(Ok(bytes)) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        target_to_tunnel_bytes = bytes,
                        close_reason,
                        "multiplexed target reader finished after input close"
                    ),
                    Ok(Err(err)) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        error = %err,
                        close_reason,
                        "multiplexed target reader failed after input close"
                    ),
                    Err(err) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        error = %err,
                        close_reason,
                        "multiplexed target reader task failed after input close"
                    ),
                }
                let active_streams =
                    mark_multiplexed_stream_target_write_closed(&state, stream_id)
                        .await
                        .map(|snapshot| snapshot.active_streams)
                        .unwrap_or_else(|| {
                            debug!(
                                %peer,
                                stream_id,
                                target_host,
                                target_port,
                                close_reason,
                                "target reader finished after stream was already removed"
                            );
                            0
                        });
                let _ = send_writer_command(&state.writer_tx, FrameCommand {
                    frame_type: FrameType::TcpClose,
                    stream_id,
                    flags: 0,
                    payload: Bytes::new(),
                }, "TCP_CLOSE", WriterLogContext::target(
                    &target_host,
                    target_port,
                    active_streams,
                )).await;
                remove_multiplexed_stream(&state, stream_id, CloseReason::ClientClosed).await;
            } else {
                remove_multiplexed_stream(&state, stream_id, CloseReason::TunnelBroken).await;
                reader_task.abort();
                let _ = reader_task.await;
            }
            close_reason
        }
    };

    log_multiplexed_stream_closed(
        peer,
        state.tunnel_id,
        stream_id,
        &target_host,
        target_port,
        opened_at,
        tunnel_to_target_bytes.load(Ordering::Relaxed),
        target_to_tunnel_bytes.load(Ordering::Relaxed),
        active_multiplexed_streams(&state).await,
        close_reason,
    );
}

async fn target_reader_loop(
    state: Arc<ServerTunnelState>,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    mut target_read: impl AsyncRead + Unpin,
    writer_tx: WriterChannels,
    transferred_counter: Arc<AtomicU64>,
) -> Result<u64> {
    let mut transferred = 0u64;
    let mut buf = [0u8; COPY_BUF_SIZE];

    loop {
        let n = timeout(RELAY_IDLE_TIMEOUT, target_read.read(&mut buf))
            .await
            .map_err(|_| anyhow!("relay idle timeout while reading from target"))??;
        if n == 0 {
            break;
        }

        transferred += n as u64;
        transferred_counter.store(transferred, Ordering::Relaxed);
        send_writer_command(
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id,
                flags: 0,
                payload: Bytes::copy_from_slice(&buf[..n]),
            },
            "TCP_DATA",
            WriterLogContext::target(
                &target_host,
                target_port,
                active_multiplexed_streams(&state).await,
            ),
        )
        .await
        .context("failed to queue TCP_DATA from target")?;
        record_multiplexed_stream_bytes(&state, stream_id, 0, n as u64).await;
    }

    Ok(transferred)
}

async fn target_writer_loop(
    _stream_id: u64,
    mut target_write: impl AsyncWrite + Unpin,
    mut rx: mpsc::Receiver<Bytes>,
    transferred_counter: Arc<AtomicU64>,
) -> Result<u64> {
    let mut transferred = 0u64;

    while let Some(bytes) = rx.recv().await {
        transferred += bytes.len() as u64;
        transferred_counter.store(transferred, Ordering::Relaxed);
        timeout(RELAY_IDLE_TIMEOUT, target_write.write_all(bytes.as_ref()))
            .await
            .map_err(|_| anyhow!("relay timeout while writing to target"))??;
    }

    timeout(RELAY_IDLE_TIMEOUT, target_write.shutdown())
        .await
        .map_err(|_| anyhow!("relay timeout while shutting down target writer"))??;
    Ok(transferred)
}

async fn fail_multiplexed_stream(state: &Arc<ServerTunnelState>, stream_id: u64, message: String) {
    let snapshot = multiplexed_stream_snapshot(state, stream_id).await;
    remove_multiplexed_stream(state, stream_id, CloseReason::TargetConnectFailed).await;
    let log_context = snapshot
        .as_ref()
        .map(|snapshot| WriterLogContext::from_meta(&snapshot.meta, snapshot.active_streams))
        .unwrap_or_else(WriterLogContext::empty);
    let _ = send_writer_command(
        &state.writer_tx,
        FrameCommand {
            frame_type: FrameType::ErrorFrame,
            stream_id,
            flags: 0,
            payload: Bytes::from(message),
        },
        "ERROR",
        log_context,
    )
    .await;
}

struct StreamCloseSnapshot {
    state: StreamState,
    meta: StreamMeta,
    active_streams: usize,
}

async fn multiplexed_stream_snapshot(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
) -> Option<StreamCloseSnapshot> {
    let streams = state.streams.lock().await;
    streams.get(&stream_id).map(|stream| StreamCloseSnapshot {
        state: stream.state,
        meta: stream.meta.clone(),
        active_streams: streams.len(),
    })
}

async fn close_multiplexed_stream_client_write(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
) -> Option<StreamCloseSnapshot> {
    let (tx_to_drop, snapshot) = {
        let mut streams = state.streams.lock().await;
        let active_streams = streams.len();
        let stream = streams.get_mut(&stream_id)?;

        let tx_to_drop = stream.tx_to_target.take();
        stream.state = match stream.state {
            StreamState::Open => StreamState::ClientWriteClosed,
            StreamState::TargetWriteClosed => StreamState::BothWriteClosed,
            StreamState::ClientWriteClosed
            | StreamState::BothWriteClosed
            | StreamState::Closing { .. }
            | StreamState::Closed => stream.state,
        };

        (
            tx_to_drop,
            StreamCloseSnapshot {
                state: stream.state,
                meta: stream.meta.clone(),
                active_streams,
            },
        )
    };

    drop(tx_to_drop);
    Some(snapshot)
}

async fn mark_multiplexed_stream_target_write_closed(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
) -> Option<StreamCloseSnapshot> {
    let mut streams = state.streams.lock().await;
    let active_streams = streams.len();
    let stream = streams.get_mut(&stream_id)?;
    stream.state = match stream.state {
        StreamState::Open => StreamState::TargetWriteClosed,
        StreamState::ClientWriteClosed => StreamState::BothWriteClosed,
        StreamState::TargetWriteClosed
        | StreamState::BothWriteClosed
        | StreamState::Closing { .. }
        | StreamState::Closed => stream.state,
    };
    Some(StreamCloseSnapshot {
        state: stream.state,
        meta: stream.meta.clone(),
        active_streams,
    })
}

async fn mark_multiplexed_stream_closing(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
    reason: CloseReason,
) -> Option<StreamCloseSnapshot> {
    let mut streams = state.streams.lock().await;
    let active_streams = streams.len();
    let stream = streams.get_mut(&stream_id)?;
    stream.state = StreamState::Closing {
        since: Instant::now(),
        reason,
    };
    Some(StreamCloseSnapshot {
        state: stream.state,
        meta: stream.meta.clone(),
        active_streams,
    })
}

async fn record_multiplexed_stream_bytes(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
    bytes_up: u64,
    bytes_down: u64,
) {
    let mut streams = state.streams.lock().await;
    if let Some(stream) = streams.get_mut(&stream_id) {
        stream.meta.bytes_up = stream.meta.bytes_up.saturating_add(bytes_up);
        stream.meta.bytes_down = stream.meta.bytes_down.saturating_add(bytes_down);
    }
}

async fn remove_multiplexed_stream(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
    reason: CloseReason,
) -> usize {
    let mut streams = state.streams.lock().await;
    let removed = streams.remove(&stream_id);
    let active_streams = streams.len();
    drop(streams);

    if let Some(mut stream) = removed {
        let last_state = stream.state;
        stream.state = StreamState::Closed;
        state.flow_control.remove_stream(stream_id).await;
        state.metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
        remember_closed_stream(state, stream_id, reason, last_state, &stream.meta).await;
    }

    active_streams
}

async fn is_multiplexed_stream_active(state: &Arc<ServerTunnelState>, stream_id: u64) -> bool {
    state.streams.lock().await.contains_key(&stream_id)
}

async fn active_multiplexed_streams(state: &Arc<ServerTunnelState>) -> usize {
    state.streams.lock().await.len()
}

async fn clear_multiplexed_streams(state: &Arc<ServerTunnelState>) -> usize {
    let mut streams = state.streams.lock().await;
    let active_streams = streams.len();
    let removed = streams.drain().collect::<Vec<_>>();
    streams.clear();
    drop(streams);

    for (stream_id, stream) in removed {
        state.flow_control.remove_stream(stream_id).await;
        state.metrics.streams_closed.fetch_add(1, Ordering::Relaxed);
        remember_closed_stream(
            state,
            stream_id,
            CloseReason::PhysicalTunnelClosed,
            stream.state,
            &stream.meta,
        )
        .await;
    }

    active_streams
}

async fn remember_closed_stream(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
    reason: CloseReason,
    last_state: StreamState,
    meta: &StreamMeta,
) {
    let now = Instant::now();
    let mut recently_closed = state.recently_closed_streams.lock().await;
    prune_recently_closed_streams(&mut recently_closed, now);
    recently_closed.insert(
        stream_id,
        ClosedStreamInfo {
            closed_at: now,
            reason,
            bytes_up: meta.bytes_up,
            bytes_down: meta.bytes_down,
            last_state,
        },
    );
}

async fn recently_closed_stream_info(
    state: &Arc<ServerTunnelState>,
    stream_id: u64,
) -> Option<ClosedStreamInfo> {
    let now = Instant::now();
    let mut recently_closed = state.recently_closed_streams.lock().await;
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
    state: &Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    payload_len: usize,
) {
    if let Some(info) = recently_closed_stream_info(state, stream_id).await {
        state.metrics.late_data.fetch_add(1, Ordering::Relaxed);
        debug!(
            %peer,
            tunnel_id = state.tunnel_id,
            stream_id,
            closed_ago_ms = elapsed_millis(info.closed_at.elapsed()),
            closed_reason = ?info.reason,
            bytes_up = info.bytes_up,
            bytes_down = info.bytes_down,
            last_state = ?info.last_state,
            payload_len,
            "late TCP_DATA for recently closed multiplexed stream"
        );
    } else {
        state
            .metrics
            .unknown_stream_data
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            %peer,
            tunnel_id = state.tunnel_id,
            stream_id,
            payload_len,
            "dropping TCP_DATA for unknown multiplexed stream"
        );
    }
}

async fn log_unknown_or_recently_closed_tcp_close(
    state: &Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    fallback_reason: CloseReason,
) {
    if let Some(info) = recently_closed_stream_info(state, stream_id).await {
        state.metrics.late_close.fetch_add(1, Ordering::Relaxed);
        debug!(
            %peer,
            tunnel_id = state.tunnel_id,
            stream_id,
            closed_ago_ms = elapsed_millis(info.closed_at.elapsed()),
            closed_reason = ?info.reason,
            bytes_up = info.bytes_up,
            bytes_down = info.bytes_down,
            last_state = ?info.last_state,
            "late TCP_CLOSE for recently closed multiplexed stream"
        );
    } else {
        state
            .metrics
            .unknown_stream_close
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            %peer,
            tunnel_id = state.tunnel_id,
            stream_id,
            close_reason = ?fallback_reason,
            "ignoring TCP_CLOSE for unknown multiplexed stream"
        );
    }
}

async fn send_writer_command(
    writer_tx: &WriterChannels,
    cmd: FrameCommand,
    operation: &'static str,
    log_context: WriterLogContext<'_>,
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
                    format!("failed to reserve writer buffer for multiplexed stream {stream_id}")
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
        .with_context(|| format!("failed to queue {operation} for multiplexed tunnel"))?;

    let wait = started.elapsed();
    let wait_ms = elapsed_millis(wait);
    writer_tx.metrics.record_writer_wait(wait_ms).await;
    if frame_type == FrameType::TcpData {
        writer_tx
            .metrics
            .bytes_down
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            tunnel_id = writer_tx.tunnel_id,
            stream_id,
            target_host = %log_context.target_host.unwrap_or("<unknown>"),
            target_port = log_context.target_port.unwrap_or_default(),
            frame_type = %frame_type,
            payload_len,
            writer_queue_capacity = queue.capacity,
            writer_queue_available = queue.available,
            writer_queue_depth = queue.depth,
            writer_channel_send_wait_ms = wait_ms,
            active_streams = log_context.active_streams.unwrap_or_default(),
            "multiplexed tunnel writer channel send waited"
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct WriterLogContext<'a> {
    target_host: Option<&'a str>,
    target_port: Option<u16>,
    active_streams: Option<usize>,
}

impl<'a> WriterLogContext<'a> {
    fn empty() -> Self {
        Self {
            target_host: None,
            target_port: None,
            active_streams: None,
        }
    }

    fn target(target_host: &'a str, target_port: u16, active_streams: usize) -> Self {
        Self {
            target_host: Some(target_host),
            target_port: Some(target_port),
            active_streams: Some(active_streams),
        }
    }

    fn from_meta(meta: &'a StreamMeta, active_streams: usize) -> Self {
        Self::target(&meta.target_host, meta.target_port, active_streams)
    }
}

#[derive(Debug, Clone, Copy)]
struct WriterQueueMetrics {
    capacity: usize,
    available: usize,
    depth: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct WriterQueueDepthSnapshot {
    control: usize,
    data: usize,
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
    tunnel_id: u64,
    capacity: usize,
    flow_control: Arc<TunnelFlowControl>,
    metrics: Arc<ServerTunnelMetrics>,
) -> (
    WriterChannels,
    mpsc::Receiver<WriterCommand>,
    mpsc::Receiver<WriterCommand>,
) {
    let (control_tx, control_rx) = mpsc::channel(capacity);
    let (data_tx, data_rx) = mpsc::channel(capacity);
    (
        WriterChannels {
            tunnel_id,
            control_tx,
            data_tx,
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

    fn queue_depth_snapshot(&self) -> WriterQueueDepthSnapshot {
        WriterQueueDepthSnapshot {
            control: writer_queue_metrics(&self.control_tx).depth,
            data: writer_queue_metrics(&self.data_tx).depth,
        }
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

fn log_multiplexed_stream_closed(
    peer: SocketAddr,
    tunnel_id: u64,
    stream_id: u64,
    target_host: &str,
    target_port: u16,
    opened_at: Instant,
    bytes_up: u64,
    bytes_down: u64,
    active_streams: usize,
    close_reason: &'static str,
) {
    let duration = opened_at.elapsed();
    debug!(
        %peer,
        tunnel_id,
        stream_id,
        target_host,
        target_port,
        duration_ms = elapsed_millis(duration),
        bytes_up,
        bytes_down,
        mbps = mbps(bytes_up + bytes_down, duration),
        active_streams,
        close_reason,
        "multiplexed TCP stream closed"
    );
}

impl MultiplexStream {
    fn new(
        stream_id: u64,
        target_host: String,
        target_port: u16,
        tx_to_target: TargetStreamTx,
    ) -> Self {
        Self {
            tx_to_target: Some(tx_to_target),
            state: StreamState::Open,
            meta: StreamMeta {
                stream_id,
                target_host,
                target_port,
                created_at: Instant::now(),
                bytes_up: 0,
                bytes_down: 0,
            },
        }
    }
}

pub async fn relay_tunnel<S>(mut tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_stream))
        .await
        .map_err(|_| anyhow!("timed out waiting for first tunnel frame"))??;

    match first_frame.frame_type {
        FrameType::TcpConnect => relay_tcp_tunnel(tunnel_stream, peer, first_frame).await,
        FrameType::UdpAssociateRequest => {
            relay_udp_association(tunnel_stream, peer, first_frame).await
        }
        other => {
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                first_frame.stream_id,
                0,
                Bytes::from_static(b"expected TCP_CONNECT or UDP_ASSOCIATE_REQUEST as first frame"),
            )
            .await?;
            bail!("first frame from peer {peer} is not a tunnel open request: {other}");
        }
    }
}

async fn relay_tcp_tunnel<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    connect_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = connect_request.stream_id;
    let (target_host, target_port) =
        decode_tcp_connect_payload(connect_request.payload.as_ref())
            .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;

    let target_connect_started = Instant::now();
    let mut target_stream = match timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    {
        Err(_) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("timed out connecting target {target_host}:{target_port}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect timed out"
            );
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
        Ok(Ok(stream)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            stream.set_nodelay(true).with_context(|| {
                format!(
                    "failed to enable TCP_NODELAY for target connection {target_host}:{target_port}"
                )
            })?;

            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect finished"
            );

            stream
        }
        Ok(Err(err)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                error = %err,
                "target TCP connect failed"
            );
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };
    let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());

    write_frame(
        &mut tunnel_stream,
        FrameType::TcpConnect,
        stream_id,
        CONNECT_OK_FLAG,
        Bytes::new(),
    )
    .await?;

    let relay_started = Instant::now();
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);
    let (mut target_read, mut target_write) = target_stream.split();

    let tunnel_to_target = async {
        let mut transferred = 0u64;

        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from tunnel peer"))??;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::TcpData => {
                    transferred += frame.payload.len() as u64;
                    timeout(
                        RELAY_IDLE_TIMEOUT,
                        target_write.write_all(frame.payload.as_ref()),
                    )
                    .await
                    .map_err(|_| anyhow!("relay timeout while writing to target"))??;
                }
                FrameType::TcpClose => {
                    timeout(RELAY_IDLE_TIMEOUT, target_write.shutdown())
                        .await
                        .map_err(|_| {
                            anyhow!("relay timeout while shutting down target writer")
                        })??;
                    break;
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during relay: {other}"),
            }
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let target_to_tunnel = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; COPY_BUF_SIZE];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, target_read.read(&mut buf))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from target"))??;
            if n == 0 {
                timeout(
                    RELAY_IDLE_TIMEOUT,
                    write_frame(
                        &mut tunnel_write,
                        FrameType::TcpClose,
                        stream_id,
                        0,
                        Bytes::new(),
                    ),
                )
                .await
                .map_err(|_| anyhow!("relay timeout while writing TCP_CLOSE to tunnel"))??;
                timeout(RELAY_IDLE_TIMEOUT, tunnel_write.shutdown())
                    .await
                    .map_err(|_| anyhow!("relay timeout while shutting down tunnel writer"))??;
                break;
            }

            transferred += n as u64;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::TcpData,
                    stream_id,
                    0,
                    Bytes::copy_from_slice(&buf[..n]),
                ),
            )
            .await
            .map_err(|_| anyhow!("relay timeout while writing TCP_DATA to tunnel"))??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let (upstream_to_target_bytes, target_to_upstream_bytes) =
        tokio::try_join!(tunnel_to_target, target_to_tunnel)?;
    let relay_elapsed = relay_started.elapsed();
    let total_bytes = upstream_to_target_bytes + target_to_upstream_bytes;
    let mbps = mbps(total_bytes, relay_elapsed);

    debug!(
        %peer,
        stream_id,
        target_host,
        target_port,
        target_tcp_connect_ms,
        upstream_to_target_bytes,
        target_to_upstream_bytes,
        total_bytes,
        duration_ms = elapsed_millis(relay_elapsed),
        mbps,
        "tunnel relay finished"
    );

    Ok(())
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn mbps(total_bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds > 0.0 {
        (total_bytes as f64 * 8.0) / seconds / 1_000_000.0
    } else {
        0.0
    }
}

async fn relay_udp_association<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    associate_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = associate_request.stream_id;
    let udp_socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await {
        Ok(socket) => socket,
        Err(err) => {
            let message = format!("failed to bind remote UDP socket: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };

    let bind_addr = match udp_socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            let message = format!("failed to inspect remote UDP bind address: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };
    let response_payload =
        encode_udp_associate_response_payload(&bind_addr.ip().to_string(), bind_addr.port())
            .map_err(|err| anyhow!("failed to encode UDP associate response: {err}"))?;
    write_frame(
        &mut tunnel_stream,
        FrameType::UdpAssociateResponse,
        stream_id,
        CONNECT_OK_FLAG,
        response_payload,
    )
    .await?;

    let counters = Arc::new(UdpRelayCounters::default());
    let udp_socket = Arc::new(udp_socket);
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);

    let tunnel_to_udp_socket = Arc::clone(&udp_socket);
    let tunnel_to_udp_counters = Arc::clone(&counters);
    let tunnel_to_udp = async move {
        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from tunnel peer"))??;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::UdpDatagram => {
                    let datagram = decode_udp_datagram(frame.payload.as_ref())
                        .map_err(|err| anyhow!("invalid UDP_DATAGRAM payload: {err}"))?;
                    let sent = timeout(
                        RELAY_IDLE_TIMEOUT,
                        tunnel_to_udp_socket.send_to(
                            datagram.payload.as_ref(),
                            (datagram.target_host.as_str(), datagram.target_port),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow!("udp relay timeout while sending datagram"))??;
                    tunnel_to_udp_counters.record_tunnel_to_udp(sent as u64);
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during udp relay: {other}"),
            }
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let udp_to_tunnel_socket = Arc::clone(&udp_socket);
    let udp_to_tunnel_counters = Arc::clone(&counters);
    let udp_to_tunnel = async move {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        loop {
            let (n, source) = timeout(RELAY_IDLE_TIMEOUT, udp_to_tunnel_socket.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from udp socket"))??;
            let payload = encode_udp_datagram(&UdpDatagram {
                target_host: source.ip().to_string(),
                target_port: source.port(),
                payload: Bytes::copy_from_slice(&buf[..n]),
                association_id: None,
            })
            .map_err(|err| anyhow!("failed to encode UDP_DATAGRAM payload: {err}"))?;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::UdpDatagram,
                    stream_id,
                    0,
                    payload,
                ),
            )
            .await
            .map_err(|_| anyhow!("udp relay timeout while writing UDP_DATAGRAM to tunnel"))??;
            udp_to_tunnel_counters.record_udp_to_tunnel(n as u64);
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let result = tokio::try_join!(tunnel_to_udp, udp_to_tunnel);
    let snapshot = counters.snapshot();
    match &result {
        Ok(_) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            "udp tunnel relay finished"
        ),
        Err(err) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            error = %err,
            "udp tunnel relay stopped"
        ),
    }

    result.map(|_| ())
}

#[derive(Default)]
struct UdpRelayCounters {
    tunnel_to_udp_datagrams: AtomicU64,
    tunnel_to_udp_bytes: AtomicU64,
    udp_to_tunnel_datagrams: AtomicU64,
    udp_to_tunnel_bytes: AtomicU64,
}

impl UdpRelayCounters {
    fn record_tunnel_to_udp(&self, bytes: u64) {
        self.tunnel_to_udp_datagrams.fetch_add(1, Ordering::Relaxed);
        self.tunnel_to_udp_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_udp_to_tunnel(&self, bytes: u64) {
        self.udp_to_tunnel_datagrams.fetch_add(1, Ordering::Relaxed);
        self.udp_to_tunnel_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UdpRelayCounterSnapshot {
        UdpRelayCounterSnapshot {
            tunnel_to_udp_datagrams: self.tunnel_to_udp_datagrams.load(Ordering::Relaxed),
            tunnel_to_udp_bytes: self.tunnel_to_udp_bytes.load(Ordering::Relaxed),
            udp_to_tunnel_datagrams: self.udp_to_tunnel_datagrams.load(Ordering::Relaxed),
            udp_to_tunnel_bytes: self.udp_to_tunnel_bytes.load(Ordering::Relaxed),
        }
    }
}

struct UdpRelayCounterSnapshot {
    tunnel_to_udp_datagrams: u64,
    tunnel_to_udp_bytes: u64,
    udp_to_tunnel_datagrams: u64,
    udp_to_tunnel_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{
        UdpDatagram, decode_udp_associate_response_payload, encode_tcp_connect_payload,
        encode_udp_datagram,
    };
    use std::collections::{HashMap, HashSet};
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    fn test_flow_control() -> Arc<TunnelFlowControl> {
        Arc::new(TunnelFlowControl::new(
            1_048_576,
            16_777_216,
            STREAM_CHANNEL_CAPACITY,
        ))
    }

    fn test_writer_channels(
        capacity: usize,
    ) -> (
        WriterChannels,
        mpsc::Receiver<WriterCommand>,
        mpsc::Receiver<WriterCommand>,
    ) {
        writer_channels(
            0,
            capacity,
            test_flow_control(),
            Arc::new(ServerTunnelMetrics::new()),
        )
    }

    fn test_writer_command(frame: FrameCommand) -> WriterCommand {
        WriterCommand {
            frame,
            _flow_permit: None,
        }
    }

    #[tokio::test]
    async fn multiplexed_dispatch_sends_tcp_data_to_registered_stream() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            tunnel_id: 0,
            streams: Mutex::new(HashMap::new()),
            recently_closed_streams: Mutex::new(HashMap::new()),
            flow_control: Arc::clone(&writer_tx.flow_control),
            metrics: Arc::clone(&writer_tx.metrics),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state
            .streams
            .lock()
            .await
            .insert(9, test_stream(9, stream_tx));
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;

        dispatch_tcp_data_to_target(
            Arc::clone(&state),
            peer,
            Frame {
                frame_type: FrameType::TcpData,
                stream_id: 9,
                flags: 0,
                payload: Bytes::from_static(b"payload"),
            },
        )
        .await?;

        let payload = timeout(Duration::from_secs(1), stream_rx.recv())
            .await?
            .expect("stream payload");
        assert_eq!(payload, Bytes::from_static(b"payload"));
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_remove_stream_drops_target_input_sender() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            tunnel_id: 0,
            streams: Mutex::new(HashMap::new()),
            recently_closed_streams: Mutex::new(HashMap::new()),
            flow_control: Arc::clone(&writer_tx.flow_control),
            metrics: Arc::clone(&writer_tx.metrics),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state
            .streams
            .lock()
            .await
            .insert(21, test_stream(21, stream_tx));

        remove_multiplexed_stream(&state, 21, CloseReason::TargetClosed).await;

        assert!(stream_rx.recv().await.is_none());
        assert!(!is_multiplexed_stream_active(&state, 21).await);
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_physical_tunnel_cleanup_drops_all_stream_inputs() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            tunnel_id: 0,
            streams: Mutex::new(HashMap::new()),
            recently_closed_streams: Mutex::new(HashMap::new()),
            flow_control: Arc::clone(&writer_tx.flow_control),
            metrics: Arc::clone(&writer_tx.metrics),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (first_tx, mut first_rx) = mpsc::channel(1);
        let (second_tx, mut second_rx) = mpsc::channel(1);
        state
            .streams
            .lock()
            .await
            .insert(23, test_stream(23, first_tx));
        state
            .streams
            .lock()
            .await
            .insert(25, test_stream(25, second_tx));

        state.streams.lock().await.clear();

        assert!(first_rx.recv().await.is_none());
        assert!(second_rx.recv().await.is_none());
        assert!(state.streams.lock().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_client_close_keeps_stream_entry_until_target_finishes() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            tunnel_id: 0,
            streams: Mutex::new(HashMap::new()),
            recently_closed_streams: Mutex::new(HashMap::new()),
            flow_control: Arc::clone(&writer_tx.flow_control),
            metrics: Arc::clone(&writer_tx.metrics),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state
            .streams
            .lock()
            .await
            .insert(29, test_stream(29, stream_tx));

        let snapshot = close_multiplexed_stream_client_write(&state, 29)
            .await
            .expect("stream close snapshot");

        assert_eq!(snapshot.state, StreamState::ClientWriteClosed);
        assert!(stream_rx.recv().await.is_none());
        assert!(is_multiplexed_stream_active(&state, 29).await);
        assert_eq!(
            state
                .streams
                .lock()
                .await
                .get(&29)
                .map(|stream| stream.state),
            Some(StreamState::ClientWriteClosed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_late_tcp_data_for_client_closed_stream_is_ignored() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            tunnel_id: 0,
            streams: Mutex::new(HashMap::new()),
            recently_closed_streams: Mutex::new(HashMap::new()),
            flow_control: Arc::clone(&writer_tx.flow_control),
            metrics: Arc::clone(&writer_tx.metrics),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state
            .streams
            .lock()
            .await
            .insert(31, test_stream(31, stream_tx));
        close_multiplexed_stream_client_write(&state, 31).await;
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;

        dispatch_tcp_data_to_target(
            Arc::clone(&state),
            peer,
            Frame {
                frame_type: FrameType::TcpData,
                stream_id: 31,
                flags: 0,
                payload: Bytes::from_static(b"late"),
            },
        )
        .await?;

        assert!(stream_rx.recv().await.is_none());
        assert!(is_multiplexed_stream_active(&state, 31).await);
        Ok(())
    }

    #[tokio::test]
    async fn target_writer_finishes_when_stream_input_is_dropped() -> Result<()> {
        let (target_side, mut peer_side) = duplex(1024);
        let (_target_read, target_write) = tokio::io::split(target_side);
        let (tx, rx) = mpsc::channel(1);
        drop(tx);

        let transferred =
            target_writer_loop(27, target_write, rx, Arc::new(AtomicU64::new(0))).await?;

        assert_eq!(transferred, 0);
        let mut buf = [0u8; 1];
        let n = timeout(Duration::from_secs(1), peer_side.read(&mut buf)).await??;
        assert_eq!(n, 0);
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_writer_loop_serializes_frame_commands() -> Result<()> {
        let (stream, mut peer) = duplex(1024);
        let (_read_half, write_half) = tokio::io::split(stream);
        let (tx, control_rx, data_rx) = test_writer_channels(1);
        let metrics = Arc::clone(&tx.metrics);
        let writer = tokio::spawn(server_tunnel_writer_loop(
            0, write_half, control_rx, data_rx, metrics,
        ));

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"hello"),
            }))
            .await?;
        drop(tx);

        let frame = timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
        writer.await?;

        assert_eq!(frame.frame_type, FrameType::TcpData);
        assert_eq!(frame.stream_id, 13);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_writer_receive_keeps_tcp_close_in_data_order() -> Result<()> {
        let (tx, mut control_rx, mut data_rx) = test_writer_channels(2);

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"data"),
            }))
            .await?;
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id: 13,
                flags: 0,
                payload: Bytes::new(),
            }))
            .await?;

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
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_writer_receive_schedules_data_fairly_between_streams() -> Result<()> {
        let (tx, mut control_rx, mut data_rx) = test_writer_channels(4);

        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"first"),
            }))
            .await?;
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"second"),
            }))
            .await?;
        tx.data_tx
            .send(test_writer_command(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 15,
                flags: 0,
                payload: Bytes::from_static(b"small"),
            }))
            .await?;

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

        assert_eq!(first.frame.stream_id, 13);
        assert_eq!(second.frame.stream_id, 15);
        assert_eq!(third.frame.stream_id, 13);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn multiplexed_tunnel_relays_tcp_data_for_multiple_streams() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = listener.local_addr()?;
        let echo_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = socket.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        socket.write_all(&buf[..n]).await?;
                    }
                    Ok::<(), std::io::Error>(())
                });
            }
            Ok::<(), std::io::Error>(())
        });

        let (mut client_side, server_side) = duplex(128 * 1024);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;
        let relay_task = tokio::spawn(relay_multiplexed_tunnel(server_side, peer));

        for (stream_id, payload) in [(1, b"one".as_slice()), (3, b"three".as_slice())] {
            write_frame(
                &mut client_side,
                FrameType::TcpConnect,
                stream_id,
                0,
                encode_tcp_connect_payload(&target_addr.ip().to_string(), target_addr.port())?,
            )
            .await?;
            write_frame(
                &mut client_side,
                FrameType::TcpData,
                stream_id,
                0,
                Bytes::copy_from_slice(payload),
            )
            .await?;
        }

        let mut connected = HashSet::new();
        let mut echoed = HashMap::new();
        while connected.len() < 2 || echoed.len() < 2 {
            let frame = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
            match frame.frame_type {
                FrameType::TcpConnect => {
                    assert_ne!(frame.flags & CONNECT_OK_FLAG, 0);
                    connected.insert(frame.stream_id);
                }
                FrameType::TcpData => {
                    echoed.insert(frame.stream_id, frame.payload);
                }
                other => bail!("unexpected frame from multiplexed tunnel: {other}"),
            }
        }

        assert!(connected.contains(&1));
        assert!(connected.contains(&3));
        assert_eq!(echoed.get(&1), Some(&Bytes::from_static(b"one")));
        assert_eq!(echoed.get(&3), Some(&Bytes::from_static(b"three")));

        write_frame(&mut client_side, FrameType::TcpClose, 1, 0, Bytes::new()).await?;
        write_frame(&mut client_side, FrameType::TcpClose, 3, 0, Bytes::new()).await?;
        drop(client_side);

        echo_task.await??;
        timeout(Duration::from_secs(2), relay_task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn udp_associate_relays_datagrams_both_directions() -> Result<()> {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo_socket.local_addr()?;
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = echo_socket.recv_from(&mut buf).await?;
            echo_socket.send_to(&buf[..n], peer).await?;
            Ok::<(), std::io::Error>(())
        });

        let (mut client_side, server_side) = duplex(128 * 1024);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;
        let relay_task = tokio::spawn(relay_tunnel(server_side, peer));

        write_frame(
            &mut client_side,
            FrameType::UdpAssociateRequest,
            77,
            0,
            Bytes::new(),
        )
        .await?;

        let response = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(response.frame_type, FrameType::UdpAssociateResponse);
        assert_eq!(response.stream_id, 77);
        assert_ne!(response.flags & CONNECT_OK_FLAG, 0);
        let (_bind_host, bind_port) =
            decode_udp_associate_response_payload(response.payload.as_ref())?;
        assert_ne!(bind_port, 0);

        let datagram_payload = encode_udp_datagram(&UdpDatagram {
            target_host: echo_addr.ip().to_string(),
            target_port: echo_addr.port(),
            payload: Bytes::from_static(b"ping"),
            association_id: None,
        })?;
        write_frame(
            &mut client_side,
            FrameType::UdpDatagram,
            77,
            0,
            datagram_payload,
        )
        .await?;

        let reply = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(reply.frame_type, FrameType::UdpDatagram);
        assert_eq!(reply.stream_id, 77);
        let reply = decode_udp_datagram(reply.payload.as_ref())?;
        assert_eq!(reply.target_host, echo_addr.ip().to_string());
        assert_eq!(reply.target_port, echo_addr.port());
        assert_eq!(reply.payload, Bytes::from_static(b"ping"));

        echo_task.await??;
        relay_task.abort();
        let _ = relay_task.await;
        Ok(())
    }

    fn test_stream(stream_id: u64, tx_to_target: TargetStreamTx) -> MultiplexStream {
        MultiplexStream::new(stream_id, "example.test".to_owned(), 443, tx_to_target)
    }
}

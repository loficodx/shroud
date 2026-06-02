# Shroud TCP Transport Refactor Plan

## Цель

Перевести проект на простую и поддерживаемую TCP-архитектуру с двумя режимами:

1. `fast_tcp` — максимальная скорость.
2. `balanced_tcp` — баланс маскировки и скорости.

При этом убрать из основного TCP-пути:

- multiplexing;
- custom `FrameType::TcpData` relay protocol;
- `stream_id` для обычного TCP `CONNECT`;
- `mpsc`/scheduler/flow-control в TCP hot path;
- `HTTP Upgrade: shroud-tunnel` как основной транспорт.

Ключевой принцип:

```text
1 SOCKS CONNECT = 1 transport connection = 1 target TCP connection
```

После успешного `CONNECT OK` TCP payload должен идти как raw byte stream через `copy_bidirectional` или `copy_bidirectional_with_sizes`, без внутреннего `TcpData` framing.

---

## Текущая проблема в коде

Сейчас даже non-multiplexed TCP path фактически не является raw relay.

Текущая схема:

```text
SOCKS client
  -> shroud-client
  -> TLS/plain TCP
  -> HTTP/1.1 Upgrade: shroud-tunnel
  -> shroud frame protocol
  -> shroud-server
  -> target TCP
```

Даже при `multiplex = false` TCP-трафик идёт через:

```text
FrameType::TcpConnect
FrameType::TcpData
FrameType::TcpClose
FrameType::ErrorFrame
```

Это создаёт лишнюю работу на каждый chunk:

```text
read from socket
-> Bytes::copy_from_slice
-> encode frame header
-> write frame
-> read frame
-> allocate/decode payload
-> write to target
```

Для multiplexing это оправдано, потому что нужно различать logical streams. Для режима `1 CONNECT = 1 connection` это лишний overhead и лишняя сложность.

---

## Итоговая архитектура

### Режим 1: `fast_tcp`

Назначение: максимальная скорость.

```text
SOCKS5 local
  -> TLS/plain TCP to shroud-server
  -> small binary CONNECT request
  -> status byte
  -> raw bidirectional relay
```

После `status = OK`:

```text
client socket <-> transport stream <-> target socket
```

Без:

- HTTP;
- WebSocket;
- H2;
- `FrameType::TcpData`;
- `stream_id`;
- multiplexing;
- custom per-chunk frames.

### Режим 2: `balanced_tcp`

Назначение: нормальная маскировка под HTTPS при приемлемой скорости.

Рекомендуемый вариант:

```text
SOCKS5 local
  -> TLS 443
  -> HTTP/2 request to normal-looking path
  -> auth + target metadata
  -> server connects target
  -> streaming body = raw proxied bytes
```

Снаружи:

```text
https://domain.com/              -> normal fallback website
https://domain.com/api/v1/events -> shroud balanced_tcp endpoint
```

Важно: внутри HTTP/2 DATA frames не должно быть дополнительного `TcpData` framing.

Плохо:

```text
HTTP/2 DATA frame
  -> Shroud TcpData frame
    -> payload
```

Хорошо:

```text
HTTP/2 DATA frame
  -> raw proxied bytes
```

---

## Новые режимы транспорта

Ввести явный enum вместо текущего набора `tls`, `path`, `multiplex`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpTransportMode {
    FastTcp,
    BalancedTcp,
}
```

Для конфига лучше использовать строку:

```yaml
transport:
  tcp_mode: fast_tcp
```

или:

```yaml
transport:
  tcp_mode: balanced_tcp
```

Для расширения можно использовать более явную структуру:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    pub tcp_mode: TcpTransportMode,
    pub server: String,
    pub port: u16,
    pub tls: bool,
    pub tls_server_name: Option<String>,
    pub tls_ca_cert_path: Option<String>,
    pub path: Option<String>,
    pub http_version: Option<HttpVersion>,
}
```

Где:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    H2,
}
```

---

## Новый пример client config

### `fast_tcp`

```yaml
inbound:
  enabled: true
  listen: "127.0.0.1:1080"

transport:
  tcp_mode: fast_tcp
  server: "your-domain.com"
  port: 443
  tls: true
  tls_server_name: "your-domain.com"
  tls_ca_cert_path: null

auth:
  client_id: "client-1"
  client_secret: "change-me"

relay:
  buffer_size: 65536
  tcp_nodelay: true
  connect_timeout_ms: 5000
  idle_timeout_sec: 300
```

### `balanced_tcp`

```yaml
inbound:
  enabled: true
  listen: "127.0.0.1:1080"

transport:
  tcp_mode: balanced_tcp
  server: "your-domain.com"
  port: 443
  tls: true
  tls_server_name: "your-domain.com"
  path: "/api/v1/events"
  http_version: h2

auth:
  client_id: "client-1"
  client_secret: "change-me"

relay:
  buffer_size: 65536
  tcp_nodelay: true
  connect_timeout_ms: 5000
  idle_timeout_sec: 300
```

---

## Новый пример server config

```yaml
server:
  listen: "127.0.0.1:9001"

auth:
  clients:
    - client_id: "client-1"
      client_secret: "change-me"

transport:
  tcp_modes:
    - fast_tcp
    - balanced_tcp
  balanced_path: "/api/v1/events"

relay:
  buffer_size: 65536
  tcp_nodelay: true
  connect_timeout_ms: 5000
  idle_timeout_sec: 300
```

Если сервер слушает `443` напрямую для `fast_tcp`:

```yaml
server:
  listen: "0.0.0.0:443"
  tls:
    enabled: true
    cert: "/etc/letsencrypt/live/domain/fullchain.pem"
    key: "/etc/letsencrypt/live/domain/privkey.pem"
```

Если `balanced_tcp` идёт через Caddy/Nginx, `shroud-server` слушает локально:

```yaml
server:
  listen: "127.0.0.1:9001"
```

---

# Этапы реализации

## ~~Этап 0. Создать baseline-ветку и зафиксировать текущие тесты~~

Цель: иметь точку сравнения до удаления multiplexing/custom frames.

### Действия

1. Создать отдельную ветку:

```bash
git checkout -b refactor/tcp-transports
```

2. Зафиксировать текущие результаты:

```text
iperf3 client -> VPS
iperf3 VPS -> client (-R)
Dante SOCKS speed
current shroud non-multiplex speed
current shroud multiplex speed
```

3. Добавить `BENCHMARKS.md` или раздел в новый документ:

```text
Date
VPS location/provider
Client ISP/location
Mode
Command
Result
Notes
```

### Критерий готовности

Есть исходные цифры, с которыми можно сравнить `fast_tcp` и `balanced_tcp`.

---

## ~~Этап 1. Ввести новый transport config~~

Цель: убрать неявную логику `multiplex: bool` как переключатель основной архитектуры.

### Файлы

- `crates/shroud-core/src/config.rs`
- client/server config examples
- tests в `shroud-core`

### Действия

1. Добавить enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpTransportMode {
    FastTcp,
    BalancedTcp,
}
```

2. Добавить новую структуру:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    #[serde(default = "default_tcp_mode")]
    pub tcp_mode: TcpTransportMode,

    pub server: String,
    pub port: u16,

    #[serde(default = "default_true")]
    pub tls: bool,

    #[serde(default)]
    pub tls_server_name: Option<String>,

    #[serde(default)]
    pub tls_ca_cert_path: Option<String>,

    #[serde(default)]
    pub path: Option<String>,
}
```

3. Временно оставить старый `OutboundConfig`, но сделать compatibility mapping:

```text
old outbound.multiplex = true  -> unsupported / warning
old outbound.multiplex = false -> transport.tcp_mode = fast_tcp или legacy_http_upgrade_framed на время миграции
```

4. Добавить warning при использовании старых полей:

```text
outbound.multiplex is deprecated and will be removed
outbound.path with custom HTTP Upgrade is deprecated
```

### Критерий готовности

- Старые конфиги ещё читаются.
- Новые конфиги читаются.
- В логах видно выбранный `tcp_mode`.

---

## ~~Этап 2. Вынести transport layer в отдельные модули~~

Цель: прекратить смешивать SOCKS/session logic, HTTP Upgrade, auth, TLS и relay в одном `tunnel.rs`.

### Новая структура client

```text
crates/shroud-client/src/transport/
  mod.rs
  fast_tcp.rs
  balanced_tcp.rs
  tls.rs
  http.rs
```

### Новая структура server

```text
crates/shroud-server/src/transport/
  mod.rs
  fast_tcp.rs
  balanced_tcp.rs
  tls.rs
```

### Общие типы в core

```text
crates/shroud-core/src/tcp_handshake.rs
crates/shroud-core/src/relay.rs
```

### Действия

1. Создать trait на client side:

```rust
#[async_trait::async_trait]
pub trait TcpTransport {
    async fn connect(&self, target_host: &str, target_port: u16) -> anyhow::Result<BoxedIo>;
}
```

Где `BoxedIo`:

```rust
pub type BoxedIo = Box<dyn AsyncReadWrite + Send + Unpin>;
```

Из-за object-safety проще сделать local trait:

```rust
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}
```

2. `SessionCore` должен работать с абстракцией:

```text
SOCKS request -> transport.connect(target) -> raw relay
```

3. Убрать прямую зависимость session на `TunnelPool`/`TunnelStreamHandle` для нового TCP path.

### Критерий готовности

`SessionCore` больше не знает про frame protocol для обычного TCP `CONNECT`.

---

## ~~Этап 3. Реализовать `fast_tcp` handshake без `FrameType`~~

Цель: заменить `TcpConnect` frame на простой одноразовый binary handshake.

### Новый handshake protocol

Минимальный формат:

```text
client -> server:
  4 bytes  magic = "SHRD"
  1 byte   version = 1
  1 byte   command = 1 CONNECT
  1 byte   auth_len
  N bytes  auth/client proof or token
  1 byte   host_len
  N bytes  host UTF-8
  2 bytes  port big-endian

server -> client:
  1 byte status
    0x00 OK
    0x01 auth failed
    0x02 invalid request
    0x03 connect failed
    0x04 forbidden
```

После `status = 0x00` начинается raw stream.

### Файл

```text
crates/shroud-core/src/tcp_handshake.rs
```

### Типы

```rust
pub struct TcpConnectRequest {
    pub host: String,
    pub port: u16,
    pub auth: ClientAuthProof,
}

pub enum TcpConnectStatus {
    Ok,
    AuthFailed,
    InvalidRequest,
    ConnectFailed,
    Forbidden,
}
```

### Функции

```rust
pub async fn write_fast_connect_request<W>(writer: &mut W, req: &TcpConnectRequest) -> Result<(), Error>
where
    W: AsyncWrite + Unpin;

pub async fn read_fast_connect_request<R>(reader: &mut R) -> Result<TcpConnectRequest, Error>
where
    R: AsyncRead + Unpin;

pub async fn write_fast_connect_status<W>(writer: &mut W, status: TcpConnectStatus) -> Result<(), Error>
where
    W: AsyncWrite + Unpin;

pub async fn read_fast_connect_status<R>(reader: &mut R) -> Result<TcpConnectStatus, Error>
where
    R: AsyncRead + Unpin;
```

### Важно

Не использовать `Frame`, `FrameType`, `stream_id`, `Bytes`, `MAX_FRAME_PAYLOAD_LEN` в `fast_tcp`.

### Критерий готовности

Юнит-тесты handshake:

- valid domain;
- valid IPv4-as-string;
- invalid empty host;
- too long host;
- port 0 rejected;
- auth failed status;
- partial read fails safely.

---

## ~~Этап 4. Реализовать client `fast_tcp`~~

Цель: client открывает transport connection, отправляет handshake, получает `OK`, возвращает raw stream.

### Файл

```text
crates/shroud-client/src/transport/fast_tcp.rs
```

### Логика

```text
TcpStream::connect(server:port)
set_nodelay(true)
optional TLS handshake
write_fast_connect_request(target)
read_fast_connect_status()
if OK -> return stream
else -> error
```

### Псевдокод

```rust
pub async fn connect_fast_tcp(
    cfg: &ClientConfig,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo> {
    let mut stream = TcpStream::connect((cfg.server, cfg.port)).await?;
    stream.set_nodelay(true)?;

    let mut stream = maybe_tls_connect(stream, cfg).await?;

    let req = TcpConnectRequest::new(target_host, target_port, auth_proof);
    write_fast_connect_request(&mut stream, &req).await?;

    let status = read_fast_connect_status(&mut stream).await?;
    ensure!(status == TcpConnectStatus::Ok, "connect rejected: {status:?}");

    Ok(Box::new(stream))
}
```

### Критерий готовности

Client может получить raw tunnel stream без `write_frame/read_frame`.

---

## ~~Этап 5. Реализовать server `fast_tcp`~~

Цель: server принимает connection, читает handshake, подключается к target, возвращает status, запускает raw relay.

### Файл

```text
crates/shroud-server/src/transport/fast_tcp.rs
```

### Логика

```text
accept transport connection
optional TLS accept
read_fast_connect_request
verify auth
TcpStream::connect(target)
set_nodelay(true)
write status OK
copy_bidirectional_with_sizes(transport, target)
```

### Псевдокод

```rust
pub async fn handle_fast_tcp_connection<S>(mut inbound: S, peer: SocketAddr, state: ServerState) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = read_fast_connect_request(&mut inbound).await?;

    if !state.auth.verify(&req.auth).await {
        write_fast_connect_status(&mut inbound, TcpConnectStatus::AuthFailed).await?;
        return Ok(());
    }

    let mut target = match TcpStream::connect((req.host.as_str(), req.port)).await {
        Ok(s) => s,
        Err(_) => {
            write_fast_connect_status(&mut inbound, TcpConnectStatus::ConnectFailed).await?;
            return Ok(());
        }
    };

    target.set_nodelay(true)?;
    write_fast_connect_status(&mut inbound, TcpConnectStatus::Ok).await?;

    let (up, down) = tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut target,
        state.relay.buffer_size,
        state.relay.buffer_size,
    ).await?;

    state.metrics.record_tcp_relay(up, down);
    Ok(())
}
```

### Критерий готовности

Server TCP relay работает без `relay_multiplexed_tunnel`, `FrameType::TcpData`, writer queues.

---

## Этап 6. Переписать session TCP relay на raw stream

Цель: убрать framed relay из обычного SOCKS TCP path.

### Файлы

- `crates/shroud-client/src/session.rs`
- `crates/shroud-client/src/tunnel.rs`

### Сейчас

```text
relay_over_tunnel_stream()
  split client
  split upstream
  client read -> write_frame(TcpData)
  read_frame(TcpData) -> client write
```

### Должно стать

```rust
let mut upstream = transport.connect(target_host, target_port).await?;
write_socks5_success(&mut client_stream).await?;
let (up, down) = tokio::io::copy_bidirectional_with_sizes(
    &mut client_stream,
    &mut upstream,
    relay_buffer_size,
    relay_buffer_size,
).await?;
```

### Важно

SOCKS success нужно отправлять только после того, как server реально подключился к target и вернул `OK`.

### Критерий готовности

В TCP path отсутствуют:

- `FrameType::TcpData`;
- `FrameType::TcpClose`;
- `STREAM_ID`;
- `TunnelStreamHandle`;
- `TunnelPool`;
- `relay_multiplexed_tcp`.

---

## Этап 7. Удалить multiplexing из active code path

Цель: не засорять код неиспользуемым транспортом.

### Удалить или вынести в архивный feature

Кандидаты на удаление:

```text
crates/shroud-client/src/tunnel_manager.rs
crates/shroud-server/src/relay.rs multiplexed sections
SessionCore::new_multiplexed
relay_multiplexed_tcp
TunnelPool
TunnelStreamHandle
FrameCommand writer queues
TunnelDataScheduler
flow permit logic
recently_closed_streams
ping/pong tunnel keepalive для multiplexing
multiplex metrics windows
```

### Рекомендуемый подход

Если хочешь полностью очистить проект:

```text
удалить multiplexing из main branch
если понадобится история — оставить в git history
```

Если хочешь сохранить на всякий случай:

```rust
#[cfg(feature = "legacy-multiplex")]
mod tunnel_manager;
```

Но мой совет: **убрать полностью**, потому что сейчас он усложняет архитектуру и мешает двигаться к стабильному MVP.

### Конфиг

Удалить из `OutboundConfig`:

```rust
multiplex
multiplex_tunnels
min_tunnels
max_tunnels
max_streams_per_tunnel
stream_slot_wait_timeout_ms
scale_up_writer_wait_ms
scale_up_queue_depth_ratio
scale_down_idle_secs
keepalive_interval_secs
keepalive_timeout_secs
max_buffer_per_stream_bytes
max_buffer_per_tunnel_bytes
max_pending_frames_per_stream
```

Удалить из server config:

```rust
ServerMultiplexConfig
```

### Тесты

Удалить/переписать тесты, которые проверяют:

- multiplexed tunnel server;
- stream id scheduling;
- writer queues;
- `TcpData` frame routing;
- `Ping/Pong` multiplex keepalive.

### Критерий готовности

`grep -R "multiplex" crates/` не должен находить active production code. Допустимо только в changelog/migration notes, если нужно.

---

## Этап 8. Удалить custom frame protocol из TCP

Цель: `protocol.rs` больше не должен быть основой TCP relay.

### Что оставить

Если UDP пока работает через старый protocol, можно временно оставить отдельный UDP protocol module.

Но для TCP удалить использование:

```text
FrameType::TcpConnect
FrameType::TcpData
FrameType::TcpClose
```

### Варианты

#### Вариант A: полностью удалить `protocol.rs`

Подходит, если UDP пока тоже не нужен или будет переписан отдельно.

#### Вариант B: переименовать в `legacy_protocol.rs`

Подходит на переходный период.

#### Вариант C: разделить

```text
protocol/
  tcp_handshake.rs
  udp_datagram.rs
  legacy_frames.rs
```

Мой выбор для чистого MVP:

```text
tcp_handshake.rs
udp.rs позже отдельно
legacy_frames.rs удалить
```

### Критерий готовности

`fast_tcp` и `balanced_tcp` не импортируют:

```rust
read_frame
write_frame
Frame
FrameType
FrameCommand
MAX_FRAME_PAYLOAD_LEN
```

---

## Этап 9. Реализовать `balanced_tcp` как HTTP/2 streaming

Цель: добавить режим баланса маскировки и скорости.

### Важное решение

`balanced_tcp` должен быть отдельным транспортом, а не переделкой старого `HTTP Upgrade: shroud-tunnel`.

### Рекомендуемый transport

```text
HTTP/2 POST /api/v1/events
headers/auth + target metadata
request/response body streaming = raw byte stream
```

### Возможная схема запроса

```http
POST /api/v1/events HTTP/2
Host: domain.com
Content-Type: application/octet-stream
X-Shroud-Client-Id: client-1
X-Shroud-Timestamp: 123456789
X-Shroud-Nonce: ...
X-Shroud-Auth: ...
X-Shroud-Target-Host: example.com
X-Shroud-Target-Port: 443
```

Ответ:

```http
:status: 200
content-type: application/octet-stream
```

После этого body — raw TCP bytes.

### Security/auth

Auth должен подписывать как минимум:

```text
method
path
timestamp
nonce
target_host
target_port
client_id
```

Иначе target metadata можно подменить.

### Rust implementation options

Возможные библиотеки:

- `hyper` + `hyper-util` для HTTP/2;
- `h2` crate напрямую, если нужен низкоуровневый control;
- `axum` для server endpoint, но streaming bidirectional HTTP body может быть неудобнее, чем низкоуровневый `h2`.

Для начала лучше low-level `h2`, потому что нужен full-duplex streaming. Обычный HTTP request/response в некоторых abstraction layers может плохо подходить для bidirectional relay.

### Важное ограничение

Для скорости:

```text
1 SOCKS CONNECT = 1 HTTP/2 connection = 1 HTTP/2 stream
```

Не надо сначала делать один shared H2 connection на все SOCKS requests. Иначе вернётся HOL/backpressure проблема.

### Критерий готовности

- `balanced_tcp` работает через TLS ALPN `h2`.
- Нормальный path `/api/v1/events`.
- Нет `TcpData` frames внутри body.
- Можно поставить behind Caddy/Nginx, если reverse proxy корректно поддерживает streaming.

---

## Этап 10. Fallback website и reverse proxy для `balanced_tcp`

Цель: снаружи сервер выглядит как обычный HTTPS-сайт.

### Caddy пример

```caddyfile
your-domain.com {
    root * /var/www/site
    file_server

    reverse_proxy /api/v1/events 127.0.0.1:9001 {
        transport http {
            versions h2c 2
        }
    }
}
```

Примечание: точная настройка зависит от того, как `shroud-server` принимает H2: TLS directly, h2c behind Caddy или HTTP/1.1 fallback.

### Nginx пример

Nginx как reverse proxy для true bidirectional HTTP/2 streaming может быть сложнее. Для MVP лучше:

```text
Caddy for balanced_tcp
or shroud-server directly terminates TLS/H2
```

### Path naming

Использовать нейтральные пути:

```text
/api/v1/events
/api/v1/sync
/assets/data
/live/events
```

Не использовать:

```text
/proxy
/tunnel
/socks
/vpn
/shroud
```

### Критерий готовности

- `https://domain.com/` открывает обычную страницу.
- `balanced_tcp` endpoint не выглядит очевидным `/tunnel`.
- Неверный запрос к endpoint возвращает обычный HTTP error, не panic/log spam.

---

## Этап 11. Metrics и logging после упрощения

Цель: оставить полезную диагностику без шума в hot path.

### Логировать только connection-level events

```text
connection accepted
target connect started/finished
tunnel established
relay finished
relay failed
bytes_up
bytes_down
duration_ms
mode = fast_tcp/balanced_tcp
```

### Не логировать

```text
every read
every write
every chunk
every frame
scheduler internals
```

### Metrics

Минимум:

```text
active_connections
accepted_connections_total
connect_failures_total
relay_errors_total
bytes_up_total
bytes_down_total
connection_duration_histogram
mode labels: fast_tcp/balanced_tcp
```

### Критерий готовности

Во время speedtest логи не создают заметный overhead и остаются читаемыми.

---

## Этап 12. UDP отдельно, не смешивать с TCP refactor

Цель: не заблокировать TCP MVP из-за UDP.

### Решение

В рамках этого плана TCP очищается первым.

UDP позже сделать отдельным protocol:

```text
SOCKS UDP ASSOCIATE
-> UDP packet encapsulation
-> server UDP socket
-> response path
```

UDP не должен использовать TCP `FrameType::TcpData`.

### Временно

Можно оставить:

```text
UDP unsupported in fast_tcp/balanced_tcp MVP
```

или:

```text
UDP legacy mode disabled by default
```

### Критерий готовности

TCP работает стабильно, UDP не ломает архитектуру TCP.

---

## Этап 13. Тестовый план

### Unit tests

#### `tcp_handshake.rs`

- encode/decode valid request;
- reject invalid magic;
- reject unsupported version;
- reject empty host;
- reject host > 255 bytes;
- reject port 0;
- status encode/decode;
- partial read returns error.

#### `auth`

- valid HMAC/auth proof;
- expired timestamp;
- reused nonce if nonce cache есть;
- wrong client id;
- wrong secret.

### Integration tests

#### Fast TCP smoke

```text
start echo target
start shroud-server fast_tcp
start shroud-client SOCKS
connect through SOCKS
send bytes
expect same bytes
```

#### Fast TCP HTTPS target

```text
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

#### Target connect failure

```text
SOCKS CONNECT unreachable target
expect SOCKS failure, not success
```

#### Concurrent connections

```text
100 concurrent SOCKS CONNECT requests
no panic
all finish or fail cleanly
```

#### Large transfer

```text
100MB local test file through SOCKS
validate checksum
record throughput
```

#### Balanced TCP smoke

Same as fast, but through H2 endpoint.

### Benchmark tests

```bash
iperf3 -c SERVER -p PORT -P 4
iperf3 -c SERVER -p PORT -P 4 -R
```

Then:

```bash
curl -x socks5h://127.0.0.1:1080 -o /dev/null https://speed.hetzner.de/100MB.bin
```

Compare:

```text
raw iperf3
Dante SOCKS
shroud fast_tcp
shroud balanced_tcp
old shroud framed mode, if still available
```

### Критерии производительности

На нормальном VPS/маршруте:

```text
fast_tcp >= 80-90% of Dante SOCKS throughput
balanced_tcp >= 60-80% of fast_tcp throughput
```

Если сеть плохая, сравнивать только относительно Dante и raw iperf3, а не абсолютные Mbps.

---

## Этап 14. Удаление legacy code

После того как `fast_tcp` работает и тесты проходят:

### Удалить client-side

```text
crates/shroud-client/src/tunnel_manager.rs
multiplex-specific code in session.rs
multiplex-specific tests
legacy HTTP Upgrade path from tunnel.rs, если не нужен
```

### Удалить server-side

```text
relay_multiplexed_tunnel
relay_multiplexed_tunnel_with_config
multiplexed stream state
writer queues
server tunnel scheduler
```

### Удалить core-side

```text
FrameType::TcpConnect
FrameType::TcpData
FrameType::TcpClose
FrameCommand
Frame encode/decode если больше нигде не нужен
MAX_FRAME_PAYLOAD_LEN если больше нигде не нужен
multiplex config fields
```

### Обновить tests

Удалить тесты, которые проверяют удалённое поведение. Не пытаться сохранить все старые tests через compatibility layer, иначе старый дизайн останется в коде.

### Критерий готовности

```bash
grep -R "multiplex" crates/
grep -R "TcpData" crates/
grep -R "shroud-tunnel" crates/
```

Результат должен быть пустым или находить только migration notes/docs.

---

## Этап 15. Migration notes

Добавить `MIGRATION.md`:

```markdown
# Migration from legacy multiplexed/framed transport

Old:
outbound:
  path: /api/tunnel
  multiplex: false

New fast mode:
transport:
  tcp_mode: fast_tcp

New balanced mode:
transport:
  tcp_mode: balanced_tcp
  path: /api/v1/events
```

Описать, что удалено:

```text
multiplexing removed
custom HTTP Upgrade removed
TcpData framing removed from TCP path
UDP temporarily unsupported / moved to future work
```

---

# Рекомендуемый порядок коммитов

## Commit 1

```text
config: add explicit tcp transport mode
```

## Commit 2

```text
core: add fast tcp connect handshake
```

## Commit 3

```text
client: add fast_tcp transport
```

## Commit 4

```text
server: add fast_tcp accept and raw relay
```

## Commit 5

```text
client: route SOCKS TCP through raw transport relay
```

## Commit 6

```text
tests: add fast_tcp smoke and large transfer tests
```

## Commit 7

```text
cleanup: remove multiplexed TCP transport
```

## Commit 8

```text
cleanup: remove legacy TcpData frame protocol from TCP path
```

## Commit 9

```text
transport: add balanced_tcp h2 streaming skeleton
```

## Commit 10

```text
docs: add migration and benchmark guide
```

---

# Что делать первым на практике

Самый правильный первый технический шаг:

```text
сделать fast_tcp как отдельный новый путь, не пытаясь сразу удалить старый код
```

То есть сначала:

```text
new config -> fast_tcp client -> fast_tcp server -> raw relay -> tests
```

Только после успешного benchmark удалить multiplexing и legacy frames.

Так меньше риск сломать всё сразу.

---

# Финальное целевое состояние

В проекте остаются только два TCP режима:

## `fast_tcp`

```text
TLS/plain TCP
binary CONNECT handshake
raw copy_bidirectional
no HTTP
no frames
no multiplexing
```

## `balanced_tcp`

```text
TLS 443
HTTPS/H2 endpoint
auth + target metadata
raw stream in HTTP/2 body
fallback website possible
no internal TcpData frames
no multiplexing
```

Код становится проще:

```text
SOCKS parsing
transport connect
raw relay
auth
metrics
```

Всё, что относится к multiplexing, scheduler, logical streams, `TcpData`, `stream_id`, writer queues и per-frame flow control, удаляется из основного проекта.

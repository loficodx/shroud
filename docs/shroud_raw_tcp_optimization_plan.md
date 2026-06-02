# План оптимизации и рефакторинга shroud-proxy: фокус на raw_tcp MVP

## Цель

Сфокусировать проект на простой, быстрой и минимально накладной TCP-модели:

```text
SOCKS5 CONNECT
  -> raw_tcp client-server connection
  -> minimal connect handshake
  -> server TCP connect to target
  -> raw bidirectional relay
```

На текущем этапе:

- `raw_tcp` — основной и единственный полноценно рабочий TCP transport.
- UDP временно удаляется/отключается из runtime path.
- `http2` и `http3/quic` остаются только как архитектурные заготовки.
- `tun` можно оставить, если он живёт сбоку и не загрязняет TCP datapath.
- Старый multiplexing не возвращаем в `raw_tcp`.
- Pool не добавляем в `raw_tcp` на первом этапе.

---

## 0. ~~Зафиксировать архитектурный scope~~

### Что должно быть в MVP

```text
local SOCKS5 TCP inbound
  -> CONNECT only
  -> TransportMode::RawTcp
  -> remote server
  -> target TCP
  -> copy_bidirectional
```

### Что не входит в MVP

```text
UDP ASSOCIATE
TCP multiplexing
persistent logical streams
HTTP/2 production transport
HTTP/3 production transport
connection pool
smart routing
traffic shaping
advanced masking
```

### Решение

В README/config явно написать:

```text
Current MVP supports SOCKS5 TCP CONNECT over raw_tcp only.
UDP ASSOCIATE is intentionally disabled and will be implemented after TCP transports are stable.
HTTP/2 and HTTP/3 modes are reserved for future transports.
```

---

## 1. ~~Переименовать transport modes~~

### Текущая проблема

Названия вида `fast_tcp` и `balanced_tcp` описывают намерение, а не реальный transport.

Проблемы:

- `fast_tcp` не всегда будет самым быстрым на браузерной нагрузке.
- `balanced_tcp` не объясняет, что технически это будет HTTP/2.
- `tcp_mode: http3` терминологически некорректно, потому что HTTP/3 работает поверх QUIC/UDP, а не TCP.

### Новая модель

Использовать технические названия:

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    RawTcp,
    Http2,
    Http3,
}
```

В конфиге:

```yaml
transport:
  mode: raw_tcp
```

В будущем:

```yaml
transport:
  mode: http2
```

```yaml
transport:
  mode: http3
```

### Маппинг старых названий

```text
fast_tcp      -> raw_tcp
balanced_tcp  -> http2
future quic   -> http3
```

### Переименования в коде

```text
FastTcpTransport              -> RawTcpTransport
connect_fast_tcp              -> connect_raw_tcp
handle_fast_tcp_connection    -> handle_raw_tcp_connection
FAST_TCP_MAGIC                -> RAW_TCP_MAGIC
FAST_TCP_VERSION              -> RAW_TCP_VERSION
TcpTransportMode              -> TransportMode
tcp_mode                      -> mode
```

### Backward compatibility

Если проект ещё не публичный, лучше не тащить совместимость.

Если всё же нужно временно поддержать старые конфиги, можно добавить aliases:

```rust
#[serde(alias = "fast_tcp")]
RawTcp,

#[serde(alias = "balanced_tcp")]
Http2,
```

Но для чистого MVP лучше удалить legacy-названия сразу.

---

## 2. ~~Удалить/отключить UDP из runtime path~~

Status: implemented for the active runtime path. SOCKS5 `UDP ASSOCIATE` is rejected with
`CommandNotSupported`, client/server UDP relay code is removed, and UDP datagram protocol helpers
are no longer part of the public core protocol API.

### Цель

Упростить кодовую базу и не смешивать TCP-оптимизацию с UDP-сессиями.

UDP — отдельный уровень сложности:

```text
SOCKS5 UDP ASSOCIATE
UDP session lifetime
TCP control connection
NAT mapping
packet framing
MTU
fragmentation
timeouts
DNS/QUIC/WebRTC traffic
```

На текущем этапе это мешает стабилизировать TCP.

### Что сделать

1. Убрать обработку `UDP ASSOCIATE` из active SOCKS path.
2. Возвращать понятную ошибку клиенту:

```text
UDP ASSOCIATE is not supported in current MVP
```

3. Убрать UDP config fields из основного конфига.
4. Убрать UDP bind/listener из server startup.
5. Отключить UDP metrics.
6. Отключить или удалить UDP tests.
7. Удалить UDP modules из публичного runtime path.
8. Оставить историю в git, не держать мёртвый код в основной ветке.

### Как отвечать SOCKS-клиенту

Для unsupported UDP ASSOCIATE возвращать SOCKS reply:

```text
Command not supported
```

То есть не panic, не silent close, а корректный protocol response.

### Будущая структура

Когда UDP вернётся, сделать его отдельным блоком:

```yaml
udp:
  enabled: false
  mode: udp_relay
```

И отдельным enum:

```rust
enum UdpMode {
    Disabled,
    UdpRelay,
    QuicDatagram,
}
```

Не смешивать UDP с `TransportMode::RawTcp/Http2/Http3`.

---

## 3. ~~Оставить TUN сбоку~~

Status: verified. TUN remains a client inbound selected by `inbounds.tun.enabled`. It reuses
`SessionCore` and the configured TCP transport, does not alter `raw_tcp`, does not affect server
startup, and keeps smoltcp UDP disabled. The local Fake DNS UDP listener is TUN-only helper state,
not the removed SOCKS/tunnel UDP relay path.

### Решение

`tun` можно оставить, если он:

- не усложняет `raw_tcp`;
- не зависит от UDP path;
- не тянет multiplexing в основной TCP transport;
- не влияет на server startup для обычного SOCKS MVP;
- включается отдельным config-флагом.

### Рекомендуемая структура

```yaml
inbounds:
  socks:
    enabled: true
    listen: "127.0.0.1:1080"

  tun:
    enabled: false
```

В коде:

```text
inbound/
  socks/
  tun/

transport/
  raw_tcp/
  http2/
  http3/
```

TUN должен быть inbound-слоем, а не transport-слоем.

---

## 4. ~~Очистить конфиги~~

Status: implemented for checked-in runtime configs. Cleanup removes only config that no longer maps
to the active runtime path, such as legacy multiplex settings and old transport mode names. TUN,
DNS, routing, `tunnel_path`, and `web_root` stay because they are still used by the current code.

### Цель

Конфиг должен отражать только реально работающую модель.

### Минимальный client config

```yaml
inbounds:
  socks:
    listen: "127.0.0.1:1080"

transport:
  mode: raw_tcp
  server: "157.22.231.153"
  port: 8443
  tls: true
  tls_server_name: "example.com"
  tls_ca_cert_path: "certs/ca.crt"

auth:
  client_id: "..."
  client_secret: "..."
```

### Минимальный server config

```yaml
listen: "0.0.0.0:8443"

transport:
  modes:
    - raw_tcp

tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"

clients:
  - client_id: "..."
    client_secret: "..."
```

### Что удалить из текущих конфигов

```text
multiplex
multiplex_tunnels
min_tunnels
max_tunnels
udp fields
balanced_tcp as enabled production mode
legacy outbound fields, если они уже не нужны
```

### Важно

Не указывать `http2` или `http3` в `server.transport.modes`, пока они не реализованы.

---

## ~~5. Сделать заготовки под http2 и http3~~

### Цель

Оставить архитектурное место под будущие режимы, но не тащить их в runtime.

### Trait

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect_tcp(&self, target: TargetAddr) -> Result<BoxedIo>;
}
```

Или более конкретно:

```rust
#[async_trait]
pub trait TcpOutboundTransport: Send + Sync {
    async fn open_tcp(&self, target: TargetAddr) -> Result<BoxedIo>;
}
```

### Builder

```rust
pub fn build_transport(config: &TransportConfig) -> Result<Arc<dyn TcpOutboundTransport>> {
    match config.mode {
        TransportMode::RawTcp => Ok(Arc::new(RawTcpTransport::new(config)?)),
        TransportMode::Http2 => bail!("http2 transport is reserved but not implemented yet"),
        TransportMode::Http3 => bail!("http3 transport is reserved but not implemented yet"),
    }
}
```

### Modules

```text
transport/
  mod.rs
  raw_tcp.rs
  http2.rs
  http3.rs
```

В `http2.rs`:

```rust
pub struct Http2Transport;

impl Http2Transport {
    pub fn new_reserved() -> Self {
        Self
    }
}
```

Но не подключать к production config.

---

## ~~6. Сделать raw_tcp максимально простым~~

### Target architecture

```text
client:
  SOCKS CONNECT parsed
  -> RawTcpTransport::open_tcp(target)
  -> TCP connect to server
  -> optional TLS handshake
  -> write RawTcpConnectRequest
  -> read RawTcpConnectResponse
  -> return stream

server:
  accept connection
  -> optional TLS already accepted
  -> sniff/read raw_tcp request
  -> auth validation
  -> TCP connect target
  -> write OK/FAIL
  -> copy_bidirectional
```

### После handshake

После успешного `OK`:

```text
никаких frames
никакого stream_id
никакого multiplexing
никакого per-chunk protocol header
никакого pool
только raw bytes
```

### Правило

`raw_tcp` должен быть baseline-режимом. Если он медленный, проблема должна искаться в I/O, TLS, network, buffers, Docker/VPS, timeouts, но не решаться добавлением multiplexing.

---

## 7. ~~Исправить timeout relay~~

Status: implemented for the active TCP relay path. Client-side SOCKS/direct relay and server-side
`raw_tcp` relay use `copy_bidirectional_with_sizes` without a wall-clock wrapper. A real idle
timeout can be added later as a separate byte-activity-aware relay primitive.

### Текущая проблема

Если используется конструкция вида:

```rust
timeout(RELAY_IDLE_TIMEOUT, copy_bidirectional(...)).await
```

это не idle timeout.

Это означает:

```text
закрыть соединение через N секунд независимо от активности
```

Для прокси это неправильно.

### Что сделать

Вариант 1 — временно убрать timeout:

```rust
let result = copy_bidirectional_with_sizes(
    client,
    remote,
    upload_buffer_size,
    download_buffer_size,
).await;
```

Вариант 2 — реализовать настоящий idle timeout:

```text
таймер сбрасывается при каждом успешном read/write
соединение закрывается только если нет движения байтов N секунд
```

### Рекомендация для MVP

Сначала убрать wall-clock timeout полностью.

Потом добавить настоящий idle timeout отдельной функцией:

```rust
copy_bidirectional_with_idle_timeout(...)
```

### Настройки

```yaml
relay:
  upload_buffer_size: 65536
  download_buffer_size: 65536
  idle_timeout_sec: 300
```

---

## 8. ~~Закэшировать TLS connector на клиенте~~

### Текущая проблема

Если TLS config создаётся на каждый SOCKS CONNECT, это лишние расходы:

```text
read CA file
build RootCertStore
build ClientConfig
create TlsConnector
```

На браузерной нагрузке это дорого.

### Что сделать

Собирать TLS connector один раз при создании transport:

```rust
pub struct RawTcpTransport {
    server_addr: SocketAddr,
    server_name: ServerName<'static>,
    auth: ClientAuthConfig,
    tls_connector: Option<TlsConnector>,
}
```

В `new()`:

```rust
let tls_connector = if config.tls {
    Some(build_tls_connector(config)?)
} else {
    None
};
```

В `open_tcp()` использовать уже готовый connector.

### Ожидаемый эффект

- меньше CPU на коротких соединениях;
- меньше аллокаций;
- стабильнее latency;
- проще профилировать реальный datapath.

---

## 9. ~~Добавить timeout на connect/handshake/sniff~~

### Client-side timeout

Разделить timeout-ы:

```yaml
timeouts:
  server_connect_ms: 10000
  tls_handshake_ms: 10000
  raw_tcp_handshake_ms: 5000
  target_connect_ms: 10000
  idle_timeout_sec: 300
```

На клиенте:

```text
TCP connect to shroud server timeout
TLS handshake timeout
raw_tcp response read timeout
```

### Server-side timeout

На сервере:

```text
sniff raw_tcp magic timeout
read raw_tcp connect request timeout
target connect timeout
```

Особенно важно для server sniff:

```rust
timeout(SNIFF_TIMEOUT, read_exact(prefix)).await
```

Иначе клиент может подключиться и зависнуть, удерживая task.

`relay idle timeout` остается отдельной задачей из пункта 7: wall-clock timeout убран, настоящий activity-aware idle timeout пока не включен в datapath.

---

## 10. ~~Упростить server protocol detection~~

### Цель

Пока есть только `raw_tcp`, не нужно делать сложный multi-protocol accept.

Минимально:

```text
accept TCP/TLS
  -> read first bytes with timeout
  -> if RAW_TCP_MAGIC: handle raw_tcp
  -> else reject
```

Когда появится HTTP/2:

```text
accept TLS
  -> ALPN or HTTP/2 server router
```

Когда появится HTTP/3:

```text
separate UDP/QUIC listener
```

### Важно

HTTP/3 не должен попадать в тот же TCP accept loop.

---

## 11. ~~Добавить target ACL на сервере~~

### Почему это важно

Если сервер публичный, raw_tcp фактически даёт возможность подключаться к произвольным адресам от имени сервера.

Минимальный denylist:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
::1/128
fc00::/7
fe80::/10
```

### Config

```yaml
security:
  deny_private_ips: true
  allow_ports:
    - 80
    - 443
```

На MVP можно начать с `deny_private_ips: true`.

---

## 12. ~~Добавить лимиты concurrency~~

### Client

```yaml
limits:
  max_concurrent_connections: 4096
```

### Server

```yaml
limits:
  max_concurrent_connections: 4096
```

### Implementation idea

На accept/open path использовать semaphore:

```rust
let permit = semaphore.acquire_owned().await?;
tokio::spawn(async move {
    let _permit = permit;
    handle_connection(...).await;
});
```

### Почему это нужно

Без лимита можно положить VPS большим количеством short connections.

---

## 13. ~~Настроить socket options~~

Status: implemented. `TCP_NODELAY` is enabled on accepted SOCKS/server TCP sockets,
client raw_tcp endpoint sockets, direct target sockets, and server target sockets. Exotic
socket options are intentionally not configured before baseline benchmarks.

### На TCP client/server streams

Проверить и включить:

```rust
stream.set_nodelay(true)?;
```

### Почему

Для proxy relay обычно желательно снизить latency маленьких пакетов.

### Осторожно

Не добавлять экзотику раньше времени:

```text
TCP_FASTOPEN
SO_MARK
SO_REUSEPORT
custom congestion control
```

Это всё позже, после baseline-бенчмарков.

---

## 14. ~~Настроить buffer sizes~~

Status: implemented. `relay.upload_buffer_size` and `relay.download_buffer_size` are
available in both client and server configs with 64 KiB defaults and positive-value
validation. Client-side SOCKS/TUN relay and server-side raw_tcp relay use these values in
`copy_bidirectional_with_sizes`.

### MVP defaults

```yaml
relay:
  upload_buffer_size: 65536
  download_buffer_size: 65536
```

### Тестируемые варианты

```text
16 KiB
32 KiB
64 KiB
128 KiB
256 KiB
```

### Важно

Большой buffer не всегда быстрее. Для большого количества соединений он может увеличить memory pressure.

Например:

```text
4096 connections * 2 directions * 64 KiB ≈ 512 MiB
```

Поэтому defaults должны быть разумными.

---

## 15. Метрики raw_tcp

### Минимальные метрики

```text
active_connections
accepted_connections_total
connect_success_total
connect_failure_total
auth_failure_total
relay_error_total
bytes_up_total
bytes_down_total
connection_duration
target_connect_duration
server_connect_duration
tls_handshake_duration
raw_tcp_handshake_duration
```

### Логи

На client:

```text
target
server_addr
connect_duration
tls_duration
handshake_duration
relay_bytes_up
relay_bytes_down
relay_duration
error_kind
```

На server:

```text
client_addr
target
auth_result
target_connect_duration
relay_bytes_up
relay_bytes_down
relay_duration
close_reason
```

### Главное

Логи должны помогать ответить:

```text
медленно из-за server connect?
медленно из-за target connect?
медленно из-за TLS?
медленно во время relay?
соединения закрываются timeout'ом?
есть ли auth/replay failures?
```

---

## 16. Тесты после рефакторинга

### Unit tests

```text
raw_tcp request encode/decode
raw_tcp response encode/decode
bad magic
bad version
bad auth
expired timestamp
replayed nonce
unsupported command
invalid target
```

### Integration tests

```text
SOCKS CONNECT through raw_tcp to echo server
large payload relay
half-close client -> server
half-close server -> client
target connect failure
server auth failure
many parallel TCP connects
long-lived active connection > idle_timeout
idle connection closes after idle_timeout
```

### Regression tests

Обязательно тест на старую ошибку:

```text
active connection must not close just because total duration > 300 sec
```

Если тест на 300 секунд слишком долгий, сделать configurable timeout в тесте:

```text
idle_timeout = 2 sec
active stream sends data every 500 ms for 5 sec
connection must stay alive
```

---

## 17. Бенчмарки

### Baseline 1 — direct iperf3

```bash
iperf3 -c SERVER_IP -P 4
```

### Baseline 2 — raw_tcp через proxy

Варианты:

1. HTTP large file download through SOCKS.
2. iperf3 через proxy wrapper, если есть подходящий инструмент.
3. curl through SOCKS:

```bash
curl --socks5-hostname 127.0.0.1:1080 -o /dev/null https://speed.hetzner.de/1GB.bin
```

### Baseline 3 — сравнение с VLESS/WireGuard

```text
direct
raw_tcp
VLESS TCP/TLS or REALITY
WireGuard/AmneziaWG
```

### Что измерять

```text
download Mbps
upload Mbps
latency to first byte
CPU client
CPU server
memory
connection failures
jitter
```

### Цель raw_tcp

Для одного большого TCP stream:

```text
raw_tcp должен быть близок к VLESS TCP/TLS
```

Для браузерной нагрузки:

```text
raw_tcp может проигрывать HTTP/2/QUIC режимам, это нормально
```

---

## 18. Удалить legacy multiplexing из raw_tcp path

### Правило

В `raw_tcp` не должно быть:

```text
stream_id
frame_type
FrameCommand
tunnel writer loop
control/data channels
logical stream map
mux scheduler
```

Если старый multiplexing нужен для истории — оставить в git history, не в active path.

Если хочется сохранить код как future reference, лучше вынести в отдельную ветку или `archive/`, но не компилировать в основной runtime.

---

## 19. Проверить Docker/network overhead

### Почему

Если сервер работает в Docker, важно убедиться, что проблема не в container networking.

### Проверки

На VPS:

```bash
iperf3 -s
```

Снаружи:

```bash
iperf3 -c SERVER_IP -P 4
```

Потом внутри container:

```bash
docker exec -it shroud-proxy-server iperf3 -c TARGET_OR_HOST -P 4
```

Также проверить:

```bash
docker stats
docker logs
htop
ss -tanp
```

### Что искать

```text
CPU throttling
низкий network throughput внутри container
слишком много TIME_WAIT
conntrack saturation
memory pressure
relay errors
```

---

## 20. Порядок выполнения

### Этап 1 — Scope cleanup

- [x] Удалить/отключить UDP ASSOCIATE.
- [x] Убрать UDP из config.
- [x] Убрать UDP startup/listeners.
- [x] Оставить TUN отдельно и выключенным по умолчанию.
- [x] Удалить legacy multiplex fields из конфигов.
- [ ] README: зафиксировать TCP CONNECT only MVP.

### Этап 2 — Naming refactor

- [ ] `fast_tcp` -> `raw_tcp`.
- [ ] `balanced_tcp` -> `http2` reserved.
- [ ] `quic`/future -> `http3` reserved.
- [ ] `tcp_mode` -> `mode`.
- [ ] `FastTcpTransport` -> `RawTcpTransport`.
- [ ] Обновить tests/config examples/docs.

### Этап 3 — raw_tcp correctness

- [x] Убрать wall-clock timeout вокруг `copy_bidirectional`.
- [ ] Реализовать или отложить настоящий idle timeout.
- [x] Добавить sniff/read handshake timeout на сервере.
- [x] Добавить client connect/TLS/handshake timeouts.
- [ ] Проверить half-close behavior.
- [ ] Проверить корректный SOCKS response для unsupported commands.

### Этап 4 — raw_tcp performance

- [ ] Закэшировать `TlsConnector`.
- [x] Включить `TCP_NODELAY`.
- [x] Настроить relay buffer sizes через config.
- [ ] Убрать лишние аллокации в request/response encode/decode.
- [ ] Проверить, что datapath после handshake — чистый raw relay.

### Этап 5 — safety limits

- [x] Добавить server max concurrent connections.
- [x] Добавить client max concurrent connections.
- [ ] Добавить target ACL/deny private IPs.
- [ ] Добавить понятные close reasons в logs.
- [ ] Добавить базовые metrics.

### Этап 6 — tests

- [ ] Unit tests protocol encode/decode.
- [ ] Integration tests raw_tcp echo.
- [ ] Large payload test.
- [ ] Parallel connections test.
- [ ] Long-lived active connection test.
- [ ] Idle timeout test.
- [x] Unsupported UDP ASSOCIATE test.

### Этап 7 — benchmark

- [ ] Direct VPS iperf3 baseline.
- [ ] raw_tcp large download test.
- [ ] raw_tcp upload test.
- [ ] Compare with VLESS/WireGuard.
- [ ] Measure CPU/memory.
- [ ] Tune buffers based on data.

### Этап 8 — http2/http3 placeholders

- [ ] Создать `transport/http2.rs`.
- [ ] Создать `transport/http3.rs`.
- [ ] Добавить reserved enum variants.
- [ ] Не включать их в production config.
- [ ] Возвращать понятную ошибку при выборе неготового режима.

---

## 21. Критерии готовности raw_tcp MVP

`raw_tcp` можно считать готовым MVP, если:

- [ ] SOCKS5 TCP CONNECT стабильно работает.
- [x] UDP ASSOCIATE корректно отклоняется.
- [ ] Нет multiplexing/frame overhead в datapath.
- [x] Нет wall-clock timeout, который убивает активные соединения.
- [ ] TLS connector не пересобирается на каждый request.
- [x] Есть timeout на connect/handshake/sniff.
- [ ] Есть лимит concurrent connections.
- [ ] Есть базовый deny private IPs на server-side target connect.
- [ ] Large download/upload работает стабильно.
- [ ] 100–500 parallel short connections не ломают client/server.
- [ ] Логи показывают причину ошибок и закрытия соединений.
- [ ] Конфиги не содержат старых misleading полей.
- [ ] `http2/http3` явно помечены как reserved/not implemented.

---

## 22. Что не делать сейчас

Не добавлять в `raw_tcp`:

```text
connection pool
multiplexing
stream_id
custom scheduler
HTTP disguise
UDP relay
QUIC
smart domain routing
per-site hacks
```

Причина: `raw_tcp` должен стать чистым baseline. Только после этого имеет смысл сравнивать с `http2` и будущим `http3`.

---

## 23. Итоговая целевая модель

```text
raw_tcp:
  purpose: maximum simplicity / minimum overhead
  model: 1 SOCKS CONNECT = 1 client-server TCP/TLS stream = 1 server-target TCP stream
  datapath: raw bytes after handshake
  no mux: yes
  no pool: yes
  UDP: disabled

http2:
  purpose: future balanced/masked transport
  model: HTTP/2 streams
  status: reserved

http3:
  purpose: future QUIC-based transport
  model: HTTP/3/QUIC
  status: reserved

tun:
  purpose: optional inbound mode
  status: separate from transport
```

Главная идея: сначала получить быстрый и понятный `raw_tcp`, который работает как классический SOCKS-style TCP relay. После этого уже можно честно измерять, нужен ли HTTP/2, HTTP/3 или отдельная UDP-подсистема.

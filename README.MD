# Shroud

Shroud is an experimental Rust client/server TCP tunneling project.

The current implementation is centered on **raw TCP CONNECT tunneling**: `shroud-client` accepts local SOCKS5 `CONNECT` traffic or Linux TUN TCP streams, opens a per-connection `raw_tcp` tunnel to `shroud-server`, authenticates the client, asks the server to connect to the requested target, and then relays raw bytes in both directions. TLS can wrap the client/server connection.

The older framed HTTP Upgrade tunnel and multiplexing documentation is no longer accurate for the refactored code path. `raw_tcp` is the default and only implemented transport mode. `http2` and `http3` are reserved in config/types but rejected as not implemented.

## Current Status

### Implemented

- Rust workspace with three crates:
  - `shroud-core` - shared config, auth, legacy frame helpers, and `raw_tcp` handshake types;
  - `shroud-client` - local SOCKS5/TUN client, routing, DNS policy checks, and outbound transport;
  - `shroud-server` - TLS listener, `raw_tcp` authentication, target ACL checks, TCP relay, and legacy HTTP/static handler code.
- Client inbounds:
  - SOCKS5 no-auth handshake;
  - SOCKS5 `CONNECT` for IPv4, IPv6, and domain targets;
  - Linux TUN TCP mode backed by `netstack-smoltcp`;
  - configurable concurrent connection limit with `limits.max_concurrent_connections`.
- TCP transport:
  - `transport.mode: raw_tcp`;
  - optional TLS;
  - one tunnel connection per proxied TCP stream;
  - binary connect handshake with `SHRD` magic, version, command, auth proof, target host, and target port;
  - one-byte server status before raw byte relay;
  - TCP_NODELAY on accepted/client/target sockets;
  - configurable connect, TLS handshake, raw TCP handshake, target connect, and idle timeout values.
- Authentication:
  - `client_id` / `client_secret` credentials;
  - HMAC-based auth proof;
  - timestamp skew validation;
  - nonce replay protection;
  - server provisioning commands for TLS certificates, client creation, and import-string listing.
- Routing on the client:
  - `proxy`, `direct`, and `block` actions;
  - exact domain rules;
  - domain suffix rules;
  - CIDR rules for IP targets;
  - port rules;
  - first matching rule wins.
- DNS policy checks on the client:
  - domain targets are preserved for remote resolution when applications use SOCKS hostname mode;
  - IP targets can be warned about or blocked;
  - useful for detecting local DNS resolution / DNS leak risk in SOCKS usage.
- Server-side target controls:
  - optional denial of private, loopback, and link-local target IPs with `security.deny_private_ips`;
  - optional port allowlist with `security.allow_ports`;
  - remote DNS lookup on the server for domain targets.
- Server web code:
  - `GET /api/status` handler;
  - static fallback from `web_root`;
  - neutral 403/404 responses;
  - note: with the current valid `transport.modes: [raw_tcp]` server mode, non-`raw_tcp` connections are rejected before the HTTP handler is reached.
- TUN mode:
  - Linux TUN device creation through `/dev/net/tun`;
  - no packet information header (`IFF_NO_PI`);
  - interface setup and optional default route setup;
  - TCP packet handling through `netstack-smoltcp`;
  - Fake DNS listener for A records;
  - fake IPv4 mapping from `198.18.0.0/15`;
  - fake IP back-mapping to the original domain for observed TCP connections;
  - Linux namespace smoke test script.
- Tests:
  - config validation and compatibility tests;
  - routing unit tests;
  - raw TCP handshake tests;
  - raw TCP client/server transport tests;
  - SOCKS/TLS tunnel integration tests;
  - curl SOCKS5 hostname smoke test;
  - large payload and half-close relay tests;
  - direct/block route tests;
  - DNS policy test;
  - rejected SOCKS UDP ASSOCIATE test;
  - server web handler unit tests;
  - ignored Linux TUN smoke test.

### Not Implemented Or Not Active

- SOCKS5 `UDP ASSOCIATE` relay. It is parsed, then rejected with `CommandNotSupported`.
- Direct UDP routing from the SOCKS inbound.
- TUN UDP forwarding.
- TCP multiplexing over one persistent tunnel.
- Per-stream multiplex flow control.
- Active client HTTP/1.1 Upgrade transport.
- WebSocket transport.
- HTTP/2 transport.
- HTTP/3 / QUIC transport.
- Browser DoH/DoT interception.
- Server-side egress IP selection.
- Automatic system DNS switching for TUN mode.

## Architecture

```text
Application / curl / browser
        |
        | SOCKS5 CONNECT or Linux TUN TCP
        v
shroud-client
        |
        | raw_tcp CONNECT handshake
        | optional TLS
        | one tunnel connection per TCP stream
        v
shroud-server
        |
        | server-side DNS lookup / ACL / TCP connect
        v
Target host
```

Workspace layout:

```text
.
├── Cargo.toml
├── configs/
│   ├── client.yaml
│   ├── client-remote.yaml
│   └── server.yaml
├── certs/
│   └── README.md
├── crates/
│   ├── shroud-core/
│   ├── shroud-client/
│   └── shroud-server/
├── scripts/
│   ├── generate-certs.sh
│   └── tun-smoke-linux.sh
├── web/
│   └── index.html
├── Dockerfile
└── docker-compose.yml
```

## Requirements

- Rust toolchain compatible with edition `2024`.
- `cargo`.
- `curl` for manual smoke checks.
- Docker / Docker Compose if running the server in a container.
- Linux for TUN mode.
- Root privileges for TUN smoke tests.
- Linux tools for TUN smoke tests:
  - `ip`;
  - `python3`;
  - `/dev/net/tun`.

## Configuration

The current client config shape uses `transport`, not the old `outbound` block. Legacy `outbound` is still accepted for compatibility, but the client logs a deprecation warning. If both `transport` and legacy `outbound` are present, `transport` wins.

Example client config:

```yaml
inbounds:
  socks:
    enabled: true
    listen: "127.0.0.1:1080"

  tun:
    enabled: false
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: false
    dns: "10.10.0.53"

transport:
  mode: raw_tcp
  server: "127.0.0.1"
  port: 8443
  tls: true
  tls_server_name: "localhost"
  # Replace with the value printed by `shroud-server generate-certs`.
  tls_server_cert_sha256: "0000000000000000000000000000000000000000000000000000000000000000"

timeouts:
  server_connect_ms: 10000
  tls_handshake_ms: 10000
  raw_tcp_handshake_ms: 5000
  target_connect_ms: 10000
  idle_timeout_sec: 300

relay:
  upload_buffer_size: 65536
  download_buffer_size: 65536

limits:
  max_concurrent_connections: 4096

auth:
  client_id: "c1ce8312-7c35-4e70-867a-3af4ac7f68d7"
  client_secret: "replace-with-random-secret"

dns:
  remote_by_default: true
  warn_on_ip_targets: true
  block_ip_targets: false

routing:
  default: "proxy"
  rules:
    - action: "direct"
      domain: "localhost"
    - action: "direct"
      domain_suffix: ".local"
    - action: "direct"
      cidr: "127.0.0.0/8"
    - action: "direct"
      port: 22
```

Example server config:

```yaml
listen: "0.0.0.0:8443"
tunnel_path: "/api/tunnel"
web_root: "./web"
transport:
  modes:
    - raw_tcp
tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
timeouts:
  server_connect_ms: 10000
  tls_handshake_ms: 10000
  raw_tcp_handshake_ms: 5000
  target_connect_ms: 10000
  idle_timeout_sec: 300
relay:
  upload_buffer_size: 65536
  download_buffer_size: 65536
limits:
  max_concurrent_connections: 4096
security:
  deny_private_ips: true
  allow_ports: []
clients:
  - name: "laptop"
    client_id: "c1ce8312-7c35-4e70-867a-3af4ac7f68d7"
    client_secret: "replace-with-random-secret"
    created_at: "2026-06-09T18:00:00Z"
```

`security.allow_ports: []` means no port allowlist is enforced. If the list is non-empty, only those target ports are allowed.

## Server Setup

Recommended provisioning is split into independent commands:

- `generate-certs` creates or reuses the server TLS certificate/key and updates only `tls.*` in `server.yaml`.
- `add-client` creates one authorized client, appends it to `server.yaml`, and prints a `shrd:1:<base64url-json>` import string.
- `client-list` prints import strings for existing clients without modifying `server.yaml`.

```bash
cargo run -p shroud-server -- generate-certs --server 127.0.0.1 --config configs/server.yaml --cert-dir certs
cargo run -p shroud-server -- add-client --name laptop --server 127.0.0.1 --config configs/server.yaml
```

For a remote host, use the public IP or DNS name clients will connect to:

```bash
cargo run -p shroud-server -- generate-certs --server 104.20.23.154 --config configs/server.yaml --cert-dir certs
cargo run -p shroud-server -- add-client --name laptop --server 104.20.23.154 --port 8443 --config configs/server.yaml
```

`generate-certs` generates a self-signed server certificate directly. It does not create or require a local CA. The generated certificate always includes `localhost` and `127.0.0.1` as subject alternative names; when `--server` is another IP or DNS name, that value is added too.

Useful provisioning commands:

```bash
cargo run -p shroud-server -- generate-certs --help
cargo run -p shroud-server -- generate-certs --server 104.20.23.154 --config configs/server.yaml --cert-dir certs --force
cargo run -p shroud-server -- add-client --help
cargo run -p shroud-server -- add-client --name phone --server 104.20.23.154 --port 8443
cargo run -p shroud-server -- client-list --server 104.20.23.154 --port 8443
```

Behavior:

- `--config` selects the server config path; default is `configs/server.yaml`.
- `generate-certs --cert-dir` selects where `server.crt` and `server.key` are generated; default is `certs`.
- existing non-empty `tls.cert_path` and `tls.key_path` in the server config are preserved unless `generate-certs --force` is used.
- existing certificate/key files are reused unless `generate-certs --force` is used.
- `add-client` fails if the server certificate/key is missing; run `generate-certs` first.
- `add-client` rejects duplicate client names.
- `client-list` never writes to the server config.
- the private key is written with `0600` permissions on Unix.

`add-client` prints:

```text
Client created:

name: laptop
client_id: c1ce8312-7c35-4e70-867a-3af4ac7f68d7

Import string:
shrd:1:eyJuYW1lIjoibGFwdG9wIiwic2VydmVyIjoiMTA0LjIwLjIzLjE1NCIs...
```

Import strings contain client credentials. Do not share them publicly.

Create a client config from an import string:

```bash
cargo run -p shroud-client -- import 'shrd:1:...' --output configs/client-laptop.yaml
```

If `--output` is omitted, the client writes `client-<name>.yaml` using the profile name from the import string. Existing files are not overwritten unless `--force` is passed.

`setup` is still available as a compatibility shortcut. It runs the same provisioning path and prints a note recommending `generate-certs` and `add-client` for production use:

```bash
cargo run -p shroud-server -- setup --server 104.20.23.154 --port 8443 --name laptop
```

The old `scripts/generate-certs.sh` helper is still present for manual development workflows that need a local CA and an OpenSSL-generated server certificate. It is not required for the recommended provisioning workflow.

Legacy/manual credential generation still exists on the server for development:

```bash
cargo run -p shroud-server -- generate-credentials
```

## Run

Start the server:

```bash
cargo run -p shroud-server -- configs/server.yaml
```

Start the server with Docker Compose:

```bash
docker compose up --build shroud-server
```

The compose service mounts these host paths read-only into the container:

- `configs/server.yaml` -> `/app/configs/server.yaml`;
- `certs/` -> `/app/certs/`;
- `web/` -> `/app/web/`.

The container uses `/app` as its working directory, so relative server paths such as `certs/server.crt`, `certs/server.key`, and `./web` resolve under `/app`.

Start the client:

```bash
cargo run -p shroud-client -- configs/client.yaml
```

Both binaries use default config paths when no config argument is provided:

```bash
cargo run -p shroud-server
cargo run -p shroud-client
```

## SOCKS5 Smoke Test

Make sure SOCKS is enabled and TUN is disabled in the client config:

```yaml
inbounds:
  socks:
    enabled: true
    listen: "127.0.0.1:1080"
  tun:
    enabled: false
```

Run server and client, then test:

```bash
curl -v --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Use `--socks5-hostname`, not `--socks5`, when you want the domain name to be sent to Shroud and resolved on the server side.

## DNS Leak Notes

For SOCKS usage:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

preserves `example.com` and sends the domain through the tunnel.

This form:

```bash
curl --socks5 127.0.0.1:1080 https://example.com/
```

may resolve the domain locally before sending an IP target to the SOCKS proxy. In that case Shroud can warn about an IP target and can optionally block it with:

```yaml
dns:
  block_ip_targets: true
```

For TUN usage, Fake DNS only works when the system resolver actually sends DNS queries to the Shroud Fake DNS listener. The current implementation does not automatically switch the system DNS server.

DoH/DoT configured inside a browser is not intercepted by the current Fake DNS listener.

## TUN Mode

TUN mode is Linux-only and beta-level.

Enable it in the client config:

```yaml
inbounds:
  socks:
    enabled: false
  tun:
    enabled: true
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: false
    dns: "127.0.0.1"
```

With `auto_route: false`, Shroud opens and configures the TUN interface, but system traffic will not automatically use it.

With `auto_route: true`, Shroud attempts to move the default route through the TUN interface and adds loop protection for the tunnel server endpoint. Use this only in controlled test environments until TUN mode is more mature.

### Fake DNS With TUN

Fake DNS is started only when TUN mode is enabled. It listens on UDP port `53` at `inbounds.tun.dns`. If `dns` is omitted, the listener defaults to `127.0.0.1:53`.

`inbounds.tun.dns` does not install DNS into the operating system. It only chooses the address Shroud binds for the Fake DNS listener. The system resolver must be pointed at that address manually while the client is running.

Current Fake DNS behavior:

- handles only UDP DNS `A` queries;
- returns fake IPv4 addresses from `198.18.0.0/15`;
- keeps an in-memory mapping from domain to fake IP;
- when the TUN TCP stack later observes a connection to that fake IP, Shroud maps it back to the original domain and sends the domain through the tunnel;
- if the destination IP was not allocated by Fake DNS, Shroud treats it as a plain IP target.

Recommended local beta setup:

```yaml
inbounds:
  tun:
    enabled: true
    name: "shroud0"
    address: "10.10.0.2/24"
    mtu: 1400
    auto_route: true
    dns: "127.0.0.1"
```

Then manually point the host resolver to `127.0.0.1` for the test session. The exact command depends on the Linux resolver stack. For `systemd-resolved`, one temporary per-link option is:

```bash
sudo resolvectl dns shroud0 127.0.0.1
sudo resolvectl domain shroud0 '~.'
```

For systems that use `/etc/resolv.conf` directly, the equivalent test change is:

```text
nameserver 127.0.0.1
```

Restore the previous DNS settings after stopping Shroud. Shroud currently does not save, replace, or restore system DNS configuration.

If you configure `inbounds.tun.dns` to a non-loopback address, that address must be local and bindable by the client process before the Fake DNS task starts. For example, using `10.10.0.53` requires you to arrange that address yourself; Shroud does not add it automatically.

Current TUN limitations:

- TCP only;
- no UDP forwarding;
- no automatic system DNS switching;
- Fake DNS only works if the system resolver is pointed at the Fake DNS listen address;
- browser DoH/DoT bypasses Fake DNS;
- QUIC/HTTP3 traffic is not supported through TUN yet.

## TUN Smoke Test

The Linux TUN smoke test creates isolated network namespaces, starts a local server/client pair, and verifies that `curl` reaches a target through the TUN path.

Run:

```bash
sudo ./scripts/tun-smoke-linux.sh
```

If binaries are already built:

```bash
cargo build -p shroud-client -p shroud-server
sudo SHROUD_SMOKE_BUILD=0 ./scripts/tun-smoke-linux.sh
```

Expected success message:

```text
PASS: curl reached 198.51.100.10:18080 through shroudsm0 and Shroud tunnel
```

The script requires:

- root privileges;
- `curl`;
- `ip`;
- `python3`;
- `/dev/net/tun`.

## Tests

Run the regular test suite:

```bash
cargo test --workspace
```

Run the ignored Linux TUN smoke test through Cargo:

```bash
sudo cargo test -p shroud-client --test tun_smoke_linux -- --ignored
```

The TUN smoke test is ignored by default because it requires Linux root privileges and modifies network namespaces/routes.

## Protocol Summary

### raw_tcp

`raw_tcp` is the active client/server transport.

Connection sequence:

```text
client TCP connect to server
optional TLS handshake
client raw_tcp CONNECT request
server one-byte status
raw byte relay between client and target
```

Client request fields:

```text
magic:      "SHRD"
version:    1
command:    CONNECT = 1
auth_len:   u8
auth:       client_id + timestamp + nonce + hmac tag
host_len:   u8
host:       UTF-8 target host
port:       u16 big-endian
```

Server status values:

```text
0x00 ok
0x01 auth_failed
0x02 invalid_request
0x03 connect_failed
0x04 forbidden
```

Auth proof validation includes the configured client secret, a timestamp skew window, and nonce replay protection.

### Legacy Frame Helper

`shroud-core` still contains a small framed protocol helper with this header shape:

```text
version:   u8
kind:      u8
stream_id: u64
flags:     u16
length:    u32
payload:   [u8; length]
```

Current hard limit:

```text
MAX_FRAME_PAYLOAD_LEN = 32 KiB
```

This helper is covered by tests but is not the active data-plane for `raw_tcp` tunneling.

## Security Notes

- Use TLS in production.
- Pin self-signed/private server certificates with `transport.tls_server_cert_sha256`.
- Keep `client_secret` secret; treat it as a password.
- Do not commit production secrets or private keys.
- Review `security.deny_private_ips` and `security.allow_ports` before exposing a server to untrusted clients.

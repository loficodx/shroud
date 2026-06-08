# TLS Certificates

The recommended certificate workflow is `shroud-server setup`. It generates a self-signed server certificate directly and prints the SHA-256 fingerprint that the client should pin with `transport.tls_server_cert_sha256`.

Expected files for the default server config:

- `certs/server.crt`
- `certs/server.key`

`docker-compose.yml` mounts `./certs` into the container as `/app/certs:ro`, and `configs/server.yaml` reads:

```yaml
tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
```

## Recommended Setup

Run setup with the address clients will connect to:

```bash
cargo run -p shroud-server -- setup --server 127.0.0.1 --port 8443
```

For a VPS IP or DNS name:

```bash
cargo run -p shroud-server -- setup --server 159.23.231.151 --port 8443
cargo run -p shroud-server -- setup --server panel.example.com --port 8443
```

The generated certificate includes `localhost` and `127.0.0.1`. If `--server` is another IP or DNS name, that value is also added as a subject alternative name.

By default, setup reuses existing certificate files and existing configured client credentials. To regenerate the certificate/key pair:

```bash
cargo run -p shroud-server -- setup --server 159.23.231.151 --port 8443 --force-certs
```

The command prints a client config snippet. Copy the printed `transport` and `auth` blocks into the client config. A local CA certificate is not required when using the printed `tls_server_cert_sha256` pin.

## Legacy OpenSSL Helper

`scripts/generate-certs.sh` is still available for manual development workflows that need a local CA:

```bash
./scripts/generate-certs.sh
./scripts/generate-certs.sh 159.23.231.151
CERT_ADDRESS=panel.example.com FORCE=1 ./scripts/generate-certs.sh
```

That script creates:

- `certs/ca.crt`
- `certs/ca.key`
- `certs/server.crt`
- `certs/server.key`

The script also prints the server certificate SHA-256 fingerprint in DER format. Use either `transport.tls_server_cert_sha256` for pinning or `transport.tls_ca_cert_path` for CA trust, not both.

Do not commit production private keys or client secrets.

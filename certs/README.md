# Development TLS Certificates

The default local server config expects a local CA plus a server certificate signed by that CA.

Expected files:

- `certs/ca.crt`
- `certs/ca.key`
- `certs/server.crt`
- `certs/server.key`

`docker-compose.yml` mounts `./certs` into the container as `/app/certs:ro`, and `configs/server.yaml` reads:

```yaml
tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
```

## Generate certificates

Use the helper script:

```bash
chmod +x scripts/generate-certs.sh
./scripts/generate-certs.sh
```

By default, the script generates a local development certificate for `localhost` and `127.0.0.1`.

To generate a certificate for a VPS IP or domain, pass the address as the first argument:

```bash
./scripts/generate-certs.sh 159.23.231.151
# or
./scripts/generate-certs.sh panel.example.com
```

You can also use environment variables:

```bash
CERT_ADDRESS=159.23.231.151 ./scripts/generate-certs.sh
CERT_ADDRESS=panel.example.com ./scripts/generate-certs.sh
```

If certificates already exist, the script does not overwrite them. To regenerate everything:

```bash
FORCE=1 ./scripts/generate-certs.sh 159.23.231.151
```

After generation, start the server:

```bash
docker compose up --build
```

The script also prints the server certificate SHA-256 fingerprint in DER format. Use this value on the client side if certificate pinning is enabled.

Do not use these development keys in production.

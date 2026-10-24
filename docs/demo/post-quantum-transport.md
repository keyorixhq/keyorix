# Demo: post-quantum key exchange on the wire (about 4 minutes)

Shows that a stock Keyorix server and the `keyorix` CLI negotiate the hybrid post-quantum
key exchange X25519MLKEM768 with no configuration, how an operator sees it, and the revert
switch. Native, no Docker. Needs Go, OpenSSL 3.5 or newer (`openssl version`), and a
Keyorix checkout. What this does and does not protect:
[../post-quantum-transport.md](../post-quantum-transport.md).

## 1. Start a TLS server (1 min)

```sh
export BIN="$PWD/pq-demo"
go build -o "$BIN/keyorix-server" ./server && (cd cli && GOWORK=off go build -o "$BIN/keyorix" .)
mkdir -p ./pq-demo/run/certs && cd ./pq-demo/run
export KEYORIX_MASTER_PASSWORD='pq-demo-master-passphrase-2026'
"$BIN/keyorix-server" admin init --dev --config keyorix.yaml
"$BIN/keyorix-server" admin encryption init --config keyorix.yaml
"$BIN/keyorix-server" admin migrate --config keyorix.yaml
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -keyout certs/server.key -out certs/server.crt && chmod 600 certs/server.key
```

In `keyorix.yaml` set `server.http.port` to a free port (for example `"18697"`) and
`server.http.tls.enabled: true` (the cert paths are already `certs/server.crt` and
`certs/server.key`). Start it and leave it running:

```sh
KEYORIX_CONFIG_PATH=keyorix.yaml "$BIN/keyorix-server"
```

## 2. Look at the handshake (1 min)

In a second terminal:

```sh
openssl s_client -connect 127.0.0.1:18697 -tls1_3 -brief </dev/null 2>&1 | grep -i group
# Negotiated TLS1.3 group: X25519MLKEM768
```

A client that only offers a classical group still connects, classically:

```sh
openssl s_client -connect 127.0.0.1:18697 -tls1_3 -groups X25519 -brief </dev/null 2>&1 | grep -i 'temp key'
# Peer Temp Key: X25519, 253 bits
```

## 3. The CLI says so (30 s)

```sh
KEYORIX_SERVER=https://127.0.0.1:18697 KEYORIX_TOKEN=x KEYORIX_CA_FILE=certs/server.crt \
  "$BIN/keyorix" doctor | grep tls
# tls  ... chain verifies against certs/server.crt (TLS 1.3, key exchange X25519MLKEM768) ...
```

## 4. The operator sees it (30 s)

```sh
curl -sk https://127.0.0.1:18697/metrics | grep '^keyorix_tls_handshakes_total'
# keyorix_tls_handshakes_total{group="X25519",listener="http"} 1
# keyorix_tls_handshakes_total{group="X25519MLKEM768",listener="http"} 2
```

(The `curl` here is the macOS system curl, which uses Apple's TLS stack: it shows up as the
classical `X25519` series. That is the metric doing its job.)

## 5. The revert switch (1 min)

Stop the server, restart it with `GODEBUG=tlsmlkem=0`, and repeat step 2: the first command
now prints `X25519`, not the hybrid. Unset it to restore the default.

## What to say

- Nothing was configured: it is the Go default, and a test fails if code ever narrows it.
- It protects recorded traffic against later decryption. It does **not** make the
  certificate chain post-quantum.
- The metric is the audit trail: it shows what share of real clients is protected.

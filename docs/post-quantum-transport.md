# Post-quantum transport (TLS key exchange)

Keyorix's TLS listeners and its own TLS clients negotiate the **hybrid post-quantum key
exchange X25519MLKEM768** (X25519 combined with ML-KEM-768, FIPS 203) whenever the peer
offers it. There is no switch to turn on: it is the Go standard library's default since
Go 1.24, Keyorix builds with Go 1.27, and no Keyorix code narrows the key-exchange groups.
A test fails if that changes.

This page says exactly what that protects, what it does not, and how to check it yourself.

## What is protected, and what is not

| Protected | Not protected by this |
|---|---|
| The **key exchange** of every TLS 1.3 connection that both ends negotiate with the hybrid group. A recorded session cannot be decrypted later ("harvest now, decrypt later") by an attacker with a quantum computer, because the session key also depends on ML-KEM, which is believed to resist quantum attack. | **Certificates and signatures.** Server certificates, CA chains and the handshake signature are still classical (ECDSA/RSA). A quantum attacker who can break them *during* the handshake could impersonate the server; this does not enable decrypting recorded traffic. Post-quantum certificates are not generally available in public PKI. |
| It is hybrid: if ML-KEM were ever broken, X25519 still protects the session as it does today. | **Data at rest.** The database, backups, key files and the KEK/DEK hierarchy are outside this page's scope; nothing here changes them. |
| | **Signatures elsewhere**: audit-log signing, tokens, release signatures. Not assessed here. |
| | **TLS 1.2 connections.** TLS 1.2 has no hybrid group; a TLS 1.2-only client gets classical ECDHE. `tls_mode: strict` (TLS 1.3 only) removes that path. |
| | **Clients that do not offer the hybrid** (older OpenSSL, macOS system `curl`, some JDKs). They connect, classically. The server never *requires* the hybrid. |
| | **A TLS-terminating proxy in front of Keyorix.** The proxy's own TLS stack decides the group for the client-to-proxy leg; see below. |

"Post-quantum" here means the *confidentiality of recorded traffic*. It is not a claim that
the whole system is quantum-safe.

## What negotiates it

| Component | Offers/accepts X25519MLKEM768 | How it is known |
|---|---|---|
| Server, HTTP listener (default and `tls_mode: strict`) | yes | `server/pq_transport_test.go`; real server checked with OpenSSL 4.0.3 |
| Server, gRPC listener | yes | `server/grpc/pq_transport_test.go` (real grpc-go client) |
| `keyorix` CLI API calls and `keyorix doctor` | yes | `cli/internal/apiclient/tlsinspect_test.go`; `doctor` prints the group |
| Go SDK (`keyorix-sdks/go`) | yes (built with Go >= 1.24; its default client sets no TLS config) | run against a real server with a `DefaultTransport` clone trusting the test CA: the server counted one hybrid handshake |
| Node SDK | yes with Node 26.11 / OpenSSL 4 | run against a real server: `getEphemeralKeyInfo()` = `X25519MLKEM768` |
| Python SDK | yes with Python 3.14 / OpenSSL 4.0.3 | run against a real server: the server counted one hybrid handshake |
| Java SDK | **not verified** | no JDK in the test session; depends on the JDK's TLS provider |
| Outbound connectors (webhooks, Vault, KMS, Kubernetes...) | the client side offers it; the remote service decides | they use Go's default groups |

The SDKs inherit their language runtime's TLS library. Whether *your* client negotiates the
hybrid is a property of its runtime version; check it with the commands below.

## How to verify

**1. The server counts it.** Every completed handshake increments

```
keyorix_tls_handshakes_total{listener="http|grpc", group="X25519MLKEM768"}
```

on `/metrics` (see [operations/metrics.md](operations/metrics.md)). `group` is one of
`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `X25519`, `P-256`, `P-384`,
`P-521`, `none`, `other`. A healthy fleet shows the hybrid for current clients and some
classical series for old ones. The counter only observes; it never refuses a connection.

**2. `keyorix doctor`** reports the group the CLI negotiated with your server:

```
tls   pass   chain verifies against system roots (TLS 1.3, key exchange X25519MLKEM768); ...
```

`keyorix doctor -o json` has `key_exchange` and `post_quantum_key_exchange` fields in the
`tls` check's report (additive: existing consumers are unaffected). If the group is
classical the line says `(not post-quantum)`.

**3. OpenSSL 3.5 or newer** (OpenSSL 4.0.3 verified):

```sh
openssl s_client -connect keyorix.example.com:443 -tls1_3 -brief </dev/null 2>&1 | grep -i group
# Negotiated TLS1.3 group: X25519MLKEM768

# force a classical-only client to see the fallback:
openssl s_client -connect keyorix.example.com:443 -tls1_3 -groups X25519 -brief </dev/null
# Peer Temp Key: X25519, 253 bits
```

**4. curl** needs a build on OpenSSL 3.5+ (or BoringSSL/AWS-LC). Example, not run in the
test session because the macOS system curl uses Apple's TLS stack, which negotiates plain
X25519:

```sh
curl -sv --curves X25519MLKEM768 https://keyorix.example.com/health 2>&1 | grep -i 'SSL connection'
```

**5. From Go**: `resp.TLS.CurveID == tls.X25519MLKEM768` on an `*http.Response`, or
`conn.ConnectionState().CurveID` on a `*tls.Conn`. That is what the integration tests assert.

## The revert switch

Go reads `GODEBUG=tlsmlkem=0` and removes the ML-KEM hybrids from the default groups.
Set it in the environment of the process that should stop offering them:

```sh
GODEBUG=tlsmlkem=0 keyorix-server ...      # server stops negotiating the hybrid
GODEBUG=tlsmlkem=0 keyorix doctor          # this CLI run offers classical groups only
```

Connections keep working (X25519 outside FIPS mode). Use it only to rule out the hybrid
while diagnosing a handshake problem (next section). Keyorix itself sets neither
`GODEBUG=tlsmlkem=0` nor any `CurvePreferences`, in any image, chart or compose file
(`rg -i 'tlsmlkem|CurvePreferences|GODEBUG'` over the repository finds no setting).
`TestPQTransport_RevertSwitch_TLSMLKEM0_FallsBackToClassical` pins that the switch works.

## When it can break a connection

The hybrid key share makes the TLS ClientHello about 1.2 KB larger, which can exceed one
TCP segment. A small number of old firewalls, load balancers and middleboxes mishandle a
ClientHello that is split across segments or larger than they expect, and drop the
connection. Symptom: handshakes to Keyorix hang or reset from certain networks while
`GODEBUG=tlsmlkem=0` on the client makes them work. The fix is on the middlebox; the
switch above is the workaround.

## FIPS 140-3 mode

Keyorix has no `KEYORIX_FIPS_MODE` setting in this repository. Go's own FIPS mode is
`GODEBUG=fips140=on` (or `only`), and it was tested with the PQ handshake tests on Go 1.27.2:

| Mode | Result |
|---|---|
| `fips140=on` | the hybrid X25519MLKEM768 is still negotiated; X25519-only clients are refused (X25519 is not an approved group) |
| `fips140=only` | same |

golang/go#78298 reported that `fips140=only` failed every handshake with
`crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode`, because the hybrid was
on the FIPS allow-list while its X25519 half was rejected. It is fixed by wrapping the
hybrids in `fips140.WithoutEnforcement` (Go 1.27, back-ported to the 1.26 branch); we could
not reproduce it with the toolchain Keyorix builds with. **If you build Keyorix components with
an older Go (1.24-1.26 before the fix) and run them in `fips140=only`, you will hit it**;
the workaround there is `GODEBUG=fips140=only,tlsmlkem=0`. The `operator/` module declares
Go 1.26.6 in `go.mod`; its release images build with the 1.27 toolchain, but a build with
the declared minimum was not tested.

In FIPS mode, classical clients that offer only X25519 (many tools) cannot connect;
P-256-capable clients can. That is a property of FIPS mode, not of the hybrid.

## Reverse proxies

If TLS ends at a proxy (nginx, Caddy, a cloud load balancer), the proxy chooses the group
for the client-facing leg, and Keyorix sees only the proxy's connection. Caddy built with
Go >= 1.24 offers the hybrid by default; nginx needs OpenSSL 3.5+ and a group list that
includes it; managed load balancers publish their own policies. Check with the OpenSSL
command above against the public name.

## How this is kept true

- `server/pq_transport_test.go`, `server/grpc/pq_transport_test.go`: real handshakes against
  the listener configs the server builds, asserting `ConnectionState.CurveID`; classical-only
  and TLS 1.2 clients still connect; a control test shows a listener narrowed with
  `CurvePreferences` is caught.
- `TestPQTransport_HTTP_ListenerDoesNotSetCurvePreferences` and
  `TestCreateGRPCTLSConfig_DoesNotSetCurvePreferences` fail if any listener config sets
  `CurvePreferences`.
- The same tests run under `GODEBUG=fips140=on` and `fips140=only`
  (`GODEBUG=fips140=only go test ./server -run TestPQTransport`).
- Not covered by an automated test: the Node, Python and Java SDKs (checked by hand against a
  real server; Java not checked), and TLS terminated by a proxy.

Design note and risks: [design/post-quantum-transport.md](design/post-quantum-transport.md).

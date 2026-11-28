# ADR-126: TLS bootstrap: correct HTTPS for an unfamiliar on-prem or air-gapped install

**Status:** Proposed (2026-11-28). Design only. It becomes Accepted when Andrei has answered the
`NEEDS DECISION` items at the end. No code follows from this ADR until then.
**Date:** 2026-11-28
**Origin:** The hosted demo box got HTTPS by hand (Andrei, 2026-11-28). A person who has never seen
Keyorix should get working, trusted, self-renewing HTTPS from the install alone, also on a LAN or
an air-gapped network where ACME cannot reach a public CA.
**Related:** [ADR-112](adr-112-secure-by-default-baseline.md) (secure baseline, upgrade grace),
[ADR-125](adr-125-certificate-issuing.md) (certificate issuing; built-in CA deferred),
[ADR-055](adr-055-certificate-expiry-monitoring.md) / [ADR-056](adr-056-certificate-hygiene-posture.md)
(certificate-typed secrets), [post-quantum-transport.md](demo/post-quantum-transport.md),
open PR #4814 (`deploy/demo-lan`, a shell local CA for a demo box: the prototype of `private-ca`).

## Non-negotiable invariants this ADR must not weaken

- **Fail closed.** A listener that cannot present a certificate valid for its configured names
  does not start; a rotated certificate that does not validate is not served.
- **No cleartext bearer tokens or secret values on a network** unless an explicit, posture-visible
  setting says a TLS-terminating proxy is in front.
- **INV-GRPC-pq-key-exchange** (`server/grpc/INVARIANTS.d/INV-GRPC-pq-key-exchange.md`): no new
  certificate source sets `tls.Config.CurvePreferences`.
- **INV-TLSRELOAD** (`internal/tlsreload/INVARIANTS.md`): a pair that fails to load never replaces
  the pair being served.
- **No silent change for existing installs** (ADR-112): an upgraded config keeps today's behaviour
  until the operator opts in, or until a grace period that the operator is told about ends.

## 1. Facts (verified on main at `36325a505`, 2026-11-28)

### 1.1 What non-dev `admin init` generates

- Only for a config that run wrote (`server/admin/init.go:124-127`) or with `--secure-files` for an
  existing config (`server/admin/init.go:223-237`, used by the container entrypoint,
  `server/entrypoint.sh:76-84`). `--dev` generates nothing (`init.go:124`).
- One **self-signed leaf**, not a CA: `x509.CreateCertificate(rand.Reader, tmpl, tmpl, ...)`, no
  `IsCA`, `KeyUsageDigitalSignature`, EKU `serverAuth` (`server/admin/init_secure.go:157-168`).
- Key: **ECDSA P-256** (`init_secure.go:136`), PKCS#8, written first (`init_secure.go:177-181`).
- SANs: DNS `localhost`, `os.Hostname()` if it is a valid label (`init_secure.go:144-147`), plus
  repeatable `--tls-dns-name` (`init_secure.go:148-156`, flag `init.go:81`). IPs: **only
  `127.0.0.1` and `::1`** (`init_secure.go:166`). There is no way to add the machine's LAN IP.
- Validity: **397 days** (`init_secure.go:45`), `NotBefore` backdated 5 minutes (`init_secure.go:160`).
  Refuses when the clock is implausible (`init_secure.go:130-134`, `internal/clockcheck`).
- Paths from the template: `certs/server.crt`, `certs/server.key` (`configs/keyorix.yaml.tpl:54-55`),
  both 0600 via `createPrivateFile` (`init_secure.go:179-184`, `226-234`). The same pair is reused for
  gRPC (`keyorix.yaml.tpl:104-105`; de-duplicated at `init_secure.go:61-68`).
- It prints `keyorix config set ca_file <cert>` / `KEYORIX_CA_FILE` (`init_secure.go:190-195`): the
  leaf itself is the trust anchor, so **every renewal means re-trusting every client**.
- **Nobody renews it.** `server/clock_warnings.go:17-19`: "The server does not renew a certificate
  itself." The only warning is a log line at start-up inside 30 days of expiry
  (`clock_warnings.go:36-57`); a server that runs for a year without a restart never logs it. The
  `keyorix_tls_certificate_not_after_timestamp_seconds` gauge exists
  (`internal/tlsmetrics/tlsmetrics.go:26-29`) but alerts only if someone scrapes and alerts on it.

### 1.2 What the server does with a non-loopback bind and TLS off

- Default bind is loopback: `DefaultBindHost = "127.0.0.1"` (`internal/config/config_server.go:102`).
- `checkTransportTLSPosture` (`server/startup_checks.go:43-83`) **does not look at the bind address
  at all**. TLS off on any listener: refuse only when `security.require_transport_tls` is true
  (`startup_checks.go:70-71`), otherwise a `WARNING` log line (`startup_checks.go:73-76`).
- The secure template sets `require_transport_tls: true` (`keyorix.yaml.tpl:201`).
  `server/config/production.yaml:82` sets it `false` on purpose (TLS at a reverse proxy,
  `production.yaml:36,48`). The `--dev` template binds `localhost` (`configs/dev.yaml:19`) with TLS
  off and the key absent, so editing it to `0.0.0.0` serves cleartext with one warning line.
- Posture mirrors the boot check: cleartext is a deviation only if `require_transport_tls` is set
  (`server/admin/posture.go:564-583`); otherwise informational, counted as
  `security.insecure_allow_cleartext_transport` (`internal/config/insecure_settings_registry.go:354-361`).
- **Docker default stack:** the backend runs TLS, but the nginx `web` container publishes
  **`8088:80` on every interface in cleartext** (`docker-compose.yml:177-178`); HTTPS only with the
  `tls` profile (Caddy on 80/443, `docker-compose.yml:303-305`). A server-side bind check cannot see
  this.

### 1.3 Built-in certificate sources

- Static files with **hot reload without restart**: `tlsreload.New` + `GetCertificate`
  (`server/tls_config.go:24,31`; gRPC `server/grpc/server.go:323,328`). Re-read at most every 30 s
  (`internal/tlsreload/tlsreload.go:35`), change detected by content digest, a broken pair keeps the
  old one (`tlsreload.go:1-16`).
- Built-in ACME for **HTTP only**: `autocert.Manager{Cache: DirCache, Prompt: AcceptTOS,
  HostPolicy: HostWhitelist}` (`server/tls_config.go:91-95`). No `DirectoryURL` is configurable, so
  it always talks to Let's Encrypt production, via TLS-ALPN-01 on the listener itself. gRPC refuses
  `auto_cert` (`config_server.go:304`, `480-481`); the air-gapped build refuses it
  (`internal/config/airgap_profile.go:24-26`, `docs/AIRGAP_RUNBOOK.md:31`).
- No client-certificate authentication on any listener (ADR-125 §"What Keyorix has today").

### 1.4 How the CLI verifies the server

- Go's default verification against the system roots, or a root pool built **only** from
  `ca_file` (curl `--cacert` semantics): `cli/internal/apiclient/ca_file.go:28-83`. It refuses a
  group/other-writable file, a file with a private key, or no certificate.
- Precedence `--ca-file` > `KEYORIX_CA_FILE` > stored `ca_file` (`cli/cmd/client.go:115`).
- `login` checks TLS trust **before** asking for the password (`cli/cmd/login.go:75-84`) and stores
  the CA path it used (`login.go:132-140`). On a verification error it prints a hint to set
  `ca_file` (`login.go:409`).
- **No TOFU, no fingerprint, no pinning** anywhere in `cli/` (only release-bundle key pinning,
  `cli/cmd/bundle.go:38-41`). No `InsecureSkipVerify` in `cli/`.
- `keyorix doctor` already does a verifying handshake and reports chain, expiry, TLS version and
  key-exchange group (`cli/internal/apiclient/tlsinspect.go:56-123`).

### 1.5 Posture and compliance

- `admin validate --posture` has **no certificate check** (no expiry, SAN or chain): TLS posture is
  on/off and `tls_mode` only (`server/admin/posture.go:564-583`).
- The Compliance control **"Certificate expiry hygiene"** (`internal/core/control_framework.go:213-217`)
  is about **certificate-typed secrets** (ADR-055/056), not the server's own certificate. Its
  "not configured" means the ADR-055 scan is off or there are no such secrets
  (`control_framework.go:343-373`, `internal/core/compliance_posture.go:281-289`).
- The crypto inventory already lists each enabled TLS listener's certificate
  (`server/http/handlers/crypto_inventory.go:136-144`, `internal/cryptoinventory/cert.go`).

### 1.6 Docs, demo and hosted demo

- `docs/SELF_HOSTING.md:773-797`: the `tls` profile (Caddy, ACME, public DNS, ports 80/443); for
  `localhost` Caddy's internal CA, whose root the operator copies out by hand for the CLI.
- `docs/SELF_HOSTING.md:1032-1062` (single binary / air-gapped): "point `server.http.tls` at a
  CA-issued one for production" and nothing more.
- `docs/demo/GOLDEN-PATH.md:408-427`: the self-signed leaf as `ca_file`, `curl --cacert`.
- `deploy/demo-hosted/Caddyfile.demo:1-20`: Caddy + Let's Encrypt, staging for rehearsal.
- `docs/CONFIGURATION.md:228-237`: which side verifies what (`tls.cert_file` vs CLI `ca_file`).

### 1.7 Why a newcomer fails today

1. **Wrong name:** the SANs are a guess (`os.Hostname()`, often a short name) and never the LAN IP
   (§1.1), while clients type an FQDN or an IP.
2. **No trust path:** the trust anchor is the leaf; there is nothing to install once and keep.
3. **Silent expiry:** 397 days, no renewal, one log line at a start that may never happen (§1.1).
4. **Cleartext by accident:** the Docker default publishes cleartext on the LAN (§1.2); a dev
  config on `0.0.0.0` only warns.

## 2. Decision (Proposed)

One identity per server, chosen once, declared in config, applied to both listeners, checked at
start, renewed in-process, visible in posture, compliance and audit.

### 2.1 Config shape

A new block, separate from the existing per-listener `tls_mode` (TLS version policy, ADR-112 §3),
whose name it must not reuse:

```yaml
server:
  certificates:
    source: private-ca        # acme | private-ca | byo | proxy ; absent = legacy (today's behaviour)
    names:                    # what clients type; DNS names and IP literals
      - keyorix.lab.example
      - 10.20.0.5
    private_ca:
      leaf_lifetime: 90d
      renew_before: 30d
      ca_lifetime: 5y
      root_key: discard        # discard | export (see 2.3)
      export_ca_file: ""       # optional public copy of the root (0644), e.g. for nginx/Caddy
    acme:
      directory_url: ""        # empty = Let's Encrypt; set for an internal ACME CA (step-ca, ...)
      email: ""
      eab_key_id_file: ""      # external account binding, when the CA needs it
    byo:
      cert_file: certs/server.crt
      key_file: certs/server.key
      ca_bundle_file: ""       # chain to validate against; empty = system roots
```

`server.certificates.names` is the single source of truth for the server's names. It also seeds
`webauthn.rp_id` / `rp_origins` and `server.http.allowed_origins` at init (`internal/config/config_webauthn.go:53-64`
already ties origins to the host): a passkey is bound to the RP ID, so renaming the server later
breaks passkeys, and the install question is the moment to get the name right.

**Legacy (key absent)** = exactly today: `http.tls`/`grpc.tls` files with hot reload, or
`auto_cert`. Posture reports it as "certificate source not declared" (informational in release N,
see 2.8).

### 2.2 Mode selection at install

`keyorix-server admin init` on a TTY asks one question and only the follow-ups the answer needs:

```
How will clients reach this server?
  1) Only from this machine                         -> private-ca, names: localhost
  2) On a LAN or air-gapped network (name or IP)    -> private-ca, asks names; offers the FQDN and
                                                       the addresses of non-loopback interfaces, and
                                                       sets server.http.host to match
  3) From the internet at a public domain           -> acme, asks domain and e-mail
                                                       (absent in the air-gapped build)
  4) Through a load balancer or proxy that does TLS -> proxy, asks the proxy addresses
  5) With a certificate from my organisation's CA   -> byo, asks the paths and validates them now
```

Non-interactive: `--certificates <mode> --name <dns-or-ip>...` (plus mode flags). Without a TTY and
without flags, init picks **private-ca with `localhost` names and the loopback bind** (the same
reach as today's config, which binds 127.0.0.1) and prints one line saying how to add names. The
container entrypoint keeps `KEYORIX_TLS_DNS_NAMES` and gains `KEYORIX_CERT_SOURCE`.

The challenge to the brief's starting point: the question is really "**which names**", not "which
mode". Modes 1 and 2 are the same mechanism with different names, so the default for anything
not public is one mode, and the names are asked explicitly instead of guessed. A config whose
bind address is non-loopback but whose names are loopback-only is refused at start (2.7).

### 2.3 `private-ca`

**Shape.** Two levels, created at **first server start** (not by `admin init`: the CA keys are
encrypted with the DEK, which exists only after `admin encryption init`):

- **Root:** self-signed ECDSA P-256, `IsCA`, `MaxPathLen 1`, critical
  `nameConstraints` = the configured `names` (DNS subtrees, IP /32 or /128) plus `localhost`,
  `127.0.0.1/32`, `::1/128`; `ca_lifetime` (default 5 years).
- **Intermediate ("issuer"):** signed by the root, `MaxPathLen 0` (`MaxPathLenZero`), the same
  critical name constraints, EKU `serverAuth`, lifetime = the root's.
- **Leaf:** signed by the issuer, ECDSA P-256, SANs = `names` (+ loopback), EKU `serverAuth`,
  `leaf_lifetime` (default 90 days), `NotBefore` backdated 1 hour (skewed LAN clients), **no CRL
  distribution point and no AIA/OCSP URL** (an air-gapped client must never stall on a revocation
  fetch). Presented chain: leaf, issuer, root.

Why two levels: RFC 5280 does not require a verifier to apply constraints carried in a trust
anchor, so constraints on the root alone protect only some clients. Constraints on the
intermediate are processed by every RFC 5280 path validator. They only mean something if the root
key cannot mint a fresh, unconstrained intermediate, hence `root_key`:

- **`discard` (default):** the root key exists in memory only long enough to sign the issuer, and
  is then zeroed and never written. A stolen box yields the issuer key, which can sign only for
  the Keyorix names. Cost: replacing the issuer means a new root (re-trust).
- **`export`:** the root key is written once, encrypted with a passphrase the operator types, to
  a path the operator names (removable media), and never kept on the box. Re-issuing the issuer
  later (`admin tls reissue-issuer --root-key <path>`) keeps the root and avoids re-trust.

The CA's purpose is **only the server's own listeners**. It has no API, issues nothing for anyone
else, and is not ADR-125 option B (a general CA), which stays deferred. A PR that exposes issuance
needs ADR-125's own threat model first.

**Key protection at rest.** The issuer key and the root and issuer certificates live in the
database (`tls_ca` table), the key encrypted under the existing encryption service (DEK, wrapped by
whatever `key_provider` the install uses: password, file, shamir, TPM, KMS), with an AAD bound to
the row. A database dump or backup alone cannot mint. Someone with the running process or the DEK
can, exactly as they can read every secret. The TPM provider is not a custody claim here (ADR-125
notes ADR-117 is Proposed). The leaf key never leaves process memory: it is generated at start or
renewal and not written anywhere.

**Creation, exactly once.** First start, under the existing key-initialisation lock: `INSERT ... ON
CONFLICT DO NOTHING`, then read back (the Postgres lesson in CLAUDE.md); a second replica uses the
row the first wrote. The server then prints to stdout and the log, on the box's own console:

```
Keyorix private CA created (names: keyorix.lab.example, 10.20.0.5)
  CA fingerprint  SHA256:3f:9a:...:c1
  CA certificate  https://keyorix.lab.example:8080/.well-known/keyorix/ca.pem
  CLI             keyorix login --server https://keyorix.lab.example:8080 --ca-fingerprint SHA256:3f9a...c1
  Trust it in browsers on each client:
    macOS    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
    Windows  certutil -addstore -f Root ca.pem          (elevated prompt)
    Debian   sudo cp ca.pem /usr/local/share/ca-certificates/keyorix.crt && sudo update-ca-certificates
    RHEL     sudo trust anchor ca.pem
    Firefox  uses its own store unless security.enterprise_roots.enabled; import it there
```

`keyorix-server admin tls status` prints the same block at any time, offline, from the database.
Keyorix prints these commands and never runs them on a client.

**Leaf renewal without restart.** A new certificate source next to `tlsreload` that implements
`GetCertificate` from an in-memory `atomic.Pointer[tls.Certificate]`. A ticker checks every hour;
when less than `renew_before` remains (or at start), it generates a key, signs, verifies the new
chain against the root for every name, **commits the `tls.leaf_issued` audit record**, then swaps
the pointer. A failed step keeps the current leaf, logs, raises the metric and retries next tick.
The 30-day margin is what makes audit-before-use safe: an audit outage delays renewal, it does not
cause a TLS outage until it has lasted 30 days. The source feeds `tlsmetrics.Wrap` like the other
two, so the existing gauge works unchanged, and it never sets `CurvePreferences`.

**CA rotation.** `admin tls rotate-ca` creates root R2 and issuer I2 while R1 is valid; the server
serves leaves from I2, and `/.well-known/keyorix/ca.pem` serves R1+R2 for a transition window
(default 30 days). Browsers and OS stores need R2 installed (printed as above). The CLI follows
automatically only with a **successor statement**: I1 signs "R2 replaces R1, fingerprint X" and the
CLI, still trusting R1, verifies it and re-pins (PR-9, optional). Without it, re-pinning is
manual. Expiry warnings for the CA start 180 days ahead (posture, compliance, metric).

**Compromise.** If the box is compromised, the attacker holds the issuer key and can impersonate
**only the Keyorix names** for the rest of the issuer's lifetime. There is no usable revocation for
a private root on air-gapped clients, so the response is `admin tls rotate-ca --compromised` (no
successor statement, no transition window: R1 is withdrawn from the well-known bundle at once),
plus removing R1 from every client store. CLIs pinned to R1 then refuse the server and say why.
The ADR does not claim more than this.

### 2.4 First CLI login: TOFU and its threat model

**The window.** On first contact the CLI cannot tell the real CA from one an on-path attacker
presents. If the user accepts the attacker's CA, the next thing the CLI sends is the username and
password (and a TOTP code, which a live relay can use at once). So the CLI must settle trust
before any credential is sent, which `login` already does (`login.go:75-84`).

**Ranked mechanisms (strongest first):**

1. **Out-of-band fingerprint** (`keyorix login --ca-fingerprint SHA256:...`, also
   `KEYORIX_CA_FINGERPRINT`): the kubeadm `--discovery-token-ca-cert-hash` model. The CLI fetches
   the chain in the handshake, checks that the root in it has this fingerprint and that the chain
   verifies for the host, then pins it. No prompt, no window. The install banner prints this exact
   command, so the admin pastes it into onboarding instructions.
2. **A CA file distributed by the organisation** (`ca_file`, today), or MDM installing the root in
   the OS store.
3. **Interactive TOFU**, only on a TTY: the CLI shows the root's fingerprint, the names it is
   constrained to and where to compare it ("printed on the server console at install; `keyorix-server
   admin tls status`"), and requires the user to type `yes`. Without a TTY, an unknown CA is
   refused.

**Pinning** writes the root PEM to the CLI's config directory (0600, the same checks
`LoadCAPool` applies) and sets `ca_file` to it, so every existing code path verifies against it. A
pinned server whose chain no longer verifies is a hard error, SSH style ("the server's CA changed:
this is either a CA rotation or an attack; compare..."), with no "accept anyway" prompt. The pin is
the root CA, never the leaf, so leaf renewal is invisible to clients.

The CLI takes the root from the TLS handshake (the server sends it in the chain), not from an
unauthenticated HTTP fetch, so TOFU adds no "skip verification" request path. `/.well-known/keyorix/ca.pem`
exists for humans and for browsers' "download, then install" step; its integrity comes only from
the fingerprint comparison.

### 2.5 `byo` (enterprise PKI)

At start and on every hot reload, the pair is validated in full, and a failure refuses the start
(or keeps the previous pair on reload, per INV-TLSRELOAD, with a `tls.reload_rejected` audit event):

- key matches the certificate; RSA >= 2048 or ECDSA P-256/P-384 or Ed25519;
- chain verifies to `ca_bundle_file` (or the system roots) with EKU `serverAuth`;
- **every** entry of `server.certificates.names` is covered by the SANs (a CN-only certificate is
  refused, as Go clients refuse it);
- not expired and already valid, judged only on a plausible clock (`clockcheck.Plausible`): on an
  implausible clock it warns and starts, keeping the edge-device behaviour of
  `clock_warnings.go:21-26`;
- less than 30 days left: start, but posture deviation, compliance gap and a log line every day.

`byo` is the recommended mode for organisations with a PKI: no new root of trust on their clients.

### 2.6 `acme`

- Built-in `autocert` gains `directory_url`, `email` and external account binding, so an **internal
  ACME CA** (step-ca, an enterprise ACME endpoint) works on an air-gapped network. The air-gapped
  build keeps refusing the public directories (Let's Encrypt, ZeroSSL by URL) at config validation
  and accepts an explicit internal `directory_url` (ADR-125 design point 7).
- The autocert cache moves to a database-backed `autocert.Cache` (encrypted like 2.3) so that
  replicas share one certificate and do not each hit the CA's rate limits.
- ACME on gRPC stays refused unless the same source feeds both listeners (one identity).
- `acme` needs the listener reachable on 443 (TLS-ALPN-01) or a port-80 helper (HTTP-01). For
  Docker the documented path stays Caddy (`tls` profile), which already does this.

### 2.7 `proxy`, and the cleartext rule

**Enforced rule (replaces "warn unless `require_transport_tls`"):** a listener **without TLS on a
non-loopback address** refuses to start, unless `source: proxy`. In `proxy` mode:

- `server.http.trusted_proxies` must be non-empty (start refused otherwise);
- the cleartext listener **answers only TCP peers in `trusted_proxies`** (and loopback, for health
  checks); any other peer gets the connection closed and a counted, logged refusal. This is what
  makes "the server is on a private network only" an enforced property: in a container the bind
  address is always `0.0.0.0`, so checking the bind address alone would prove nothing;
- posture shows "TLS terminated at proxy: certificate not observable by Keyorix".

Also refused at start in every mode: a non-loopback bind whose `names` are loopback-only (the
"wrong name" failure caught before a client sees it).

The Docker default stack changes in the same series: `8088` is published on `127.0.0.1` only, and
the LAN path is the `tls` profile or `private-ca` served by the backend through the web container
(PR-8). The Helm chart is out of this ADR's PRs (PROD-HELM-1 owns `deploy/helm`); it needs the same
review.

### 2.8 Upgrade path (no surprise breakage)

- An existing config without `server.certificates` keeps today's behaviour in release N:
  `tls.cert_file` files with hot reload, or `auto_cert`. Posture adds the informational line
  "certificate source not declared" and the new certificate checks (expiry, SANs vs host) as
  informational only.
- The cleartext rule (2.7) for an **upgraded** config follows the ADR-112 grace pattern
  (`EnableFilePermissionCheckUpgradeGrace`): release N warns at every start, reports a posture
  deviation and a compliance gap; release N+2 refuses. A config that explicitly writes
  `require_transport_tls: false` (the `production.yaml` proxy topology) is told to set
  `source: proxy` and `trusted_proxies`. Fresh installs are enforced from their first start.
- `keyorix-server admin tls migrate --to private-ca|byo|proxy|acme` writes the block, prints what
  each client must do (for private-ca: trust the new root once; the old self-signed leaf stops
  being presented), and is recorded in the audit chain.
- The existing `certs/server.crt` from init is never deleted by migration.

### 2.9 HA / multi-node

- `private-ca`: CA rows are shared through PostgreSQL, encrypted under the DEK that every replica
  already shares (`docs/SELF_HOSTING.md` "Running more than one replica"). **Each replica issues
  its own leaf** from the issuer key; no leaf key is ever distributed. Leaves carry the shared
  names (the load balancer's name) and may add a per-node name. Rotation is a row state
  (`pending`, `active`, `retiring`) picked up on the hourly tick. SQLite is single-node by
  definition.
- `acme`: database-backed autocert cache (2.6), so one certificate is shared.
- `byo`: the operator places the same files on every node; `admin diagnose` on each node reports
  the fingerprint so a mismatch is visible.
- `proxy`: nothing changes; `trusted_proxies` must list every balancer address.
- A balancer doing TLS passthrough sees the replicas' leaves, all chained to the same root.

### 2.10 Post-quantum interplay

- Key exchange stays Go's default (`X25519MLKEM768` hybrid, `docs/demo/post-quantum-transport.md`):
  the new certificate sources only supply `GetCertificate` and never set `CurvePreferences`
  (INV-GRPC-pq-key-exchange; the existing guard tests are extended to the new sources).
- Certificates stay classical (ECDSA P-256). This protects recorded traffic against later
  decryption, not authentication against a future quantum attacker. Post-quantum signatures in
  X.509 for TLS are not supported by the clients that matter at the time of writing; that must be
  re-checked before Accepted.
- CA rotation (2.3) is the migration path to post-quantum or composite certificates; the 5-year
  default CA lifetime is chosen so a rotation happens anyway well within that horizon.
- `keyorix doctor` already reports the negotiated group (`tlsinspect.go:39-44`); `admin tls status`
  adds the certificate algorithm so the two are never confused.

### 2.11 Diagnostics in plain words

No third command. `keyorix-server admin diagnose` gains a `tls` section and `keyorix doctor`'s
existing `tls` check gains explanations. Both say what is wrong and what to type, for example:

- "The certificate is for `keyorix.lab.example`, `localhost`; you connected to `10.20.0.5`. Use
  `https://keyorix.lab.example:8080`, or add the address: `keyorix-server admin tls names add 10.20.0.5`."
- "The server listens on 0.0.0.0 but its certificate names only localhost: clients on the network
  will get a name error."
- "This CA is not trusted on this machine. Its fingerprint is SHA256:... ; compare it with the
  server console, then run ..."
- "The certificate expires in 12 days and source is byo: Keyorix cannot renew it; replace
  `certs/server.crt`, it is picked up within 30 s."

`admin tls names add` re-issues the leaf at once when the new name is inside the CA's name
constraints, and says that a CA rotation is needed when it is not.

### 2.12 Posture and Compliance

- `admin validate --posture`: deviations for an expired or less-than-7-day certificate, names not
  covered by the SANs, a non-loopback bind with loopback-only names, cleartext without `proxy`,
  CA within 180 days of expiry; informational for the source and the days left.
- **A new control, not the existing one.** "Certificate expiry hygiene" covers certificate-typed
  secrets (§1.5); folding the server's own certificate into it would let one healthy listener
  certificate turn an unscanned secret population into a pass (the #397 false-pass class that
  `certificateHygieneStatus` was written to prevent). A new control `transport-certificate`
  (Area Cryptography, the same framework references) reads the **certificate actually being
  served** (from the active source, not a re-read of a file, because private-ca and acme have no
  file): Pass with more than 30 days left and names covered; Gap when expired, less than 7 days,
  or names not covered; Unknown in `proxy` mode, with the detail "terminated at the proxy". The
  tile the demo shows as "not configured" today stays the secrets control and keeps meaning that.

### 2.13 Audit events

Recorded through the existing audit API (no change to the audit write path), actor `system` for
the server's own actions and `admin_cli` for `keyorix-server admin` commands
(`server/admin/admin.go:375-387`):

| Event | When | Content (never key material) |
|---|---|---|
| `tls.ca_created` | first start, private-ca | root and issuer fingerprints, name constraints, lifetimes, `root_key` mode |
| `tls.ca_rotated` | `admin tls rotate-ca` | old/new fingerprints, `compromised` flag |
| `tls.leaf_issued` | issue or renewal | serial, SANs, notAfter, replica id; committed before the leaf is served |
| `tls.leaf_renewal_failed` | renewal step failed | step, error class |
| `tls.cert_reloaded` | byo/legacy file change accepted | fingerprint, notAfter |
| `tls.reload_rejected` | byo file change refused | reason (SAN, chain, key mismatch, expired) |
| `tls.acme_certificate_obtained` | autocert cache write | domain, notAfter, directory host |
| `tls.source_changed` | `admin tls migrate` | old and new source |
| `tls.names_changed` | `admin tls names add/remove` | old and new names |

A start-up refusal cannot be audited (storage may be the reason); it is logged, and posture shows
it after the fix.

### 2.14 What each mode fails closed on

| Mode | Refuses to start | Keeps serving the old certificate | Never does |
|---|---|---|---|
| private-ca | implausible clock at CA or first leaf creation; CA row unreadable or undecryptable; issuer outside its own constraints; names outside the CA's constraints | renewal failed (sign, verify, audit) | write the leaf key or the root key (discard mode) to disk; serve a leaf that does not verify for every name |
| byo | key mismatch; chain does not verify; a name not covered; expired on a plausible clock; weak key | rotated pair fails any start check | serve a pair it would refuse at start |
| acme | air-gapped build with a public directory; no domains; domain not in `names` | renewal failed (autocert keeps the cached one) | fall back to a self-signed certificate |
| proxy | `trusted_proxies` empty | n/a | answer a non-proxy, non-loopback peer in cleartext |
| any | cleartext on a non-loopback bind outside proxy; non-loopback bind with loopback-only names | | accept TOFU without a TTY; accept a changed pinned CA |

## 3. Test plan

Unit (default CI):
- CA and leaf templates: name constraints critical on root and issuer, `MaxPathLen` values, no CRL
  DP/AIA, SANs = names; a certificate for another name signed by the issuer fails Go verification;
  an unconstrained intermediate signed by the issuer is refused (`MaxPathLenZero`).
- Discard mode: no file and no column holds the root key after creation (scan the DB row and the
  data directory).
- Renewal: fake clock at `renew_before` ± 1 day; failure at each step (sign, verify, audit) keeps
  the old leaf; the pointer swap is race-free (`-race`, concurrent handshakes during renewal).
- Audit before use: a failing audit sink means the new leaf is never served.
- byo validator: table of bad pairs (wrong key, CN-only, missing SAN, expired with a plausible and an
  implausible clock, RSA 1024, wrong EKU), at start and on reload.
- Cleartext rule: matrix of bind (loopback, LAN IP, `0.0.0.0`, `::`) × TLS × source; proxy-mode
  peer filter refuses a non-proxy peer and accepts loopback.
- Fresh vs upgraded config: the grace path warns in N and refuses in N+2 (driven by the release
  constant, not the calendar: `guardrules`, `docs/guard-rollout-contract.md`).
- CLI: `--ca-fingerprint` match and mismatch; TOFU refused without a TTY; a changed pinned CA is a
  hard error; no credential prompt before trust is settled.
- PQ: the existing `TestPQTransport_*` / `TestCreateGRPCTLSConfig_DoesNotSetCurvePreferences` run
  against each new source.

Integration (native server, SQLite and kpg Postgres):
- Fresh `admin init --certificates private-ca --name <ip>`: server starts, `admin tls status` prints
  the fingerprint, `keyorix login --ca-fingerprint` works, `curl --cacert ca.pem` works for every
  name and fails for another name.
- Two replicas on one Postgres starting at once create exactly one CA (independent `*gorm.DB`
  connections, not a shared storage object) and each serves its own leaf.
- Renewal with `leaf_lifetime: 2m`, `renew_before: 1m` on a running server: new serial served
  without a restart.

Verifier matrix (pending e2e VM and manual browser runs): name-constraint enforcement and
chain building in Go, OpenSSL 3, curl, Chrome, Firefox, Safari/macOS, Windows CryptoAPI, Java,
Python requests; including the behaviour with the root-only constraints, to confirm the two-level
design is needed and sufficient. This matrix must pass before `private-ca` becomes the default.

## 4. Implementation plan (PRs, each based on main, small)

| PR | Content | Size | Security path (Andrei's gate) |
|---|---|---|---|
| PR-1 | This ADR (docs only) | ~590 lines docs | no |
| PR-2 | `internal/localca`: pure package, CA/issuer/leaf templates, name constraints, verify helpers; no wiring | ~350 + tests | **yes** (crypto) |
| PR-3 | `server.certificates` config block, validation, `config.d` fragments; legacy = absent; no behaviour change | ~250 + tests | yes (config validation) |
| PR-4 | private-ca wiring: `tls_ca` table + encrypted storage, first-start creation under lock, in-memory renewing `GetCertificate` source, audit events, banner, `admin tls status` | ~400 + tests | **yes** (keys, storage, TLS) |
| PR-5 | byo validator at start and on reload (extends tlsreload with a validate hook), posture checks, `admin diagnose` tls section | ~300 + tests | **yes** (TLS acceptance) |
| PR-6 | Cleartext rule + proxy-mode peer filter + upgrade grace; posture deviations | ~250 + tests | **yes** (transport, fail-closed defaults) |
| PR-7 | `admin init` question and flags, entrypoint env, names → webauthn/origins seeding | ~300 + tests | yes (init defaults) |
| PR-8 | Docker compose: 8088 on loopback, private-ca through the web container; SELF_HOSTING/AIRGAP docs via `upgrading.d` / `configuration.d` fragments | ~150 | yes (deployment default) |
| PR-9 | CLI: `--ca-fingerprint`, TOFU on TTY, pin-as-ca_file, changed-CA hard error, doctor wording; optional successor statement | ~350 + tests | **yes** (client trust) |
| PR-10 | `transport-certificate` compliance control + crypto inventory from the live source + web tile | ~250 + tests | no (read-only reporting) |
| PR-11 | acme: `directory_url`, EAB, DB-backed autocert cache, air-gapped public-directory refusal | ~300 + tests | **yes** |
| PR-12 | `admin tls rotate-ca`, `names add/remove`, `migrate`, export-root mode | ~350 + tests | **yes** |

Order: 2 → 3 → 4 → (5, 6 in parallel) → 7 → 8, 9, 10; 11 and 12 after 4. PR-9 waits for CLI-UX-2
(owns `cli/`). PR-5 touches `server/tls_config.go` / `server/grpc/server.go`; check overlap with
HARDEN-HTTP-1 first. PR-3 and PR-7 touch `internal/config/config.go` (hot file): last commit, tiny.

## 5. Alternatives considered

- **Keep the self-signed leaf, just add names and renewal.** Rejected: every renewal would need
  every client to re-trust; this is the root of "no way for clients to trust it".
- **One-level constrained root, key kept online.** Simpler, but its constraints bind only verifiers
  that apply trust-anchor constraints, and a stolen box gives an unconstrained-intermediate minting
  key. Kept as the fallback if the verifier matrix shows root constraints are universally enforced.
- **Ship Caddy (or step-ca) for every mode.** Good for Docker, wrong for the single binary and the
  air-gapped edge device, and it moves the CA key outside Keyorix's encryption and audit.
- **SSH-style TOFU as the primary path.** Rejected as primary: users accept prompts; the
  fingerprint-in-the-command path costs the admin one paste and has no window.
- **Feed the server certificate into the existing certificate-hygiene control.** Rejected (2.12).
- **Refuse cleartext by bind address only.** Rejected: in a container the bind is always `0.0.0.0`;
  the peer filter in proxy mode is the enforceable property.

## 6. Security considerations

- Installing any CA on employee machines widens their trust; name constraints and the two-level
  design limit it to Keyorix's names, and `byo` avoids it. Docs must say so plainly.
- The issuer key is as safe as the DEK; with `discard`, no key that can sign an unconstrained CA
  exists anywhere after creation.
- No revocation is offered for the private CA; short leaves (90 days) and rotation are the controls,
  and no CRL/OCSP URL is advertised.
- TOFU's window is real; it is never the only option and never available without a TTY.
- The proxy-mode peer filter depends on `trusted_proxies` being correct; a too-wide CIDR reopens
  cleartext to that range. Posture shows the ranges.
- Name and SAN parsing (`names`, `--name`) is an input-validation surface: exact-match, IDNA
  rejected or normalised, fuzzed like the other parsers.

## NEEDS DECISION

1. **CA key at rest:** issuer key encrypted under the DEK in the database (recommended) vs a 0600
   file like today's leaf key vs KMS/HSM signing only.
2. **Root key:** `discard` by default (recommended; rotation = re-trust) vs keep it online encrypted
   (in-place issuer re-issue, but a stolen box can mint unconstrained intermediates) vs `export` by
   default (needs removable media at install).
3. **First-login trust:** fingerprint-in-command as the documented path plus interactive TOFU on a
   TTY (recommended) vs fingerprint/CA file only (no TOFU at all).
4. **Default when nothing is configured** (fresh, non-interactive, no flags): private-ca with
   loopback names and loopback bind (recommended) vs today's self-signed leaf vs refuse to init.
5. **Plain HTTP behind `--dev` on a non-loopback bind:** refuse (recommended; use private-ca) vs allow
   with a registered `insecure_` setting.
6. **Upgrade grace for the cleartext rule:** warn in N, refuse in N+2 (recommended) vs refuse at once
   vs warn forever for configs that explicitly wrote `require_transport_tls: false`.
7. **byo expiry at start:** refuse when expired on a plausible clock, warn on an implausible one
   (recommended) vs always warn (edge first) vs always refuse.
8. **Audit-before-use for leaf renewal:** a renewal whose audit record cannot be committed is not
   served (recommended, safe because of the 30-day margin) vs serve and retry the audit.
9. **Name-constraint breadth:** exact configured names (recommended; a rename outside them needs a CA
   rotation) vs a permitted domain suffix (`--ca-permit-domain corp.example`, easier renames, wider
   blast radius).
10. **Lifetimes:** leaf 90 days / renew 30 days before / CA 5 years (recommended) vs PR #4814's
    820-day leaf / 10-year CA.
11. **Built-in ACME vs Caddy** as the documented internet path for the single binary (recommended:
    built-in with `directory_url`; Caddy stays for Docker).
12. **Proxy-mode peer filter:** enforce (recommended) vs advisory only.

## Verification

This ADR enforces nothing yet. The facts in §1 were read on main at `36325a505`. Statements about
RFC 5280 trust-anchor constraint processing, browser and OS verifier behaviour, Firefox's store and
the per-OS trust commands are general knowledge and are to be confirmed by the verifier matrix (§3)
before this ADR is accepted.

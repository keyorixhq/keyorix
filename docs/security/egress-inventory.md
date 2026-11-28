# Egress inventory: what Keyorix can connect to

A security reviewer's question is "does it phone home?". This page answers it from the
code, and the answer is checked by a test, not asserted here.

**Answer.** No Go code in this repository contacts a Keyorix-operated service or any other
third party on its own: there is no telemetry, analytics, crash-reporting, licence-check or
update-check call, and no OTLP, Sentry or push-gateway client is imported. Every outbound
destination class below needs either an operator setting in the config file (or an
environment variable, for the separate binaries) or an object an authorised admin creates
through the API, and every class is **off** until then: with no `storage` block the server
uses a local SQLite file and has no outbound destination at all. What the check does not
see (browser JavaScript, subprocesses) is listed under "What the check does not establish".
The "Needs coordinator" section lists what is not as simple as that.

The two files DOCS-EDGE-FDATASYNC-1 could not open settle the same way:
`internal/core/usage_report.go` and `server/http/handlers/reports/admin_usage.go` are one
read of local storage (`GetProjectUsageStats`) returned as the JSON response of
`GET /api/v1/admin/usage` to an authenticated admin (permission `audit.read`). Neither
opens a connection, and no usage, stats or analytics file is in the allowlist below.

## How this list was established, and why it is complete for what it checks

`internal/egressguard` (`TestEgressSitesAreInventoried`) parses every non-test `.go`
file with `go/parser`, in the root module and every nested module (`cli/`, `operator/`,
`migrate/`, `devtools/`, `scripts/`), ignoring build tags so the `noaws`/`noazure`/`nogcp`
variants are read as well. It skips only `_test.go` files, `testdata/`, `vendor/`,
`node_modules/`, `.git/`, and `web/`, `tmp/`, `.scratch/`, `.claude/` at the repository
root. A file is an outbound site when it uses one of these forms, resolved through the
file's own import names (an aliased import is followed):

1. **A reference** to a function or variable that dials or sends: `http.Get/Post/PostForm/Head`,
   `http.DefaultClient`, `http.DefaultTransport`, `net.Dial*`, `net.Lookup*`,
   `net.DefaultResolver`, `tls.Dial`, `tls.DialWithDialer`,
   `httputil.NewSingleHostReverseProxy`, `sql.Open`, `sql.OpenDB`,
   `grpc.Dial/DialContext/NewClient`, `gorm.Open`, `ssh.Dial`, `ssh.NewClientConn`,
   `pgx.Connect/ConnectConfig`, `pgxpool.New/NewWithConfig`,
   `stdlib.OpenDB/RegisterConnConfig`, `saml.FetchMetadata`.
2. **Construction of a client type**: `http.Client`, `http.Transport`, `net.Dialer`,
   `net.Resolver`, `tls.Dialer`, `httputil.ReverseProxy` as a composite literal, `new(T)` or
   `var x T`. A type that only appears in a parameter, field or return type is not a site.
3. **Importing a package that only exists to talk to a remote service**, because such
   libraries open the connection inside the call: `net/smtp`, `net/rpc`,
   `golang.org/x/oauth2` (its exchange falls back to `http.DefaultClient`), websocket
   libraries, `go-mail`, the AWS SDK `config`/`service`/`feature` packages, the Azure
   `azidentity`/`security`/`resourcemanager`/`storage` packages, `cloud.google.com/go/...`,
   `google.golang.org/api/...`, Vault's API client, `lib/pq`, the MySQL driver, `go-redis`,
   the MongoDB driver, the AWS credential providers, the Keyorix client SDKs, OTLP
   exporters, Sentry, the Prometheus push gateway client, `client-go`,
   `controller-runtime`. Packages whose last path element is `types` or `bson`, and
   `google.golang.org/api/option` and `iterator`, carry data types only and are not sites.

Each site file must have a row in [`egress-allowlist.tsv`](egress-allowlist.tsv) with a
class from the table below and a reason. The test also fails for a row that covers no site
(stale), for a class used in the allowlist but missing from the table, and for a table class
no row uses. So the table and the allowlist cannot drift from each other or from the code.

**Checking the list of forms itself.** A list of call forms is only as complete as its
author's idea of what a client looks like, and the first version of this one was not: it
did not know the MongoDB driver, so `internal/rotation/mongodb.go` and
`internal/dynamic/mongodb.go` were invisible until the direct dependencies in `go.mod` were
read one by one. `TestEgressEveryDirectDependencyIsClassified` makes that reading permanent:
every direct dependency of every `go.mod` in the repository (the root module, `cli/`,
`operator/`, `migrate/`, ...) must be classified in `dependencyKinds` as `client` (the
scanner recognises it, which the test also checks) or `local: <why it opens no
connection>`. A new library added to any module fails the test until someone decides.

Re-derive it yourself: `go test ./internal/egressguard/ -run TestEgressSitesAreInventoried -v`.
A new outbound client in a new file fails with `<file>:<line> creates an outbound connection
(<forms>) and has no row in docs/security/egress-allowlist.tsv`.

What the check does **not** establish (a green run is not "Keyorix makes no other connection"):

- A connection made through a package or function that is not in the lists above. The lists
  are the reviewable assumption; extend them when a new kind of client is adopted.
- What a subprocess does. `storage.encryption.key_provider.type: exec` runs the operator's own
  `exec_command`, and `keyorix run` runs the user's command; those programs may use the
  network. Every call site that starts a process is listed and checked under "Subprocess call
  sites" below, but the child's own connections are not.
- Browser-side requests (JavaScript in `web/`, the vendored swagger UI). Served markup is
  checked for third-party hosts by `server/http/airgap_external_hosts_guard_test.go`, which
  states its own limits.
- Reflection, plugins, code generated at run time.
- Whether a site is reachable, and the **trigger / config key / default / data** columns:
  those are reviewed prose, read from the code named in the allowlist reasons. The `On by
  default` column is read from the wiring in `server/wire_*.go` and `server/schedulers.go`.
- `DEV` rows. The test that makes the "not shipped" claim true checks direct imports: no
  file outside a `DEV` row imports a package inside one, so a binary built from shipped
  packages cannot contain a `DEV` site. The `DEV` programs themselves (`scripts/`,
  `examples/`) are not release artifacts; the release targets in the `Makefile` build
  `./server` (and the air-gap variant), `cli`, and `migrate`.

Out of scope here because it is inbound, not egress: the `/metrics` endpoint is scraped by
the operator's Prometheus; Keyorix does not push metrics anywhere (no push-gateway or OTLP
exporter is imported).

## Destination classes

"Data" lists field names, never values. The operator-named HTTP sinks of E02 to E06 go
through the egress guard (class E19): HTTPS is required unless the host is loopback, and
private, link-local and cloud-metadata addresses are refused unless the operator sets the
matching `insecure_allow_*` option (the config comments name each opt-out, and the alert
escalation sink in E03 also refuses redirects). This document does not repeat those
per-sink settings.

| ID | Destination class | Trigger | Config key / how set | On by default | Data sent (names only) |
|---|---|---|---|---|---|
| E01 | The operator's own database. PostgreSQL over TCP when `storage.type` is `postgres`; a SQLite file (no network) otherwise | Server boot and every query; `admin` commands; restore; audit verify | `storage.type`, `storage.database.dsn` or `host`/`port`/`name`/`user`/`password` (env `KEYORIX_DB_PASSWORD`)/`ssl_mode`/`ssl_root_cert`, `storage.database.path` | Local SQLite file, no network destination | All application records, to a database the operator owns |
| E02 | Notification receivers named in config: a webhook, Slack, Teams, an SMTP relay | A notification is created (expiry/rotation reminders, compliance digest, auto-rotation failures, ...) | `notifications.webhook.{enabled,endpoint,token,signing_secret}`, `notifications.slack.{enabled,webhook_url}`, `notifications.teams.{enabled,webhook_url}`, `notifications.email.{enabled,host,port,username,password,from,tls,broadcast_to}` | No: every channel `enabled: false`; with none enabled notifications stay in the app | `core.NotificationEvent`: `user_id`, `email` (recipient), `type`, `title`, `message`, `project_id`, `link`. Slack/Teams get title and message text only. Webhook adds an `X-Keyorix-Signature` HMAC header when a signing secret is set |
| E03 | Webhook or Slack channels an admin created for alert escalation | An anomaly alert goes unacknowledged past an escalation policy's delay | Created through the API (a notification channel and an alert-escalation policy), stored in the database, not in the config file | No: no channel exists until an admin creates one | `event`, `alert_id`, `severity`, `alert_type`, `description` (with the accessing user and IP redacted), `secret_name`, `detected_at`, `policy_name`, `channel` |
| E04 | The operator's SIEM: Splunk HEC, Datadog Logs, or a generic authenticated webhook | Every audit event, plus replay of the on-disk spool | `audit.siem.{enabled,provider,endpoint,token,spool_dir}` (env `KEYORIX_SIEM_TOKEN`) | No: `enabled: false` | Audit event: `id`, `event_type`, `timestamp`, `user_id`, `project_id`, `secret_id`, `description`, `ip_address`, `actor_type`, `success`, `diff`, `impersonation`, `impersonated_by`, `acting_as`, `entry_hash`, `prev_hash`, `request_id` |
| E05 | An RFC 3161 timestamp authority the operator names | Each audit checkpoint is written | `audit.checkpoint_notary.{enabled,type,url,timeout,ca_cert_path}` | No: `enabled: false`; with no `url` it does nothing | A SHA-256 digest of the checkpoint (the RFC 3161 message imprint) only |
| E06 | Off-box evidence storage the operator names: a webhook, or an S3-compatible bucket | The evidence-delivery schedule | `evidence_delivery.{enabled,schedule,output_dir,webhook.*,object_store.*}` (object-store credentials come from the standard AWS chain, never from Keyorix config) | No: `enabled: false` | The compliance evidence pack: `generated_at`, `posture`, `controls`, `audit_anchor`, `campaigns`, `break_glass`, `rotation_overdue`, `sod_violations`, `risk_exceptions`, `access_requests`, and a detached signature for the object store |
| E07 | The operator's SMTP relay, for first-credential setup links | An admin creates a user or invitation | `credential_delivery.{mode,base_url,smtp.*}` | No: `mode` empty means `auto`, which uses SMTP only if a relay is configured, else returns the link to the admin | The setup link (an absolute URL containing a single-use token) to the recipient's address |
| E08 | The SSO identity provider the operator names (OIDC issuer) | Server boot (OIDC discovery document), each SSO login (code exchange, key fetch) | `sso.{enabled,providers[].{name,type,issuer,client_id,client_secret,redirect_url,scopes}}` | No: `sso.enabled: false`. SAML providers use `idp_metadata_xml`/`idp_metadata_file` and make no outbound request | The OAuth2 authorisation-code exchange (the provider's client credentials and the one-time code); the discovery document and keys are plain GETs |
| E09 | The JWKS endpoint of each trusted machine-identity issuer | A machine presents a federated token | `oidc.{enabled,issuers[].{issuer,jwks_uri,audiences}}` | No: `oidc.enabled: false` | An unauthenticated GET of `jwks_uri` |
| E10 | External secret stores for read-through federation: AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault | A caller reads a `connect` reference | `connect.{enabled,connectors[].{name,type,region,address,project_id,account_id,token_env,allowed_refs,scope,project}}`; credentials from the cloud's ambient identity chain or the env var `token_env` names | No: `connect.enabled: false`, no connectors | The secret reference (name or ARN) being read; the cloud SDK adds its own signed-request headers |
| E11 | A cloud KMS holding the key-encryption key | Server boot (unwrap the KEK) and any admin command that opens the key | `storage.encryption.key_provider.{type,kms_key_id,wrapped_key_path,kms_encryption_context}` with `type` one of `aws-kms`, `gcp-kms`, `azure-kms` | No: the default `type` is `password` (local derivation); the other providers (`file`, `env`, `exec`, `shamir`, `tpm`) are local | The wrapped KEK blob and the key identifier (the KMS unwrap call) |
| E12 | A database or cloud API whose credential Keyorix rotates: AWS IAM, Azure (Microsoft Graph), GCP service accounts, MySQL, PostgreSQL, MongoDB, Redis | A rotation against a configured backend runs (an admin-triggered rotation, or the auto-rotation scheduler) | `auto_rotation.backends[].{name,type,dsn_env,region,allowed_refs}` (the DSN is read from the env var `dsn_env` names; cloud credentials from the ambient chain); `auto_rotation.{enabled,schedule}` for the scheduler | No: `auto_rotation.backends` is empty and `auto_rotation.enabled` is false | The new credential for the target account, to the target the operator named |
| E13 | A backend that issues dynamic-secret leases: AWS STS, Azure, GCP IAM credentials, Kubernetes, MySQL, PostgreSQL, MongoDB, Redis; plus one DNS lookup of the target host | An admin registers a dynamic-secret config (the DNS check), a lease is issued, renewed or revoked | Dynamic-secret config created through the API (`admin_dsn` or cloud settings); `dynamic_secrets.*` for the private-network and plaintext opt-outs | No: needs an admin-created dynamic-secret config | The credential-issue and revoke calls for the lease, to the target the admin named; the DNS query carries the target hostname |
| E14 | `keyorix-k8s-sync` (separate binary): the Keyorix server it reads from, and the Kubernetes API server it writes Secrets to | The sync loop (or one pass with `--once`) | Its own config file (`--config`, env `KEYORIX_K8S_SYNC_CONFIG`: the Keyorix URL, project ID, mappings) and env `KEYORIX_TOKEN` | Not part of the server binary; runs only where deployed | Secret reads from Keyorix; Kubernetes Secret objects to the in-cluster API |
| E15 | The Kubernetes operator (separate module): the Kubernetes API server, and the Keyorix server named in each `KeyorixSecret` | Reconcile loop | `KeyorixSecret` custom resources and the operator's own flags | Not part of the server binary; runs only where deployed | Secret reads from Keyorix; Kubernetes object reads and writes |
| E16 | The `keyorix` CLI to the Keyorix server URL the user gives it | A CLI command; the CLI's TLS diagnostic (`InspectTLS`) | `client.endpoint`, `client.auth`, the CLI's CA file option | Only to the URL the user configures; no other host | The command's API request |
| E17 | `keyorix-mcp` to the Keyorix server it is configured with | An MCP tool call | Environment: `KEYORIX_URL`, `KEYORIX_TOKEN` or `KEYORIX_TOKEN_FILE` (both required) | Not part of the server binary; runs only where deployed | The tool call's API request |
| E18 | `keyorix-migrate` (separate binary): the source store being migrated from (Vault, AWS, Azure, GCP) and the target Keyorix server | The operator runs a migration | Its own flags | Not part of the server binary; runs only when the operator runs it | Reads from the source store; secret writes to the Keyorix server |
| E19 | DNS resolution by the egress guard (`internal/netutil`) of a destination's hostname before it connects; no destination of its own. Used by the code of E02 to E06, E08, E09, E10 (Vault, Azure), E11 (Azure), E13, E14 and E17 | Any delivery or fetch of those classes | n/a (follows each destination's own config) | No: only when one of those classes is configured | A DNS query for the configured hostname, to the host's resolver |
| DEV | Development and test tooling: `scripts/` (e2e, fuzz, drills, demo, metrics), `examples/`, `internal/testhelper/`, and the `internal/testutil/` packages `fuzzworld`, `pgcanary`, `pgdsn`, `pgwirecount`, `sqlitetest` | Run by a developer or CI | n/a | Not shipped: see "How this list was established" | n/a |

Air-gap build: `make` also builds the server with `-tags noaws,noazure,nogcp`
(`BINARY_SERVER_AIRGAP`), which swaps the AWS, Azure and GCP files of E10 to E13 for
no-op stubs (`*_noaws.go`, `*_noazure.go`, `*_nogcp.go`); `novault` and `nok8s` do the same for
the Vault connector and the Kubernetes dynamic-secret backend. The guard reads both
variants of each file, so it does not itself check what a tagged build leaves out.

## Subprocess call sites

Every place shipped Go code starts a process (`os/exec` `Command`/`CommandContext`,
`exec.Cmd` built directly, `syscall.Exec`/`ForkExec`, `os.StartProcess`, `unix.Exec`),
found by `TestEgressSubprocessSitesAreInventoried` in `internal/egressguard`. Files of the
`DEV` rows (`scripts/`, `examples/`, ...) are not scanned. A row is keyed by file and
function, so every call in that function must fit the row. An unlisted call site fails
with `<file>:<line> starts a subprocess ... and has no row`. What the child itself does is
not checked: the last column is reviewed prose.

| Class | Meaning |
|---|---|
| EXEC-OPERATOR-CONFIGURED | The command line comes from the operator's deployment configuration and is run by the server. The child may use the network |
| EXEC-LOCAL-ONLY | A fixed program and fixed arguments (no operator or user choice of program), working on local files; no connection of its own |
| EXEC-USER-COMMAND | The person running the CLI names the program and its arguments; it runs with that person's rights. The child may use the network |

| File | Function | Class | Runs | Command line set by | Reaches the network |
|---|---|---|---|---|---|
| `internal/crypto/exec_provider.go` | `ExecKeyProvider.KEK` | EXEC-OPERATOR-CONFIGURED | The key helper (`op read`, `sops -d`, `vault read`, a sidecar helper) whose stdout is the KEK, with a timeout, no shell and only `PATH`/`HOME` in its environment | `storage.encryption.key_provider.exec_command` (argv) in the server config, at boot and on admin commands that open the key | Not by Keyorix; the helper usually does (a secret manager) |
| `cli/cmd/run.go` | `execChild` | EXEC-USER-COMMAND | `keyorix run -- <command>`: the child process that receives the secrets as environment variables | The user's argv after `--`; no shell | Not by Keyorix; the child does whatever the user's program does |
| `cli/cmd/secret_scan.go` | `resolveScanFileSet` | EXEC-LOCAL-ONLY | `git diff --cached --name-only` and `git diff-tree` to list the files `secret scan --staged/--commit` checks | Fixed `git` and fixed flags; the user's `--commit` value is one argv entry and may not start with `-` | No: reads the local repository (the user's own git configuration applies) |
| `internal/fuzzutil/osairgap/jail.go` | `Run` | EXEC-LOCAL-ONLY | Re-executes the running test binary (`self`, `-test.run=TestOsairgapNSInitDispatch`) in a fresh network namespace (`CLONE_NEWNET`), as the parent half of the OS-level air-gap egress fuzz harness. Test-only fuzz tooling, not imported by shipped code | The calling test passes its own binary path (`os.Args[0]`) and the fixed `-test.run` flag; the `RunSpec` goes over an environment variable | No: the child starts with no interface but loopback, which is the point of the jail |
| `internal/fuzzutil/osairgap/jail.go` | `RunNSInit` | EXEC-LOCAL-ONLY | The program under test (`RunSpec.Argv`), run inside the new network namespace with proxy variables pointing at a loopback canary that records egress attempts. Test-only fuzz tooling, not imported by shipped code | The calling test's own `RunSpec.Argv`; no shell | No: the namespace has only loopback, so a dial out fails with `ENETUNREACH` and is reported as a containment error; the harness exists to prove that |
| `fuzzkit/certdiff/certdiff.go` | `opensslVerify.Run` | EXEC-LOCAL-ONLY | `openssl verify -CAfile ... -attime ...` on PEM files the harness wrote to its own temp dir, as the reference verifier in the certificate differential fuzzer. Fuzz tooling in the separate `fuzzkit/` module, not imported by shipped code | Fixed `openssl` program and fixed flags; the arguments are the harness's own temp-dir paths and a timestamp | No: verifies local files (`verify` does no fetching) |
| `tools/oraclehealth/runner.go` | `Env.goCmd` | EXEC-LOCAL-ONLY | `nice -n N go test` against a mutated working copy, for the fuzz-oracle mutation tool. Development tool, not a release artifact and not imported by shipped code | Fixed `nice`/`go`; the arguments are the tool's own subcommands and flags | Only through the Go toolchain's own module download, if the module cache is cold; no Keyorix code connects |
| `server/http/handlers/contracttest/exercising_tests_exist.go` | `realTestNames` | EXEC-LOCAL-ONLY | `go test -list` in the handlers package, for a test that checks test names. Test helper: not imported by any shipped package | Fixed arguments; the `go` binary is `runtime.GOROOT()` or the `go` found on `PATH` | Only through the Go toolchain's own module download, if the module cache is cold; no Keyorix code connects |

## Per-site inventory: who supplies the destination, what guards it (V7-GAP-1)

The class table above says what Keyorix can connect to. This section is one row per
outbound site (or per family of identical sites) and answers the SSRF question: **who
supplies the host, is there a guard in front of the dial, and are redirects followed**. It is
reviewed prose, derived by reading each site; the file list behind it is the allowlist, which
`TestEgressSitesAreInventoried` keeps complete. A site not in this table is a defect in this
table, not a licence.

Destination supplier, from least to most attacker-reachable:

| Code | Supplier | Reachable by |
|---|---|---|
| C | compiled constant (a cloud SDK's own endpoint) | nobody |
| O | operator config file or environment | instance operator only |
| U | the person running a CLI/operator/tool | that person |
| P | stored per-project setting written through the API | a project admin (below instance admin) |
| H | a third-party response (discovery document, redirect, returned endpoint) | whoever controls or can tamper with that upstream |

Guard column: `netutil` = `netutil.Dialer` re-validating every dial (resolve, check every
answer, dial the pinned IP); tier names are in "Intentional differences" below. `own` = a
documented package-local policy. `scheme` = https required (http only for loopback) with no
dial guard. Redirects: `refused` = `CheckRedirect` returns an error or `ErrUseLastResponse`;
`same-host` = only a same-origin, non-downgrading hop; `default` = Go's default (follow up to
10).

| # | Site (file) | Class | Supplier | Attacker-influenced | Guard in front of the dial | Redirects | Fuzz/differential coverage |
|---|---|---|---|---|---|---|---|
| S01 | `internal/notifychan/webhook.go`, `chat.go`, `secure_transport.go` | E02 | O | no | netutil, loopback-permitted tier, resolver seam `lookupIPAddr` | same-host only, no downgrade, bounded hops | `FuzzWebhookSSRFGuard`, `FuzzSSRFGuardDifferential` |
| S02 | `internal/notifychan/email.go`, `internal/delivery/smtp.go` (E07) | E02, E07 | O (SMTP host). The recipient address is user data, the relay host is not | no | none: SMTP host is operator config; TLS mode checked (`tls=none` needs an env opt-in) | n/a | none needed: nothing attacker-chosen reaches the dial |
| S03 | `internal/core/alert_escalation.go` | E03 | P (channel URL, stored) | **yes** (anyone allowed to create a notification channel) | netutil, loopback-permitted tier, per-send re-validation, resolver seam `channelLookupIPAddr` | refused (`noEscalationRedirect`) | `FuzzSSRFGuardDifferential` (predicate), table tests `alert_escalation_ssrf_sendtime_test.go`, `alert_escalation_redirect_ssrf_test.go`; no dial-wiring fuzz |
| S04 | `internal/core/notification_channels.go` | E03 | P | **yes** | create/update-time check with the private tier; the dial itself is S03 | n/a | `FuzzSSRFGuardDifferential` |
| S05 | `internal/audit/siem/forwarder.go` | E04 | O | no | own policy on purpose (loopback permitted, same predicate as the webhook tier) via `netutil.Dialer` | same-host only, no downgrade, bounded hops | `FuzzEgressGuardParity`, `FuzzSSRFGuardDifferential` |
| S06 | `internal/notary/rfc3161.go` | E05 | O | no | scheme only (`netutil` here is URL redaction, not a dial guard) | refused | none needed |
| S07 | `internal/evidencesink/webhook.go` | E06 | O | no | netutil, loopback-permitted tier | same-host only, no downgrade, bounded hops | `FuzzEgressGuardParity` |
| S08 | `internal/evidencesink/objectstore.go` | E06 | O | no | own: the endpoint's address is resolved once and every dial of that client goes to that pinned IP, so a redirect cannot leave the endpoint. Private endpoints are allowed by design | default, but pinned to the endpoint IP | none: operator-only |
| S09 | `server/wire_sso.go` (discovery GET; its client also carries S10) | E08 | O (issuer) | no | netutil, link-local tier | same-host | **new** `FuzzOIDCDiscoveryTransportEgressParity` (drives the `oidcDiscoveryTransport` var; the client is `ssoIdPHTTPClient`, shared with S10); rebinding: `FuzzOIDCDiscoveryResolverRebinding` (stubbed stdlib resolver, same transport var) |
| S10 | `internal/core/sso.go` (code exchange, `Exchange`) | E08 | H (`token_endpoint` from the discovery document), held at discovery to the issuer's host or an operator-listed `token_endpoint_hosts` entry, https unless the issuer is http on loopback | no (since #4738): a compromised IdP can still name any port and path on its own host or a listed host (RFC-1918 and loopback reachable by design; for an http-loopback dev issuer, any loopback port) | netutil, link-local tier: the provider's `HTTPClient`, the same `ssoIdPHTTPClient` (transport `oidcDiscoveryTransport`) as S09; `CompleteSSO` refuses a provider without one instead of falling back to `http.DefaultClient` | same-host (the S09 policy) | **new** `FuzzSSOExchangeTransportEgressParity` (drives the client `buildSSOProviders` puts on the provider), `TestSSOExchangeClientIsTheDiscoveryClient`, `FuzzDiscoverOIDCHostile` (token_endpoint oracle). Finding F2, fixed |
| S11 | `internal/oidcverify/oidc_jwks.go` | E09 | O (`jwks_uri`) | no | netutil, link-local tier; https required | same-host, max 3 hops | **new** `FuzzJWKSTransportEgressParity` (drives the client `NewHTTPJWKSResolver` builds); rebinding: `FuzzJWKSResolverRebinding` |
| S12 | `internal/connect/vault.go`, `hardened_client.go` | E10 | O (connector `address`) | no. The `ref` a caller reads is a path inside that address, and `allowed_refs` limits it | netutil, link-local tier, plus a request-target check for a literal link-local host | refused | **new** `FuzzConnectVaultTransportEgressParity` (drives the client `NewVaultConnector` builds); rebinding: `FuzzConnectVaultResolverRebinding` |
| S13 | `internal/connect/azurekv.go` | E10 | O (vault URL) | no | netutil, link-local tier | refused | **new** `FuzzConnectAzureTransportEgressParity` (drives `azureKVHTTPClient`, the client handed to azsecrets); rebinding: `FuzzConnectAzureResolverRebinding` |
| S14 | `internal/connect/awssm.go` | E10 | O (region, from the SDK endpoint rules); an ARN in a caller's `ref` does not choose the endpoint | no | netutil, link-local tier | refused | **new** `FuzzConnectAWSTransportEgressParity` (drives `awsSMHTTPClient`, the client installed in the SDK); rebinding: `FuzzConnectAWSResolverRebinding` |
| S15 | `internal/connect/gcpsm.go` | E10 | C | no | none (gRPC to the SDK's constant endpoint); size caps only | n/a | none needed |
| S16 | `internal/crypto/azurekms/azurekms.go` | E11 | O (`kms_key_id`, host must end in an Azure Key Vault suffix) | no | netutil, private tier (loopback refused too), resolver seam `azureKMSResolve` | default (followed); every hop is re-dialed through the guard | **new** `FuzzAzureKMSTransportEgressParity`, `FuzzAzureKMSResolverRebinding` |
| S17 | `internal/crypto/awskms`, `gcpkms` | E11 | C | no | none (SDK constant endpoints) | n/a | none needed |
| S18 | `internal/rotation/azure.go` (Microsoft Graph) | E12 | C (hard-coded Graph host) | no | netutil, link-local tier (a hostile redirect or proxy is the only route in) | refused | **new** `FuzzAzureGraphTransportEgressParity`; rebinding: `FuzzAzureGraphResolverRebinding` |
| S19 | `internal/rotation/awsiam.go`, `gcpsa.go`, `azure_sdk.go` | E12 | C | no | none (SDK constant endpoints) | n/a | none needed |
| S20 | `internal/rotation/postgres.go`, `mysql.go`, `mongodb.go`, `redis.go` | E12 | O (`dsn_env`) | no | none for private networks (the target is the operator's own database); MySQL and RESP responses are bounded by `netutil.MySQLGuardDialer` / `RESPGuardDialer` | n/a | response-bound fuzzers only |
| S21 | `internal/dynamic/postgres.go`, `mysql.go`, `mongodb.go`, `redis.go` | E13 | P (`admin_dsn`) | **yes** (project admin) | netutil, private tier, every dial, opt-out `allow_private_network`; `mongodb+srv` targets pre-validated | n/a | `FuzzAdminDSNHostSSRFGuard`, `FuzzSSRFGuardDifferential`, `FuzzDSNHostsCoverDriverHosts`, `FuzzEgressDialEnforcement`; table tests `internal/dynamic/egress_guard_test.go` |
| S22 | `internal/dynamic/kubernetes.go` | E13 | P (`api_server` inside `admin_dsn`) | **yes** (project admin) | netutil, private tier, every dial, opt-out `allow_private_network` (explicit `api_server` only; the in-cluster API address is exempt); register-time host check kept as defence in depth | refused (every hop is re-dialed through the guard) | `TestKubernetesEngine_DialGuard` (`internal/dynamic/kubernetes_dialguard_test.go`: loopback refusal, resolver rebinding, positive control). F1 fixed |
| S23 | `internal/dynamic/awssts.go`, `azure.go`, `gcp.go` | E13 | C | no | none (SDK constant endpoints) | n/a | none needed |
| S24 | `internal/core/dynamic_secrets.go` | E13 | P | **yes** | this is the register-time DNS check itself (private tier), not a connection | n/a | `FuzzAdminDSNHostSSRFGuard` |
| S25 | `internal/k8ssync/keyorix_fetcher.go`, `rest_sink.go`, `cmd/keyorix-k8s-sync` | E14 | O (config file), in-cluster API server | no | scheme (https; http loopback only) | refused (fetcher) | none needed |
| S26 | `operator/internal/keyorix/client.go` | E15 | **P-like** (a `KeyorixSecret` custom resource names the server) | **yes** (any tenant who can create the resource) | own: the server must be https and in the operator's `--allowed-servers` list (empty list rejects every resource) | refused | `FuzzValidateServer` (operator module) |
| S27 | `cli/internal/apiclient/*`, `cli/cmd/client.go` | E16 | U | no | none: the user chooses the server | refused | hostile-server fuzzers (`FuzzCLIHostileServer`) |
| S28 | `internal/mcp/keyorix.go` | E17 | O (`KEYORIX_URL`) | no | scheme | refused | none needed |
| S29 | `migrate/internal/vaultsource`, `awssource`, `azuresource`, `gcpsource`, `healthscan`, `httpsafe`, `apiclient` | E18 | U (flags of the operator running the tool) | no | none: response-size cap (`httpsafe`) and redirect refusal only. A hostile source can be reached, by design, because the operator names it | refused (`httpsafe.RefuseRedirect`, vault `ErrUseLastResponse`) | `FuzzVaultSourceHostileWalk`, `FuzzAWSSourceHostileEndpoint` |
| S30 | `internal/netutil/*`, `internal/notifychan/secure_transport.go` | E19 | n/a | n/a | the guards themselves | n/a | `FuzzEgressDialEnforcement`, `FuzzIPv4EmbeddingSSRFParity` |
| S31 | `internal/storage`, `internal/auditverify`, `internal/serverguard`, `internal/solewriter`, `server/admin/restore*.go` | E01 | O | no | none: the operator's own database | n/a | none needed |

Nothing else in the allowlist opens a connection to a destination an attacker can choose.
The `DEV` rows are not shipped (see above).

### Intentional differences between the guard tiers

These are policy choices, each one deliberate and documented at the predicate in
`internal/netutil/dialer.go`. The new site-wiring targets and `internal/fuzzutil/egressref`
encode them, so a change to one of them fails a test instead of passing silently.

| Tier (predicate) | Used by | Refuses | Deliberately permits | Why |
|---|---|---|---|---|
| link-local (`IsLinkLocal`) | S09, S10, S11, S12 to S14, S18 | 169.254.0.0/16 and fe80::/10, and every embedded-IPv4 encoding of 169.254/16 (IPv4-mapped, NAT64 well-known and local-use, IPv4-compatible, 6to4, Teredo) | RFC-1918, loopback, CGNAT, IPv6 ULA (so also `fd00:ec2::254`, the AWS IPv6 metadata address), `192.0.0.192` (Oracle metadata), `100.100.100.200` (Alibaba metadata, inside CGNAT) | An on-prem or air-gapped IdP or Vault on 10.x or a ULA address is the primary deployment shape, and http on loopback is a supported dev shape. The IPv4 metadata address 169.254.169.254 is shared by AWS, GCP and Azure. The IPv6 and Oracle/Alibaba metadata addresses are a documented residual (`netutil/dialer.go`, `linkLocalCIDRs`) |
| private (`IsPrivateOrLinkLocal`) | S16, S21, S24 | the link-local tier, plus RFC-1918, 127.0.0.0/8, 0.0.0.0/8, CGNAT 100.64.0.0/10, ::1, fc00::/7, in every embedded encoding | public addresses, including NAT64 of a public IPv4 (the IPv6-only egress path) | The target is the deployment's backing infrastructure; there is no reason for it to be on the server's own network unless the operator sets the opt-out |
| webhook (`IsPrivateOrLinkLocalExceptLoopback`) | S01, S03, S05, S07 | the private tier | loopback (direct and embedded) | A receiver on the local host is a legitimate dev/test setup. A policy difference must never become an encoding or range gap |
| pinned endpoint | S08 | nothing by address | everything, but every dial goes to the IP resolved at construction | The operator names the endpoint, and private object stores are normal |
| allow-list | S26 | every server not in `--allowed-servers` | the listed servers only | The operator holds cluster-wide Secret read; a tenant must not be able to aim it |

### Findings

| ID | Site | Supplier | Finding | Severity | Where tracked |
|---|---|---|---|---|---|
| F1 | S22 `internal/dynamic/kubernetes.go` | P | The Kubernetes dynamic-secret engine built its HTTP client on a bare `http.Transport` and ignored `allow_private_network_targets`. The only check on the admin-supplied `api_server` was core's host check (re-run on every issue and revoke), which resolves the name separately from the transport's own lookup, so a hostname rebound between the two (DNS rebinding) reached a private address | fixed: dial-time guard on the explicit `api_server` | `TestKubernetesEngine_DialGuard`; closure `k8s-dynamic-dial-guard-001` |
| F2 | S10 `internal/core/sso.go` | H | The authorization-code exchange uses `http.DefaultClient`: the `token_endpoint` from the discovery document gets no host check (only `jwks_uri` does), no dial guard, and redirects are followed. The allowlist row said the client was built in `server/wire_sso.go`; that client serves the discovery GET only | low (needs a compromised IdP) | [#4738](https://github.com/keyorixhq/keyorix/issues/4738), fixed: the exchange runs on the discovery client (dial guard, redirects only to the same host:port without downgrade) and discovery refuses a token_endpoint off the issuer host unless listed in `token_endpoint_hosts` |

The three packages that on 2026-11-12 had HTTP clients and no netutil guard were checked:
`internal/rotation` (S18: since H1 it dials through a link-local guard and refuses
redirects; the URL is a compiled constant), `internal/delivery` (S02: an SMTP relay named by
the operator; no URL is attacker-influenced), and `migrate/internal/httpsafe` (S29: an
operator-run tool whose source endpoints are named by its user; redirect refusal and size
cap are the whole policy and that is by design). None is a finding. The copy-pasted
`netutil.Dialer{Disallow: netutil.IsLinkLocal}` construction at S09, S11 and S18 is now held
to one reference by the new targets instead of by three hand-copied table tests.

### What the new targets prove, and what they do not

`FuzzJWKSTransportEgressParity`, `FuzzOIDCDiscoveryTransportEgressParity`,
`FuzzSSOExchangeTransportEgressParity`,
`FuzzAzureGraphTransportEgressParity`, `FuzzConnect{Vault,Azure,AWS}TransportEgressParity` and
`FuzzAzureKMSTransportEgressParity` dial the site's real `DialContext` with one fuzzed
destination in ten encodings (raw, IPv4-mapped, NAT64 well-known and local-use,
IPv4-compatible, 6to4, Teredo, `fe80::` with a zone suffix, ULA including `fd00:ec2::254`,
public IPv6) and compare the guard's refusal with a reference computed from the octets in
`internal/fuzzutil/egressref`, with no call into netutil. The context is cancelled before the
dial, so no socket is opened: a refusal is read from the guard's own error, and an address
the guard lets through ends in a cancelled-context error. `FuzzAzureKMSResolverRebinding`
drives a hostname through a resolver stub that changes its answer after the first call and
checks that a mixed public/private answer set is refused whole and that the guard resolves
once per dial.

Red proof of every oracle is `internal/fuzzutil/egressref/egressref_test.go`: it runs the
same probes against a planted no-guard dialer, a stdlib-only classifier (the pre-#1937
encoding gap), a tier that over-blocks, a first-answer-only validator and a double
resolution, and fails unless each one turns the oracle red, while the real netutil predicates
stay green.

DNS rebinding at the link-local sites. None of S09, S11, S12 to S14 and S18 has a resolver
field on its `netutil.Dialer` (only S16 does, `azureKMSResolve`), so their rebinding targets
(`FuzzOIDCDiscoveryResolverRebinding`, `FuzzJWKSResolverRebinding`,
`FuzzConnect{Vault,Azure,AWS}ResolverRebinding`, `FuzzAzureGraphResolverRebinding`) go through
the one seam every one of them shares, the standard library's `net.DefaultResolver`:
`egressref.RebindDNS` installs a Go resolver whose connection is an in-process DNS server, so
the site's real `DialContext` resolves through the real stdlib resolver code. The server
answers the first A and AAAA lookup with a fuzzed pair of addresses (ten encodings each) and
every later lookup with 169.254.169.254. The oracle (`egressref.CheckRebind`) requires:

- the whole first answer set is refused when the link-local tier refuses any address in it
  (a mixed public/link-local answer), whatever the order;
- when the set is permitted (served as loopback, so the connect lands on a listener the
  oracle owns and nothing leaves the machine), the connection is to the validated address and
  never to the later answer;
- exactly one A and one AAAA query per dial, so no second lookup sits between validation and
  connect (zero would mean the stub is not in the path, and fails too).

What these targets do not verify: a real DNS server or network resolution, the cgo resolver,
`/etc/hosts` and search-domain handling (the name is rooted), a site configured with an egress
proxy, or over-blocking of a legitimate public address in the rebinding case (the set a
permitted pair is served as is loopback; the parity targets judge public addresses on
literals). The stub replaces a process-global variable, so these targets must not run in
parallel with a test that resolves names. S16 keeps its own seam-based
`FuzzAzureKMSResolverRebinding`, which drives a pre-cancelled context and therefore cannot
check where a permitted dial connects.

Red proof of the rebinding oracle is `TestOracleRebind` in
`internal/fuzzutil/egressref/egressref_test.go`: the real guard is green across the sweep, and
a planted no-guard dialer, a first-answer-only validator, a validate-once guard that redials by
hostname (second lookup, connection to the rebound address) and an over-blocking guard each turn
it red for their own reason.

Not covered: with an egress proxy configured the dial targets the proxy, not the destination
(accepted and documented at each site); the loopback-permitted tier sites (S01, S03, S05, S07)
are covered at the predicate level and by table tests, not by a transport-level fuzz target;
S22 is pinned by a table test (`TestKubernetesEngine_DialGuard`), not a transport-level fuzz target. S10 (the SSO code exchange) runs on the S09 client
and is driven by `FuzzSSOExchangeTransportEgressParity`; the rebinding target drives the shared
transport variable, not the exchange client itself.

## Needs coordinator

Nothing in the table is on by default and aimed at a third party, so there is nothing to
change. These are decisions or limits that are not mine to settle:

1. **Cloud SDK ambient credentials (E10, E11, E12, E13).** When one of these classes is
   configured, the AWS, Azure and GCP SDKs resolve credentials through their default chain,
   which can query the cloud host's instance-metadata service (a link-local address on
   the host's own cloud, not a third party). That is the SDK's behaviour and it only runs
   once the class is configured. Say so to a reviewer who asks; changing it would be a
   security-policy change.
2. **`DEV` rows are directory prefixes** (`scripts/`, `examples/`, `internal/testhelper/`
   and five `internal/testutil/` packages), so a new network client inside those
   directories is covered without a row. The import check proves they are not shipped,
   which is why this is allowed; narrow the prefixes if you would rather review each new
   tool. (The first draft also listed all of `internal/testutil/`; the check failed on it
   because shipped packages import its `srcpath` helper, so it was narrowed.) Looked at again
   with the subprocess guard (EGRESS-SUBPROCESS-GUARD-1) and left as is: 13 files in about 11
   tool directories under `scripts/` and `examples/` hold a network client, and a per-tool
   row set would also make every other `scripts/` file non-DEV, putting it under the
   DEV-import check and the subprocess table (about a dozen more rows for tools that are
   built by hand or by CI only). That is a review of the dev tools, not a small diff.
3. **Subprocess egress** (`key_provider.type: exec`, `keyorix run`): the call sites are
   listed and guarded (see "Subprocess call sites"); what the operator's or user's program
   does on the network cannot be, by construction.

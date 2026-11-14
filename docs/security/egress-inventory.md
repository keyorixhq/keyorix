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
| `tools/oraclehealth/runner.go` | `Env.goCmd` | EXEC-LOCAL-ONLY | `nice -n N go test` against a mutated working copy, for the fuzz-oracle mutation tool. Development tool, not a release artifact and not imported by shipped code | Fixed `nice`/`go`; the arguments are the tool's own subcommands and flags | Only through the Go toolchain's own module download, if the module cache is cold; no Keyorix code connects |
| `server/http/handlers/contracttest/exercising_tests_exist.go` | `realTestNames` | EXEC-LOCAL-ONLY | `go test -list` in the handlers package, for a test that checks test names. Test helper: not imported by any shipped package | Fixed arguments; the `go` binary is `runtime.GOROOT()` or the `go` found on `PATH` | Only through the Go toolchain's own module download, if the module cache is cold; no Keyorix code connects |

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

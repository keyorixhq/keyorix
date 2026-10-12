# Vault health scan

`keyorix-migrate vault scan` is a free, read-only health check for an existing Vault (or
OpenBao) install. It's the entry point for the "orphaned Vault" case: nobody's looked at the
whole install end to end in a while, and you want an honest read on what state it's actually in
before deciding what to do about it — migrate off it, fix it in place, or just know where you
stand. It's the same tool `keyorix-migrate vault` (the secret importer, see
[migrate-from-vault.md](migrate-from-vault.md)) ships in — same binary, same release, no
separate download.

This is **not** the paid Vault Health Assessment (a human-delivered engagement — see
<https://keyorix.com/vault-health>). It's the free, self-run version: one
command, a report, and a sense of what an expert would find.

## The read-only guarantee, and how it's enforced

**This tool never writes anything to Vault, and never reads a secret value — only metadata.**
Both are meant to be true by construction, not by review discipline, so it's safe to point at a
production Vault:

- `migrate/internal/healthscan/client.go`'s `Client` can issue exactly two HTTP methods against
  Vault: `GET` and `LIST`. Every other method — `POST`, `PUT`, `DELETE`, `PATCH`, anything — is
  rejected inside the client itself, before any request is built or any network call is
  attempted. `TestRequest_RejectsWriteMethods` proves this with a transport that fails the test
  outright if network I/O is ever attempted for a rejected method.
- Every check that touches a KV v2 secrets engine reads only its `/metadata` path (version
  number, `updated_time`, custom metadata) — never `/data` (the actual secret value).
  `TestRedaction_CanaryNeverAppearsInAnyOutputFormat` and
  `TestCheckSecretStaleness_NeverReadsDataPath` prove this against a fake server that plants a
  secret value at the corresponding `/data` path and fails the test if it's ever requested.
- `TestIntegration_FullScanAgainstRealServer` (CI-only, gated on `$VAULT_ADDR`) runs the entire
  scan against a real Vault and a real OpenBao container and independently counts every HTTP
  method that actually hit the wire — not trusting the client's own guard, observing real
  traffic.

One consequence of "GET/LIST only": the scan **cannot** identify which tokens hold Vault's root
policy. Doing that needs `POST auth/token/lookup-accessor` (Vault deliberately keeps the
accessor out of the URL for this one, so there's no GET-shaped equivalent). The report shows
this under "Not checked" rather than silently skipping it or, worse, weakening the read-only
guarantee to get it — it does show the *total* number of live token accessors, which is
available via `LIST`.

The one flag that's an explicit trade-off: `--tls-skip-verify` disables TLS certificate
verification. It's refused by default (no environment variable, only an explicit flag) and
always prints a loud warning to stderr when used — see `client.go`'s `Config.TLSSkipVerify` doc
comment for why this is the one deliberate divergence from `keyorix-migrate vault`'s own "no
skip-verify option, ever" policy.

## What it checks

Each check reports one of: a **finding** (id, severity, evidence, why it matters, and a concrete
remediation when there's something to fix), or **not checked** (the token's policy doesn't grant
the path — never a run failure).

| # | Check(s) | What it looks at |
|---|---|---|
| a | `version-eol`, `enterprise-license` | Version vs. this build's embedded version table (no network call to HashiCorp — see `versions.go`); license (BSL-1.1 vs MPL-2.0, by Vault's real 1.14 license change); OpenBao vs. Vault (by major version — OpenBao's fork started at 2.0.0); Enterprise detection via `sys/license/status`. |
| b | `seal` | Seal type (shamir vs. auto-unseal), recovery vs. unseal key shares/threshold, sealed status. |
| c | `ha-storage`, `raft-autopilot` | Storage type, HA/leader status, raft peer/voter count (single node flagged high), autopilot health. |
| d | `audit-devices` | Zero enabled = critical; one = medium (still a single point of failure); two+ = informational. |
| e | `token-accessor-count`, `root-tokens` | Total live token accessor count. `root-tokens` always reports "not checked" — see above. |
| f | `auth-methods`, `approle-secret-id-hygiene` | Enabled auth methods, userpass-only setups, OIDC presence; every AppRole role's `secret_id_ttl`/`secret_id_num_uses` for unlimited-lifetime or unlimited-use secret_ids. |
| g | `policy-sprawl`, `policy-wildcard-sudo` | Policy count; any policy granting `sudo`, or `create`+`update`, on `*` or `sys/*`. |
| h | `ttl-hygiene`, `lease-counts` | Default/max lease TTL of 0 or >768h on any mount or auth method; best-effort top-level lease counts per mount. |
| i | `secrets-engines-inventory`, `kv-v2-config`, `secret-staleness` | Engine inventory, KV v1 vs. v2, KV v2 `cas_required`, secrets not updated in over a year (from metadata only — see above). |
| j | `tls-listener` | `tls_disable`/`tls_min_version` from `sys/config/state/sanitized` — often sudo-only, expect this one to show up as "not checked" frequently. |
| k | `namespaces` | Vault Enterprise namespace inventory (informational-only on OSS/OpenBao). |
| l | `raft-auto-snapshot` | Automated raft snapshot config (Enterprise). When the API isn't visible at all (OSS, non-raft storage, OpenBao), this reports **"unknown, ask"** — deliberately distinct from "not applicable," since backups may exist through a mechanism this scan simply can't see through Vault's API. |
| — | `migration-readiness` | Not a risk check — see below. |

Every check that walks something unbounded (AppRole roles, ACL policies, KV secrets) is capped,
and a truncated result says so in its evidence — never a silent partial count.

## The policy

[`healthscan-policy.hcl`](../migrate/healthscan-policy.hcl) is the minimal read-only policy the
full check list needs — one stanza per check, commented with which check it enables. You don't
have to grant all of it: attach whatever subset you're comfortable with, and read the "Not
checked" section of the report for what a broader policy would additionally unlock.

```
vault policy write healthscan-readonly migrate/healthscan-policy.hcl
vault token create -policy=healthscan-readonly -ttl=1h
```

(Or mint an AppRole with this policy for a repeatable, non-interactive scan.)

## Running it

```
keyorix-migrate vault scan \
  --addr https://vault.example.com:8200 \
  --output ./report
```

Writes `report.md`, `report.json`, and `report.html`. Exit code is `0` unless the tool itself
failed (bad flags, no address, an auth failure) — a denied check never fails the run, it becomes
a "not checked" entry.

Auth: `--token`/`$VAULT_TOKEN`, or `--role-id`/`--secret-id` (AppRole, or
`$VAULT_ROLE_ID`/`$VAULT_SECRET_ID`). `--namespace`/`$VAULT_NAMESPACE` selects a Vault
Enterprise/OpenBao namespace. `--cacert`/`$VAULT_CACERT` (a PEM file) or
`--capath`/`$VAULT_CAPATH` (a directory of PEM files) trusts a private/internal CA. Credentials
passed directly on the command line warn to stderr — prefer the env var or a `--token-file`
(path, or `-` for stdin).

## The report

**Markdown** and **HTML** (single-file, inline CSS, no external assets, prints cleanly) are for
reading. Both contain: an executive summary (a 0–100 score, with the exact formula it was
computed from stated right next to it — see `score.go`'s `ScoreFormula`), the top 5
risk-weighted findings, a findings table, per-check detail, the "Not checked" list with the
policy line that would enable each, a "Migration readiness" section (below), and a neutral
footer naming the tool version. No marketing tone anywhere in a finding's own text.

**JSON** is for machines, with a `schema_version` field on the envelope (currently `3`) so a
consumer can tell which shape it's reading before parsing the rest.

### Sample excerpt (from a real, deliberately-misconfigured dev Vault)

```
# Vault Health Scan

keyorix-migrate 0.95.x against `http://vault.internal:8200`

## Executive summary

**Score: 9/100**

_Score = 100 - (25 x critical findings + 15 x high + 8 x medium + 3 x low), floored at 0. ..._

Top risks:

1. **[audit-devices] Audit devices** (critical) — no audit device enabled
2. **[tls-listener] TLS/listener configuration** (critical) — 1 listener(s); issues: [listener[0]: TLS disabled]
3. **[ha-storage] HA and storage topology** (high) — storage=inmem, ha_enabled=false, ...
4. **[seal] Seal configuration** (high) — seal type=shamir, unseal key shares: 1-of-1 threshold
5. **[ttl-hygiene] Token/lease TTL hygiene** (medium) — 5 mount(s)/auth method(s) with a 0 or >768h TTL: ...
```

### Migration readiness

A dedicated section (and its own `migration-readiness` finding, informational-only, never
scored) summarizing what [`keyorix-migrate vault`](migrate-from-vault.md) — the import command,
not this scan — can and can't bring into Keyorix today: KV v1/v2 mount counts, an approximate
top-level secret count, and which mounts it **cannot** import (dynamic-secrets engines like
`database`, `pki`, `aws` issue credentials on demand — there's no static value to migrate).

## Sharing the JSON with us

If you'd like a second opinion, or want to talk about the paid Vault Health Assessment, send us
`report.json` — it never contains a secret value, only findings, evidence text, and metadata
about your Vault's configuration. Use the form at <https://keyorix.com/vault-health>, which
also takes the file as an attachment.

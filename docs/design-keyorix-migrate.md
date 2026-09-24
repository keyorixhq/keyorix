# Design: `keyorix-migrate`

**Status:** Draft (2026-09-25). Implements the decision recorded in
`docs/cli-split-inventory.md` §PR5 ("`secret import --source {vault,aws,azure,gcp}`
is moved out, not dropped") and ADR-108. The old thin-CLI's `secret import` now
supports file mode only (`cli/cmd/secret_import.go`); the live-credential import
modes move here. The old monolithic CLI's Phase 5 deletion is gated on this tool
existing for at least the Vault source (customers' most common migration path —
an existing, often orphaned Vault install).

## Why a separate module and binary

ADR-108's thin CLI (`cli/`) carries no cloud SDKs in its SBOM — that is the whole
point of the split. A Vault/AWS/Azure/GCP importer needs exactly those SDKs (or,
for Vault, a hand-rolled HTTP client against its KV API — see "Vault client"
below). Bolting that onto `cli/` would reintroduce the dependency the split
removed. `keyorix-migrate` is therefore its own Go module (`migrate/go.mod`), its
own binary, built and SBOM'd separately — the same shape `cli/` and `operator/`
already use in this repo, one more sibling, not a new pattern.

## Module boundaries (compiler-enforced, per `cli/`'s precedent)

- `migrate/go.mod` has **no `replace` directive to `../`** and does not depend on
  the root module at all — unlike `cli/`, which the split explicitly kept
  standalone from the main module too (ADR-108 Decision A). `migrate` is
  stricter than even that: it doesn't need `internal/apiclient`'s generator
  tooling to *run* from the main module, only to *generate* its own copy (see
  below).
- `migrate` must not import `internal/core`, `internal/storage`, or anything
  under `internal/` — a `depguard`-style test (`migrate/internal/depguard_test.go`,
  mirroring `cli/`'s own boundary guard) fails the build if it ever does. This
  is the same "ceiling checked against the actor, not asserted in a comment"
  discipline the rest of this repo uses for security boundaries — here the
  boundary is architectural, not authz, but the mechanism (a test that inspects
  the actual import graph, not a doc comment) is the same idea.
- It talks to Keyorix **only** through the public REST API, authenticated with a
  Personal Access Token (`--token` / `$KEYORIX_TOKEN`), exactly like `cli/`'s
  `Authorization: Bearer` pattern (`cli/cmd/client.go:newAPIClient`). It never
  opens the database directly — there is no local/embedded mode, matching
  ADR-108's Decision A for the thin CLI (this tool is even further from the
  server than `cli/` is: it has no server-side counterpart at all).
- Reads from the source (Vault, later AWS/Azure/GCP) use that source's own SDK
  or HTTP API. Nothing about the source read path touches Keyorix's storage
  layer.

## Generated API client

Reuses `cli/`'s exact approach (`cli/Makefile`'s `client` target,
`cli/internal/apiclient/gen/filterspec.go`): `oapi-codegen` against a filtered
copy of `server/http/handlers/openapi.yaml`, containing only the paths this tool
needs. `migrate` generates its **own** copy
(`migrate/internal/apiclient/{types,client}.gen.go`) via its own filterspec
program and its own `Makefile` target — it does not import `cli/internal/apiclient`
(that would violate "no dependency on `cli/` or the main module" just as much as
importing `internal/core` would; `cli/` is not a dependency-safe leaf either,
since it itself is a full sibling module with its own release cadence).

Initial `keptPaths` for `migrate`:

```
/api/v1/version                              # skew check, same method as cli/
/api/v1/projects
/api/v1/projects/{id}/environments
/api/v1/secrets
/api/v1/secrets/{id}
/api/v1/secrets/by-name
```

`CreateSecretJSONBody` already carries a `Metadata map[string]string` field
(`secrets_crud.go:88`, accepted since #1808) that is stored on `SecretNode.Metadata`
and round-trips back out through `GetSecret` (which serializes the full
`*models.SecretNode`, unlike the narrower `Secret`/`SecretGetResult` response
schemas `cli/`'s filtered spec documents — a real gap in the documented response
shape, not a missing feature; see "Idempotency" below for how this tool reads it
back without waiting on that schema fix). `migrate` decodes it via a local raw-JSON
DTO, matching the `decodeData[T]` fallback convention `cli/cmd/client.go` already
established for exactly this class of gap — not a new pattern.

## Source-to-Keyorix mapping (dry-run plan)

Every run builds a **mapping plan** before touching anything:

| Source | Keyorix |
|---|---|
| Vault path (e.g. `secret/data/team-a/db-password`) | `--project`/`--environment` (required flags, numeric IDs — matching `cli/`'s PR5 convention of taking scope by ID, not by name) + a deterministic secret name derived from the path's last segment(s), sanitized the same way the old CLI's `sanitizeSecretName` did |
| Vault KV field(s) | one secret per field when the leaf has more than one field (`<path>-<field>`), one secret named after the path when it has a single `value` field — same shape `cli/cmd/secret/source_vault.go`'s `readLeaf` already uses, ported rather than redesigned |
| Vault custom-metadata / KV v2 metadata | Keyorix `metadata` map, prefixed `vault.` to avoid colliding with this tool's own bookkeeping key (see Idempotency) |

The plan is a report, not an action: for every candidate it states `create`,
`update` (idempotent match, value differs), `skip` (idempotent match, value
identical), or `conflict` (a secret already exists at the target name whose
stored source-id metadata does not match this run's source, or is absent —
i.e., a name collision with something migrate didn't create). Nothing is
written to Keyorix until `--apply` is passed. `--apply` re-derives and re-checks
the plan immediately before executing each item (not trusting a plan computed
and shown seconds or minutes earlier) — the source or the target could have
changed in between.

## Idempotency

Every secret `keyorix-migrate` creates gets a stable **source-id** written to
its `metadata` map at creation time:

```
metadata["migrate.source"]    = "vault"
metadata["migrate.source-id"] = sha256("<vault addr>|<mount>|<kv-version>|<full path>|<field, if exploded>")
```

A re-run looks up the deterministic target name via `GET /secrets/by-name`
(scoped to `--project`/`--environment`, same call `cli/`'s `secret get --name`
uses), and if found, reads `migrate.source-id` back via `GET /secrets/{id}`
(the full `SecretNode` JSON — see "Generated API client" above). Three
outcomes:

1. **No existing secret** → plan says `create`.
2. **Existing secret, source-id matches** → this tool made it on a prior run.
   Compare values (an extra unauthenticated-to-report bit is not implied — this
   tool has to read the source and target values anyway to import/compare
   them, and neither can be logged, see "Never log secret values" below): `skip`
   if identical, `update` if the source changed.
3. **Existing secret, source-id missing or different** → a name collision with
   something this tool did not create (hand-created secret, a different
   source's migration, a stale/renamed source path reusing an old name).
   Plan says `conflict` and the item is never written without `--force`
   (a separate, explicit flag from `--apply`, required in addition to it) —
   the default is to stop and let the operator resolve the collision by
   renaming one side, matching this repo's "fail closed and loud, never
   silently merge" convention for exactly this class of collision (see
   `docs/normalization-boundary-design-1642.md`'s "backfill fails on collision,
   never merges" precedent, memory `[[normalization-boundary-design-1642]]`).

The name-based lookup is the primary key (cheap: one `by-name` call per item,
no full-project listing); the source-id in metadata is the correctness check
that turns an accidental name collision into a loud `conflict` instead of a
silent overwrite or a silent duplicate.

## Never log, print, or report a secret value

The per-item result report (JSON + human-readable, one line per source item) —
consistent with this repo's "assert the effect, not the return value" testing
discipline (`CLAUDE.md`'s "To test a fails-open path" entry) — carries: source
path, target project/environment/name, outcome (`created`/`updated`/`skipped`/
`conflict`/`error`), and on error, the error message. It never carries a
`value` field, a diff of values, or an error message interpolated from a value
(a Vault or Keyorix API error message could echo back part of a payload in
some failure modes — errors from both clients are sanitized to strip anything
that looks like it echoes request/response body content before it reaches the
report). The canary-value test (Step 2) plants a known marker value and greps
every byte this tool writes to stdout, stderr, and the JSON report for it.

## Resume

`--apply` writes each item's outcome to the JSON report incrementally (flushed
per item, not buffered to the end) so a killed-mid-run process leaves a
truncated-but-valid-prefix report. A re-run with the same source/target flags
recomputes the plan fresh (per-item `by-name` + source-id check, as above) —
already-created items resolve to `skip` (or `update`, if the source changed
since), so a resume is just an ordinary re-run, not a special mode. There is no
separate "resume from report" flag; the idempotency check already makes every
run resumable by construction. This is deliberate: a special-cased resume path
would be a second, less-exercised code path to keep correct, when the ordinary
path already has to be correct for every subsequent run anyway (this repo's
"a mechanism must be validated against a failure that actually happened"
principle applied narrowly — the realistic failure here is "process killed
mid-run," which the ordinary idempotency path already has to survive).

## Auth: token and AppRole (Vault), namespaces

- **Token auth**: `--vault-token` / `$VAULT_TOKEN`, same as the old CLI's
  `source_vault.go`.
- **AppRole auth**: `--vault-role-id`/`--vault-secret-id` (or their `$VAULT_ROLE_ID`/
  `$VAULT_SECRET_ID` env equivalents) exchanged for a token via
  `POST {addr}/v1/auth/approle/login` at startup; the resulting client token is
  used for all subsequent KV calls exactly like a directly-supplied token. Not
  ported from anywhere in this repo (the existing `source_vault.go` and
  `connect/vault.go` are both token-only) — new code, small surface (one POST,
  one field extracted from the response).
- **Namespace** (Vault Enterprise / OpenBao): `--vault-namespace` /
  `$VAULT_NAMESPACE`, sent as the `X-Vault-Namespace` header on every request
  (KV and AppRole login alike) — Vault's own documented mechanism, nothing
  bespoke.

## Vault client: ported, not reused directly

`migrate` cannot import `cli/cmd`'s `source_vault.go` (unexported, and `cli/`
is not a dependency-safe leaf per the module-boundary rule above) or
`internal/connect/vault.go` (inside the forbidden `internal/` tree). Both are
read *once per call* and single-path; `migrate` needs recursive-tree KV walk
plus AppRole/namespace, which neither existing implementation has. The design
carries forward the parts worth keeping without copy-pasting blindly:

- `internal/connect/vault.go`'s `resolveKVMountVersion` (query
  `sys/internal/ui/mounts/<path>` rather than sniff response shape) is the
  correct way to distinguish KV v1/v2 — ported over `source_vault.go`'s
  `--vault-kv-version` flag-driven approach, since `keyorix-migrate` walks
  whatever mounts a customer's real Vault has and should not require the
  operator to already know each mount's KV version up front.
- `source_vault.go`'s recursive `walk`/`list`/`readLeaf` shape (LIST to find
  children, recurse into `/`-suffixed keys, read leaves) is the right
  traversal and is ported directly — this is exactly the "recursive paths"
  requirement.
- Both existing clients' redirect-refusal (`CheckRedirect: http.ErrUseLastResponse`
  — an X-Vault-Token-carrying redirect must never be followed to an
  attacker-controlled host) and response-size caps are carried forward
  unchanged; there is no reason to weaken either for this tool.
- "All versions or latest only" (a new requirement neither existing client
  has): KV v2's `/metadata/<path>` response lists all version numbers: with
  `--all-versions`, `migrate` reads each numbered version
  (`/data/<path>?version=N`) and imports it as a distinct Keyorix secret
  version via `POST /secrets/{id}/versions`... **open question**, see below.

## Open questions for follow-up (flagging, not deciding unilaterally)

1. **"All versions" target shape.** Keyorix secrets are versioned already
   (`SecretVersion`), so importing "all versions" most naturally maps to
   creating the Keyorix secret at its oldest Vault version and then adding a
   new Keyorix version per subsequent Vault version, in order — but the
   `by-name`/create/update API surface `migrate` is scoped to (see `keptPaths`
   above) does not include a "create version" route yet. Needs either scope
   creep into that route for Step 2, or `--all-versions` deferred to a
   follow-up once versioned-import is designed. Recommend deferring —
   "latest only" (the default) covers the primary migration case (get off
   Vault), and versioned import can be scoped properly once there's a real
   customer ask for it.
2. **PAT provisioning UX.** `cli/` already has `pat.go` (`keyorix pat create`)
   for minting a token; `keyorix-migrate` assumes the operator already has one
   in hand (`--token`/`$KEYORIX_TOKEN`), matching `cli/`'s own precedent of not
   auto-provisioning credentials. No new decision needed here, just confirming
   the assumption explicitly.

## Testing (Step 2, Vault)

- **CI integration test**: `docker run hashicorp/vault:<pinned> server -dev` (or
  OpenBao's dev-mode equivalent) alongside a real `keyorix-server` backed by
  SQLite (matching this repo's existing `pg-gated`/`default-ci` split in
  `docs/security-closures.tsv` — this test is `default-ci`, no external DSN
  needed, both dependencies are containers CI already knows how to run).
  Seeds Vault with a small KV v1 and a KV v2 tree (nested paths, multi-field
  leaves, one soft-deleted version to confirm it's skipped not mistaken for
  live data — the same `{"data": null}` shape `connect/vault.go`'s doc comment
  already documents as a footgun), runs `keyorix-migrate --source vault --apply`,
  and asserts the resulting Keyorix secrets and their `migrate.source-id`
  metadata.
- **Canary-value test**: plant one Vault secret with a distinctive, greppable
  value; assert it appears nowhere in this tool's stdout, stderr, or JSON
  report (only in the actual Keyorix secret value, fetched back via the API
  to confirm the import worked) — see "Never log, print, or report a secret
  value" above.
- **Resume test**: run `--apply` against a multi-item source, kill the process
  partway (a context-cancellation point injected for the test, not a real
  `SIGKILL` race — deterministic, not timing-dependent), re-run `--apply`
  to completion, and assert the final Keyorix secret count matches the source
  item count exactly (no duplicates from the interrupted first pass, per the
  idempotency design above).

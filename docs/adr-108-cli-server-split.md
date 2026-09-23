# ADR-108: Split Keyorix into a thin network CLI and a server with offline `admin` subcommands

**Status:** Accepted (Andrei, 2026-09-23). It gets the next repo ADR number when committed to `docs/`. It builds on ADR-083 (remote storage is a client mode only) and ADR-107 (CLI over the human-facing API, Proposed). **Companion ADR:** server-side decoupling of `internal/core` from connectors and backends is a separate decision in `ADR-109 (`docs/adr-109-core-depends-on-interfaces.md`)`. It is not a prerequisite for this ADR, and this ADR is not a prerequisite for it. Both are sequenced in (Keyorix planning notes, claude/2026-09-23-refactor-program-plan-cli-server-split.md).

## Context (measured 2026-09-23 on main)

| Binary | Size | Links `internal/core` | Cloud-SDK packages linked |
|---|---|---|---|
| `keyorix` (CLI, repo root `main`) | 65 MB | yes | 90 |
| `server` | 97 MB | yes | 99 |
| `keyorix-mcp`, `keyorix-k8s-sync` | small | no | 0 |

- The CLI embeds the whole server stack: core, storage, and every AWS/Azure/GCP SDK. 45 CLI files import core. It works in two modes:
  - **local:** it opens the SQLite DB itself, which makes it a second server that bypasses the API's authorization, audit and rate limits;
  - **remote:** it calls `RemoteStorage`, which uses the `/system` storage-proxy tier on the server.
- The `/system` proxy tier has to re-implement the authorization of each human-facing route. It is where the 2026-09-21/23 authority findings came from (11 proxy routes, F5/F6). Per ADR-102, `system.write` reaches 148 routes.
- Coupling finding (already fixed by #2004): `internal/config` imported `internal/connect` only for the list of connector type names, which pulled every cloud SDK into config, into i18n, and into everything that translates an error. The list is now in a leaf package, and a guard test keeps it that way. The CLI still links core directly, and core imports the connectors, so the client stays heavy until this split.

## Decision (proposed)

**A. Thin network CLI (`keyorix`).**
- It lives in its own Go module (its own `go.mod`), so it cannot import core, storage, `internal/config` server code or any SDK. The compiler enforces the boundary.
- It talks to the server only through the public REST API (or gRPC). Its request and response types are generated from the OpenAPI/proto definitions (ADR-106).
- It has no local database mode.

**B. `keyorix-server admin …` subcommands for operations that must not, or cannot, go through the network API.** These need shell access on the server host plus the DB and key files; owning the host is the authority.
1. Server cannot start: migration failure, broken config, KEK unavailable, crash-corrupted DB. Covers diagnose, repair and migrate.
2. Everyone locked out: recover an admin account (lost password or MFA, last admin deactivated). This must never be a network endpoint, because that would be a built-in auth bypass. Every use is written to the audit chain, and the command prints what it did.
3. Operations that need the database to themselves: consistent offline backup and restore, version-skipping upgrades (air-gapped customers), the SQLite → PostgreSQL move, a full KEK re-encryption sweep.
4. Independent audit verification: check the tamper-evident audit chain from the DB file, without trusting the running server. This is a compliance deliverable for regulated customers.

These are subcommands of the server binary rather than a third binary, because the server binary already links core and storage. Keycloak's `kc.sh export/import` and GitLab's host-side rake tasks use the same pattern.

**C. Remove the `/system` storage-proxy tier and `RemoteStorage`** once nothing calls them. This is ADR-083's deferred work and ADR-107's goal. It also settles most of ADR-102's `system.write` question by removing the surface.

**Out of scope:** server-side decoupling (core depending on interfaces instead of connector SDKs, lean build tags). That is the companion ADR. This ADR removes the SDKs from the *client*; the companion ADR removes them from builds of the *server* that don't need them.

## Why

- **Security:** it removes the proxy tier, a whole bug class and a large authorization surface. The CLI cannot bypass the API. Break-glass needs host access and is audited.
- **Air-gapped and regulated environments:**
  - offline backup, restore, upgrade and recovery without a running API;
  - offline audit-chain verification for auditors;
  - a smaller client to ship and certify, with an SBOM that lists no cloud SDKs.
- **Size:** CLI from 65 MB to an estimated 10–15 MB (not measured). Server size is the companion ADR's concern.
- **Maintainability and fuzzing:** the local-vs-remote conformance suites, the `/system` handlers and the parity fuzzers that exist only because of them all go away. The CLI's request/response parsing becomes a small, fast fuzz target.

## Consequences and risks

- **Breaking change:** "CLI opens the DB directly" is removed, and those operations move to `keyorix-server admin`. Acceptable at prototype stage; release notes and migration docs are needed.
- **API gaps:** any CLI command with no REST equivalent needs one first. The inventory decides the order.
- **Two modules in one repo:** CI must build and test both, and version skew between CLI and server needs a compatibility rule (the CLI checks the server's API version and warns or refuses).

## Order of work (separate PRs, one program)

1. Inventory: every CLI command → the REST route it would call, the gaps, and the operations for B.
2. New CLI module with a dependency guard in CI. Move commands group by group: secrets, projects, users, then the rest.
3. `keyorix-server admin` subcommands for B1–B4. Each gets its own tests; recover-admin gets an adversarial review.
4. Delete the `/system` proxy tier and `RemoteStorage`, plus their tests and parity fuzzers. Update the ledger and closures.
5. Then the companion decoupling ADR (see the program plan).

## Decisions on the open questions (Andrei, 2026-09-23)

1. **Transport: REST only for the CLI.** The human-facing REST API carries the full authorization model, audit and rate limiting. One transport means one test surface and no CLI-level REST↔gRPC parity problem, and plain HTTPS works through enterprise proxies and TLS inspection. gRPC stays for machine clients (SDKs, k8s-sync, services). The CLI's client is generated from the canonical API definition (ADR-106), so it cannot drift.
2. **recover-admin requires a recovery key by default.**
   - Generated at install and shown once. Split M-of-N (Shamir) is a later enterprise option.
   - Every use writes to the audit chain and notifies all admins.
   - A keyless host-only mode exists only when explicitly configured, for labs and demos.
   - Rationale: separation of duties. Host root should not automatically become Keyorix admin (an insider-threat control for NIS2/DORA). This matters most when the KEK is in a KMS or HSM; if the KEK file sits on the host, root already has everything, and the docs say so plainly.
3. **CLI/server version skew is tiered.** The server advertises its API version and a minimum supported CLI version.
   - Same major version: allowed. An older CLI warns ("upgrade available"). A newer CLI calling an endpoint the server doesn't have gets a clear "server too old for this command" error, not a 404.
   - Different major version, or a CLI below the server's minimum: refused. The minimum lets us force upgrades after a CLI-side security fix.

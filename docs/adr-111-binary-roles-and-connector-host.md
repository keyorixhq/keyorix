# ADR-111: Binary roles and an out-of-process connector host

## Status

**Proposed** (2026-10-02).

Builds on ADR-109 (core depends only on interfaces; `full` and `air-gapped` build profiles) and ADR-108 (CLI/server split, `keyorix-server admin`). Sequenced after ADR-109's steps 1–6: its interfaces are this ADR's process boundary.

## Context

What ships today (main, 2026-10-02):

| Binary | Role | Runs where |
|---|---|---|
| `keyorix-server` | The daemon: API (REST + gRPC), storage, crypto, audit chain | Host |
| `keyorix-server admin …` | Offline host-side operations with no running server: `init`, `validate`, `diagnose`, `backup`/`restore`, `encryption` (KEK rotation), `recover-admin`, `recovery-key`, `audit verify`, `migrate` | Host, local operator only |
| `keyorix` (CLI, own module) | Thin remote client of the server API | Anywhere |
| `keyorix-migrate` | Import from Vault | Operator machine |
| `keyorix-mcp` | MCP server for AI assistants (API client) | Anywhere |
| `keyorix-k8s-sync` | Kubernetes secret sync (API client) | Cluster |

The full server profile still links every cloud SDK in-process (97 MB binary, 99 cloud-SDK packages, measured 2026-09-23 for ADR-109). As connectors grow, that costs:
- **Memory:** Go runs every linked package's initialization at startup, so unused SDKs still allocate heap. Vault (50 MB idle, 522 MB installed) shows where this ends; Keyorix is 16 MB idle today.
- **Attack surface and SBOM:** every SDK is in-process with the master key, and every SDK CVE shows up as "affected" in customer scanners.
- **Certification:** schemes like Common Criteria, LINCE/CPSTIC and FIPS 140-3 evaluate one defined configuration. Every binary or component that handles secrets is inside that boundary.

Go's `plugin` package is not an option: no Windows support, exact toolchain and dependency match required, no unloading.

## Decision (proposed)

1. **Binary roles are fixed as in the table above, plus one new binary.** Offline administration stays inside `keyorix-server admin`, not a separate binary: it shares the exact storage and crypto code of the server it repairs, so there is no version skew and no extra artifact to sign or certify.

2. **New `keyorix-connectors` binary: the connector host.** It contains every external-system integration that today needs a cloud or vendor SDK (connect, rotation, dynamic backends and KMS providers where they need SDKs). `keyorix-server` links none of them in any profile.
   - The server starts the host **on first use** of any connector, never at boot. Deployments with no connectors never start it; the air-gapped edition never ships it.
   - Transport: the server's **stdin/stdout pipes** to its child process, not a socket, so no other process can connect. The protocol implements ADR-109's interfaces (`ConnectorResolver`, `RotationExecutor`, `DynamicBackendFactory`, KMS provider).

3. **Security rules for the host:**
   - **Verified before exec:** the server checks the host's Ed25519 signature (same key and cosign flow as releases) and an exact version match, and refuses to start it otherwise (fail closed).
   - **Least privilege:** the host gets no database access, no key files and no master key. It receives only the secret material needed for the single call it is serving, and it never does Keyorix's own encryption.
   - **Audited lifecycle:** host start, stop, crash, restart and verification failures are audit events.
   - **Containment:** a host crash degrades only the connector operation that was running (it returns an error and the server restarts the host on the next call). It never affects the secrets service. Restart backoff is bounded.

4. **Connector rule: plain HTTPS first.** A new connector calls the external API directly (most need 3–5 calls) with a small request-signing helper. A full vendor SDK needs a written justification in the PR. This keeps the host's own startup memory small, because everything linked into one binary initializes together.

5. **Certification boundary:** the certified configuration is `keyorix-server` in the air-gapped profile: one binary, with the crypto boundary entirely inside it. The connector host is outside the evaluated configuration unless separately evaluated later.

6. **Guards:**
   - Extend `airgap-dependency-guard.sh` so `keyorix-server` links no cloud or vendor SDK in **any** profile, not just air-gapped.
   - A CI budget for `keyorix-server` binary size and idle memory, failing on more than about +10% without a reviewed reason. This is a `.github` change, so it needs Andrei's approval.
   - Tests: the host is not started at boot; an invalid signature or mismatched version is refused; a host crash returns an error, the next call restarts it, and both are audited; the host process has no DB or key-file access.

7. **Host connector allowlist: default deny, by type and destination.** Which external systems a server may talk to is decided by whoever runs the host, in the server's config file (`keyorix.yaml`, or Helm values), never through the API. Keyorix admins configure connectors through the API or UI, but only within that allowlist. This is a two-person control: a compromised admin account cannot point a connector at an attacker's endpoint and stream secrets out.

   ```yaml
   connectors:
     allowed:                      # default: empty = no connectors, host never starts
       - type: vault
         endpoints: ["https://vault.corp.example:8200"]
       - type: aws-secrets-manager
         regions: ["eu-west-1"]
     idle_shutdown: 10m
   ```

   - **Default deny:** an empty or missing list means no connectors and the connector host never starts. This is the default for air-gapped and OT deployments.
   - **Type and destination:** each entry names the connector type and the endpoints or regions it may reach. A connector configured through the API with any other type or destination is rejected, and the rejection is audited.
   - **Enforced twice:** the server refuses the call, and the host only initializes allowed connector types (the server passes the allowlist when it starts the host). A bug in one layer alone doesn't open it.
   - **Changes need host access:** edit the file, then restart or reload. The server records an audit event with the old and new list. No API endpoint can change the allowlist.
   - **Visible:** the API and admin UI show which connector types and destinations this server allows, so a greyed-out connector is explained rather than mysterious.
   - **Fleets:** for many servers, the allowlist is managed by the customer's config management (Ansible, Helm values), the same way as firewall rules.
   - **Tests:** an empty list never starts the host; a disallowed type and a disallowed destination are both rejected and audited; the host refuses to initialize a type not passed in its allowlist; an allowlist change produces an audit event with the diff.

## Consequences

- The certified unit and the full product share one server binary; editions differ only in whether the connector host ships.
- Server memory and binary size stay flat as connectors are added; the cost moves to an optional process.
- Every secret crossing the pipe is a new boundary to test (fuzz the protocol decoder on both sides).
- One more artifact to sign, scan and SBOM, but only one regardless of how many connectors exist.
- Latency: the first connector call after start pays the host's startup cost (expected well under a second); later calls pay one local pipe round-trip.

## Open questions

1. **Which integrations move:** do database rotation and dynamic-secret drivers (Postgres, MySQL) move to the host too, or stay in-process because they're light and widely used? Proposal: decide per integration by measured size and startup-memory cost.
2. **Wire format:** gRPC over the pipes (reuses existing tooling) or simple length-prefixed protobuf (smaller). Proposal: length-prefixed protobuf.
3. **`keyorix-k8s-sync`:** stays a separate API client. It is not a connector the server calls, so it doesn't belong in the host.
4. **Idle shutdown:** should the host exit after N minutes without calls? Proposal: yes, with a configurable timeout.

## Definition of done

- `go list -deps ./server` in every profile contains no cloud or vendor SDK.
- `keyorix-connectors` ships signed with its own SBOM in the full profile only.
- The host connector allowlist is enforced in both server and host, defaults to empty, and is documented in the deployment guide and Helm chart.
- Server binary size and idle memory before and after are published in the program plan, with the CI budget in place.

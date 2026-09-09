# ADR-104: gRPC scope — a partial data-plane surface, with parity as a planned project

## Status

**Partially accepted.** Two different things are recorded here and they have
different standing.

**Accepted (owner decision, 2026-09-09):** gRPC is today a partial, data-plane
interface; HTTP is the complete one; that fact will be stated in the config
template, the API reference, and the proto rather than left undocumented; and
capability parity with HTTP is the intended long-term direction.

**Proposed, not ratified:** everything in "Scope" and "Phasing" below — the
three-state ledger, the CI gate, the deliberate HTTP-only exclusions, and the
phase ordering. These are a design for the parity project, not authorization to
build it. No RPC in this document is approved for implementation.

This ADR authorizes only the documentation and field-number reservations that
ship with it.

## Context

An audit on 2026-09-09 compared the two transports:

- gRPC: **13 services, 86 RPCs** (`server/proto/keyorix.proto`)
- HTTP: **151 handler files**, covering everything gRPC does plus roughly two
  dozen capability areas gRPC has no equivalent for.

The audit was prompted by a single finding — `CreateSecretRequest` has no
`description` or `classification` field — which turned out not to be a special
case but one instance of a systematic pattern.

### What is not wrong

Enforcement is transport-agnostic. Traced end to end:

```
gRPC GetSecretValue                         server/grpc/services/secret_service.go:152
  -> core.GetSecretValueWithPermissionCheck   internal/core/versions.go:233
    -> getSecretValueForUser                  internal/core/versions.go:243
      -> enforceSecretReadGuards              internal/core/versions.go:175
        -> checkRestrictedSecretReadApproval  internal/core/versions.go:203
```

The gate is implemented in **core**, not in the HTTP handler layer, so every
transport inherits it. Reading a `restricted` secret over gRPC with
`RestrictedRequiresMFAStepUp` enabled is denied, and because gRPC has no
step-up RPC, a gRPC client cannot read restricted secrets at all. That is
fail-closed. The same holds for the other read guards on that path: expiry,
suspension, and access schedule.

**gRPC cannot bypass a control that HTTP enforces.**

### What is wrong

Objects *created* over gRPC land in the least-governed state available, and
nothing tells the operator that the transport they enabled cannot express the
controls their compliance posture assumes. The config template said only
"Enable gRPC server", which implies parity, because that is what enabling a
second protocol normally means.

The risk is **silent under-configuration**, not bypass.

### Why a mechanism is needed, not a fix

This class of defect has now been found twice, both times by accident:

1. `server/grpc/services/secret_service.go:166` carries the comment from a
   previous fix: *"Without it, a secret read over gRPC left no `secret.read`
   event and no access-log row, so the anomaly detector never saw it: secrets
   could be exfiltrated over gRPC invisibly to both the audit trail and anomaly
   detection."*
2. `classification` / `description` on `CreateSecretRequest`, found a year later
   in a different subsystem by a different session.

Same shape each time: HTTP grew a control, gRPC did not, nobody noticed. Adding
RPCs without a detection mechanism produces the next gap on the next feature.

## Decision

### 1. Say what gRPC is (this ADR's shipped change)

State the partial status where an operator or integrator will actually hit it:
`configs/keyorix.yaml.tpl`, `docs/API_REFERENCE.md`, `docs/CONFIGURATION.md`,
`docs/README.md`, and the header of `server/proto/keyorix.proto`. An
undocumented gap and a documented limitation are different answers in a security
questionnaire, independent of when any code lands.

### 2. Reserve the field numbers now (this ADR's shipped change)

`CreateSecretRequest` reserves `11 to 20`, earmarked `11 = description`,
`12 = classification`. Protobuf field numbers can never be reused; reserving is
free today and impossible to retrofit once a number is spent by unrelated work.

### 3. Parity is the goal — but "identical to HTTP" is the wrong target

Some HTTP endpoints should never have a gRPC twin, and a parity project that
does not say so up front can never reach a green state, which means its ledger
gets ignored, which means the gate is gone. Deliberate exclusions, with reasons
that survive an auditor's question:

| capability | why gRPC must not have it |
|---|---|
| SCIM, SCIM groups | SCIM *is* a REST standard (RFC 7644). Identity providers speak it over HTTP; a gRPC SCIM would be non-conformant by construction. |
| SAML / SSO / OIDC callbacks | Browser redirect flows. There is no client-side actor to hold a gRPC connection. |
| WebAuthn | The ceremony runs in `navigator.credentials`. A native gRPC client cannot perform it. |
| Sessions, cookies | A browser concept. |
| CSV export downloads | A browser download shape. The underlying query should be an RPC; the file need not be. |

### 4. The open design question that gates everything else

**MFA step-up has no machine-appropriate translation.** Its absence is currently
what makes gRPC fail-closed on `restricted` secrets. But "prompt the user for a
TOTP" is not a coherent primitive for a workload identity, so porting it
literally would produce something worse than the present gap — a second factor
that is not a second factor.

The right question is *what is the second factor for a machine?* The likely
answer is an approval or dual-control grant, a primitive this codebase already
has in break-glass (already exposed over gRPC). This interacts directly with
`adr-039` HA dual-control work; it wants one design, not two.

**This must be decided before phase 1**, because the answer determines whether
`restricted` is reachable over gRPC at all — a product statement, not an
implementation detail.

### 5. Before any RPC: a parity ledger and a CI gate

Derive both surfaces mechanically — HTTP routes from router registration, RPCs
from compiled descriptors via `protoreflect` (**not** by grepping `.proto`
text) — and emit a checked-in artefact with one row per HTTP capability in
exactly one of three states:

| state | meaning | requires |
|---|---|---|
| `parity` | a gRPC RPC covers it | the RPC name |
| `planned` | parity intended, not built | a phase number |
| `http-only` | deliberately never gRPC | **a written reason** |

**The test fails on any HTTP route matching no row.** A new route therefore
cannot be added silently: its author must classify it at the moment they have
the context to do so. That is the whole mechanism, and it is cheap.

A hand-maintained parity checklist in a markdown file is stale the week after it
is written, and its staleness is invisible. See
`adr-103`-adjacent guidance and the remote-proxy conformance work for the
general form of this rule: *the residue must be reported by the harness, never
enumerated by hand.*

### 6. Verification design: differential, not static

Static shape analysis will not catch this defect class, and we have measured
that rather than assumed it. In the RemoteStorage proxy conformance campaign,
four static checks — each red/green-validated and mutation-kill-confirmed —
caught **zero of nine** real historical defects, and one of them actively
*certified* a genuine bug as correct.

What catches it: run the same operation over both transports against the same
core, then compare **the resulting database state and the emitted audit
events**. That is precisely the shape of the `:166` defect — identical returned
value, missing audit row — and no source-shape check can see it.

Start with the RPCs that already claim parity. If the harness finds nothing, that
is either a clean surface or a weak harness, and the way to tell is a planted
mutation.

**CI budget.** Keyorix CI is currently 13.5m wall clock with a ~10.5m ceiling
tier. A differential harness must run on every PR or it is decorative, so it has
to be sized against that ceiling deliberately. Table-driven comparison over a
shared in-process core should be cheap; that must be verified, not assumed.

## Phasing

| phase | content | gate |
|---|---|---|
| **0** | This ADR. Documentation + field-number reservations. | — |
| **1** | Make a gRPC-created object governable: `description`, `classification`, a `ClassifySecret` RPC mirroring the existing `ClassifyMachineIdentity`/`ClassifyMachineToken`/`ClassifyConfig`, folder CRUD, ownership, access schedule, retention override. | §4 decided; §5 ledger + gate in place |
| **2** | Lifecycle and operations: templates, rotation policy writes, bulk operations, version comments/diff, expiring/extend, suspend. | phase 1 complete |
| **3** | Governance control plane: access reviews, access requests, SoD, legal hold, risk exceptions, permission baseline, anomaly config, notification channels, read quota. Ask honestly whether each belongs on a data-plane transport — several are human-workflow surfaces whose only real client is the web UI, and may legitimately end as `http-only` rows. | phase 2 complete |
| **4** | Identity, pending §4: PATs, machine-identity auth paths, and whatever the machine-appropriate step-up primitive turns out to be. | §4 decided |

All phase-1 proto changes are additive and wire-compatible.

## Consequences

- Operators reading the config template now learn the limitation before enabling
  gRPC rather than after provisioning against it.
- `CreateSecretRequest` fields 11-20 are unavailable to unrelated work. This is
  the intent; it costs nothing and prevents an unrecoverable collision.
- The parity project cannot start with "add the two missing fields". That is the
  version that feels like progress and leaves an unaudited partial write surface
  exactly where it was.
- A deliberate `http-only` column means the ledger can reach a green state.
  Finishing with a large `http-only` column and a small `planned` column is a
  **better** outcome than mechanical 1:1 translation.

### Success condition

Not "86 RPCs became 151". It is:

> Every HTTP capability is either covered by gRPC or carries a written reason
> why not, and CI fails if a new one appears that is neither.

## Related

- `docs/adr-039-ha-deployment.md` — dual-control primitive, see §4
- The RemoteStorage proxy conformance work — source of the
  static-versus-differential evidence in §6

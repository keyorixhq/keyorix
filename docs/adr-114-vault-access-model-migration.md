# ADR-114: Vault access-model migration (policies, auth methods → Keyorix roles, grants, machine identities)

**Status:** Accepted (Andrei Beshkov, 2026-10-03)
**Date:** 2026-10-03
**Related:** ADR-030 (machine-token authentication), ADR-031 (OIDC/Kubernetes-JWT
federation), ADR-084 (admin bypass is a structural marker, never grantable),
ADR-108 (CLI/server split — `keyorix-migrate` is the module this ships in),
ADR-113 (service accounts retired — machine identities are the one non-human
identity model), `docs/design-keyorix-migrate.md` (the existing KV-value
migration this extends), `docs/specs/vault-migration-fidelity.md` (MIG-1),
issue #2542 (the gap this closes).

## Context

MIG-1 (`docs/specs/vault-migration-fidelity.md`) proved `keyorix-migrate`
faithfully carries Vault KV **values** into Keyorix, but found **zero** code
path for Vault's **access-control model**: ACL policies, auth methods
(AppRole/userpass/Kubernetes), and tokens. A customer migrating off Vault has
to hand-rebuild every grant from scratch, with nothing checking the rebuilt
grants match what Vault actually allowed. That's #2542 — filed "high,
product decision needed" because Vault's path-glob ACL model does not
correspond 1:1 to Keyorix's project/environment-scoped RBAC, so the right
move is a deliberate mapping design, not an implementation sprint.

Andrei's decision (issue #2542, 2026-10-03): **Option 1, assisted mapping.**
`keyorix-migrate` reads Vault's policies and auth-method roles and *proposes*
Keyorix roles, grants, and machine identities. Anything that doesn't translate
cleanly goes into a human-review report and is **never silently applied**.
After applying, an **equivalence check** proves each migrated identity can
read exactly what it could read in Vault, and nothing more. **Tokens are
never migrated** — every machine identity gets a freshly issued Keyorix
credential.

This ADR is the design: the mapping table, the rounding rule, how a Vault
path tree becomes a Keyorix project/environment scope, the report format, and
the dry-run → review → apply flow. It ships alongside (but is reviewed before)
three follow-up PRs: `vault plan-access` (read-only), `vault apply-access`,
and the equivalence check wired into MIG-1's fidelity harness.

## Decision

### The governing rule: round down, always

**Every approximation this tool makes must produce a Keyorix grant that is a
subset of what Vault actually granted — never a superset.** When a Vault
construct maps exactly, migrate it exactly. When it maps only approximately
(a glob that can't be resolved to a clean scope, a role that binds more than
one concrete principal), migrate the **largest subset that stays provably
within Vault's actual grant**, and say in the report what was left out.
When no such subset exists, or the construct has no Keyorix equivalent at
all, don't migrate it — write it to the human-review report with a reason
and a category, and create nothing. The one-sentence test for every rule
below: *"could a customer, after `apply-access`, do something in Keyorix they
could not already do in Vault?"* If the answer could ever be yes, the item is
Approximate-with-narrowing or Unmappable, never Exact.

### Mapping table

| Vault construct | Keyorix construct | Classification | Why |
|---|---|---|---|
| AppRole (`role_id`/`secret_id`, `token_policies`, `token_ttl`) | A machine identity (`IdentityType = service`) + a freshly issued `kx_machine_…` credential (ADR-030) + `MachineIdentityRole` grants derived from `token_policies` | **Exact** (credential is re-issued, not copied — see below) | AppRole's own role_id/secret_id are not migrated; everything that *authorizes* (the policy set) is. |
| Kubernetes auth role (`bound_service_account_names`, `bound_service_account_namespaces`, `token_policies`) — exactly one literal name and one literal namespace | A machine identity (`IdentityType = k8s`) + a `MachineIdentityOIDCBinding{issuer, subject: "system:serviceaccount:<ns>:<name>"}` (ADR-031) + `MachineIdentityRole` grants from `token_policies` | **Exact** | A 1:1 (issuer, subject) binding is exactly what one bound SA/namespace pair is. `issuer` is the cluster's OIDC issuer URL, supplied by the operator (`--k8s-issuer`) since Vault's own k8s auth config stores a CA bundle and a review-token JWT, not an OIDC-discoverable issuer URL — the two auth models verify the same JWT differently, so the issuer can't be read out of Vault. |
| Kubernetes auth role binding **multiple** literal SA names/namespaces | One machine identity + one OIDC binding **per concrete (namespace, name) pair** | **Approximate, round down** | Keyorix bindings are 1:1; a role covering 3 SAs becomes 3 independently-revocable machine identities holding the same grants. Strictly narrower-or-equal: each resulting identity can do exactly what that one SA could do in Vault, nothing a sibling SA could additionally do. |
| Kubernetes auth role with `bound_service_account_names` or `_namespaces` containing `"*"` | Nothing created for the wildcard | **Unmappable** | A Keyorix OIDC binding names one exact subject; there is no "any subject in this issuer" binding (and adding one would be a standing wider-than-Vault grant for every future SA that namespace ever gets — exactly the superset this ADR forbids). Reported with every *currently existing* SA that would have matched, each independently offered as a candidate "approximate" migration if the operator wants it, so a wildcard isn't a dead end — just not an automatic one. |
| userpass auth (username + password, attached policies) | Nothing (no credential equivalent) | **Unmappable** | Vault passwords are not extractable or safely portable. The attached policies still feed the human-review report as a recommendation ("user X had policies [...], consider a Keyorix user account with role Y") — but creating the Keyorix user account and its own credential is a human action, not this tool's. |
| A `path "<glob>" { capabilities = [...] }` policy stanza, path resolves to exactly one project+environment, capabilities ⊆ {read, list, create, update, delete} | A custom Keyorix `Role` (one per unique capability-set the migration produces — see "Role granularity" below) granting the mapped permission(s), `MachineIdentityRole`-granted at that project/environment scope | **Exact** | `read`/`list` → `secrets.read`; `create`/`update` → `secrets.write`; `delete` → `secrets.delete`. Capability sets map additively — see permission mapping below. |
| Same, but the glob spans **multiple** project/environment units | One grant per **currently-existing, concretely-enumerated** (project, environment) pair the glob resolves to (via a Vault `LIST` walk at migration time) | **Approximate, round down** | A glob is a live rule in Vault — it covers paths that don't exist yet. A static Keyorix grant cannot replicate "covers whatever shows up later," and approximating it as a project-wide or wildcard grant would be the forbidden superset. Resolving only to what exists today is strictly narrower: a path Vault would newly match tomorrow is simply not covered, which is a loud, reportable limitation (surfaced in the report, not a silent gap), never a silent excess. |
| Same, `capabilities` includes `sudo` | Nothing created for that stanza | **Unmappable** | `sudo` bypasses every other restriction on the path — Keyorix's nearest concept, `Role.BypassesPermissionChecks` (ADR-084), is a structural admin marker never granted by a migration tool. No partial mapping exists that stays narrower than full bypass; the whole stanza is reported, not approximated. |
| A `deny` capability on a path that overlaps an `allow` stanza attached to the **same** auth-method role | The computed allow-set for that role has the denied sub-path **subtracted** before any grant is derived | **Subtracted, not ignored** | Vault's effective access for that identity is "allow minus deny." Treating `deny` as merely "unmappable, flag it" and migrating the raw `allow` stanza anyway would be a real superset — exactly what rounding down forbids. If the subtraction can't be expressed as a clean project/environment-scope grant (the deny carves out the middle of an otherwise-clean scope), the **whole affected allow stanza** is pushed to the human-review report rather than guessed at. |
| Sentinel / Enterprise Governing Policies (EGP), any policy using Vault templating (`{{identity.entity.id}}`, etc.) | Nothing | **Unmappable, by construction** | `parsePolicyHCL` (already shipped, `healthscan/policyparse.go`) extracts static `path { capabilities }` stanzas only — it never evaluates logic, and a templated path's actual value depends on *who* authenticates, which has no single static Keyorix grant that represents it for every future holder. |
| A Vault token (`vault token create`, any auth method) | Nothing (never migrated — explicit product decision) | **Unmappable, by design** | Deliberate: a long-lived Vault token has no Keyorix credential equivalent and re-issuing a fresh machine credential is the whole point of the "safer story" below. The report still identifies the token's policy set (if discoverable via `sys/auth/token/...`) as a recommendation. |
| `sys/*`, `auth/*` (mount management), `identity/*` policy grants | Nothing | **Unmappable** | Keyorix has no "manage auth methods" or "manage mounts" surface for any principal below a human admin — there is nothing to map this onto below the level of "give this person a Keyorix admin account," which is a human decision. |

### Permission mapping (capability → Keyorix permission)

| Vault capability | Keyorix permission |
|---|---|
| `read`, `list` | `secrets.read` |
| `create`, `update` | `secrets.write` |
| `delete` | `secrets.delete` |
| `sudo` | *(none — see table above, stanza is Unmappable)* |

### Role granularity

One Keyorix custom `Role` is created per **unique capability-set** the
migration produces (e.g. a role granting only `secrets.read`, a separate one
granting `secrets.read` + `secrets.write`), reused across every
machine identity/scope that needs that exact set — mirroring how Vault
policies themselves are named, reusable capability bundles. A role is never
reused across a migration run and a later one with a different source Vault;
each migrated role's `Description` carries its Vault provenance (see
"Provenance and idempotency" below), and `apply-access` looks up by that
provenance before creating a duplicate.

### Path tree → project/environment, and the override

`keyorix-migrate vault` (the existing KV-value importer) requires
`--project`/`--environment` because one run targets exactly one scope.
Access migration cannot share that assumption — a **single** Vault policy
routinely spans many projects and environments by glob. The convention:

- **Default convention**: `<mount>/<project-segment>/<environment-segment>/...`
  — the first KV path segment after the mount is matched by name against an
  existing Keyorix project, the second against an environment within it
  (case-sensitive exact match). This mirrors the *existing* secret-value
  convention in `docs/design-keyorix-migrate.md` ("Source-to-Keyorix
  mapping") deliberately — a customer who already migrated secret values
  with that layout gets the same project/environment resolution for access
  grants, no second mental model.
- **Override**: `--path-map <vault-prefix>=<projectID>:<environmentID>`
  (repeatable), required whenever the Vault tree doesn't follow the
  convention, or the operator wants a different target than the name match
  would produce. The longest matching prefix wins; an unmatched path with no
  override falls through to the default convention; a path matched by
  neither, or matching a project/environment that doesn't exist in Keyorix,
  is **Unmappable** (reported with the unresolved path), never guessed at or
  dropped silently.
- `environment_id = 0` (Keyorix's existing global-within-project sentinel,
  already used by `UserRole`/`MachineIdentityRole`) is used **only** when the
  Vault glob provably covers every environment under the resolved project
  with no narrower structure — e.g. `team-a/*` with no environment segment at
  all. It is never used as a fallback for "couldn't resolve the environment,"
  which would be exactly the forbidden superset (env-0 grants access to every
  environment, including ones the glob never actually touched).

### Provenance and idempotency

Vault's identity models with a free-text field but no structured
metadata map (`Role.Description`, `MachineIdentity.Description`, unlike
`Secret.Metadata` which `keyorix-migrate vault` already uses for the
value-import idempotency key) carry a single provenance line in
`Description`, in a fixed, grep-able form:

```
migrate.source-id: <sha256 of fixed, non-sensitive components>
```

appended after any human-readable summary. `apply-access` looks up an
existing object by its **deterministic derived name** first (e.g. a machine
identity named from the sanitized AppRole/K8s-role name, a role named from
its capability set and originating policy name), and on a name match, reads
back the `migrate.source-id` line to tell "I created this, re-running is a
no-op" from "a name collision with something this tool didn't create" —
the exact three-outcome shape (`create`/`skip`/`conflict`) `internal/plan`
already implements for secret values, reused here rather than reinvented.
A `conflict` is never auto-resolved; it is reported and left untouched.

Every created `Role`, `MachineIdentity`, `MachineIdentityRole`, and
`MachineIdentityOIDCBinding` additionally produces its normal audit event
(ADR-030: "every mutation is audited") — `apply-access` adds no audit
bypass — so the object's creation is traceable through the audit trail as
well as through its own `Description` line.

### Why tokens are re-issued, not copied

Vault's `role_id`/`secret_id` and raw tokens are not wire-compatible with any
Keyorix credential shape (`kx_machine_…` opaque tokens, or an OIDC
issuer/subject binding) — there is no format Keyorix could accept that would
let a Vault secret work unmodified as a Keyorix one. Re-issuing is therefore
not an extra precaution bolted on top of a copy that was already possible; it
is the only mechanism that exists. It is also the safer story to tell a
customer: the old Vault credential can be revoked independently, on its own
schedule, with no coordination step with Keyorix; the new Keyorix credential
never passed through Vault's logs, audit trail, or storage; and the
one-time-shown convention (`apply-access` writes new credentials to a file
with `0600` permissions, never to stdout/the report — same discipline
`docs/design-keyorix-migrate.md`'s "Never log, print, or report a secret
value" already applies to KV values) means the migration tool itself never
holds a durable copy either.

### Report format

`plan-access` writes the same three-file convention as `vault scan`
(`<prefix>.json`, `.md`, `.html`) and the same per-item outcome shape
`internal/plan` already uses for values, extended with the mapping
classification:

- `create` — this tool will create this object; shows every field it will
  set (names, scope, permissions, and for a machine identity, which
  credential/binding it will mint) and nothing that doesn't yet exist.
- `skip` — already migrated by a prior run of this tool (provenance match).
- `conflict` — a same-named object exists that this tool did not create;
  never auto-resolved, always left for the operator.
- `unmappable` — new outcome, not present in the value-import plan shape.
  Carries a `category` (`sudo`, `deny-overlap`, `sentinel-or-templated`,
  `userpass`, `token`, `wildcard-identity`, `unresolved-path-scope`,
  `mount-management`) and a human-readable `reason`, **always naming the
  exact Vault construct** (policy name + path, or auth-method role name) so
  a human reviewer can find it in Vault directly — never a generic "could
  not migrate."

No report, at any verbosity, ever contains a Vault token, `role_id`/
`secret_id`, or a freshly minted Keyorix credential value — the existing
canary-value-test discipline from MIG-1's fidelity harness extends to cover
this report too (credentials substituted for the canary in the equivalence
check's own test fixtures).

### Flow: dry-run → review → apply

1. **`keyorix-migrate vault plan-access`** (read-only — same safety
   contract as `vault scan`: GET/LIST only against Vault, and for this
   command, read-only `by-name`/`list` lookups against Keyorix too, never a
   write) reads every ACL policy and every AppRole/userpass/Kubernetes auth
   role, applies the mapping and rounding rules above, and writes the
   three-file report. Nothing is created.
2. **Human review.** The operator reads the `.md`/`.html` report, especially
   every `unmappable` row, and either accepts the plan, or re-runs
   `plan-access` with `--path-map` overrides to correct a resolved scope,
   repeating until satisfied. This step is mandatory by construction — there
   is no `--yes`/non-interactive flag that skips straight from `plan-access`
   to object creation; `apply-access` always requires an explicit `--plan
   <file>` the operator has had the chance to read.
3. **`keyorix-migrate vault apply-access --plan <file>`** re-derives and
   re-checks the plan immediately before executing *each* item — never
   trusting the file's snapshot, exactly like the existing value-import
   `--apply` convention ("the source or the target could have changed in
   between") — then creates only what the (re-verified) plan says to create.
   Idempotent and resumable via the provenance lookup above: a killed-mid-run
   process leaves a valid prefix of completed items, and a re-run with the
   same plan file treats them as `skip`. Every newly issued machine-identity
   credential is written to an operator-specified file (`--credentials-out`,
   `0600`), one time, in generation order; nothing is printed to stdout/
   stderr beyond a non-sensitive summary line per item.
4. **Equivalence check** (own PR, wired into MIG-1's fidelity harness so it
   runs in CI against the seeded messy Vault): for every migrated identity,
   enumerate what it could read in Vault (`sys/capabilities-self` against a
   real token minted for that AppRole/K8s role in the test bed) and what it
   can read in Keyorix (its granted roles resolved to secrets), and diff.
   **Any Keyorix access beyond Vault's is a hard FAIL** — a bug in this
   tool's narrowing logic, not a tolerance to document. Missing access
   (the narrowing working as designed, or a genuinely Unmappable item) is
   reported as a named gap, never silently passed.

## Consequences

- Closes #2542's three "not supported — no code path at all" rows for ACL
  policies, auth-method roles, and the equivalence check.
- The round-down rule means a migrated environment is **provably no more
  permissive than the Vault it replaced** — the equivalence check is the
  mechanism that keeps this true rather than merely asserted, per this
  repo's "prefer the machine-checked over the asserted" principle.
- A customer with heavy Sentinel/EGP, templated identity policies, or
  wildcard Kubernetes bindings will see a human-review report dominated by
  `unmappable` rows rather than a fully-automated migration — expected and
  intentional: those constructs have no safe automatic equivalent, and a
  tool that guessed at one would be exactly the superset-risk this ADR exists
  to prevent.
- `keyorix-migrate`'s module-boundary constraint (no dependency on
  `internal/core`/`internal/storage`) means `apply-access` creates roles and
  machine identities **only** through the public REST API, with whatever
  role/machine-identity/OIDC-binding endpoints that implies adding to its
  filtered OpenAPI client (`keptPaths`) — tracked in the implementation PR,
  not a design question for this ADR.
- Follow-up, explicitly out of scope here: Vault Transit/PKI/database
  dynamic-secret engines have no Keyorix equivalent at all (already
  documented as out of scope by MIG-1) and are not touched by this ADR
  either — access-control migration only covers principals/grants for the
  KV migration this tool already performs.

## What this is not

- Not a live sync — this is a one-time, human-reviewed migration, same as
  the existing value import. Vault and Keyorix access models can and will
  drift apart the moment `apply-access` finishes; there is no ongoing
  reconciliation.
- Not a guarantee that every Vault access pattern has a Keyorix equivalent —
  several categories above are permanently Unmappable by construction
  (`sudo`, Sentinel/EGP, templated policies, wildcard Kubernetes bindings),
  and the right outcome for those is a clear human-review item, not a
  best-effort guess.

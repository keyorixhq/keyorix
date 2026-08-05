# ADR-076: Kubernetes operator RBAC/watch scope — fail-closed to own-namespace by default

## Status

Accepted. Implementation follows in subsequent commits on this same branch
(`fix/adr-070-operator-rbac-scope`).

## Context

The `keyorix-operator` (ADR-060, `operator/`) ships with a `ClusterRole` granting full
CRUD (`get/list/watch/create/update/patch/delete`) on core `Secrets`, bound **cluster-wide**
via a `ClusterRoleBinding`, **by default**. The reconcile loop only ever touches Secrets in
the same namespace as the triggering `KeyorixSecret` CR — the grant is broader than the
code's own behavior requires, in every deployment except the one where a single instance
genuinely must watch every namespace with no static list.

**This is the third attempt to narrow it, and the first two both left the default
unchanged:**

1. **`0869bd91`** (#429, ADR-060) — the operator's original introduction. Cluster-wide
   only; no opt-out existed.
2. **`dc36f3e4`** (#327, #613) — scoped the manager's Secret *informer cache* to
   label-matched Secrets only. A real mitigation (bounds what a compromised operator
   process can dump from its own memory), but it narrows nothing at the RBAC layer — the
   ServiceAccount's live API grant is untouched.
3. **`9171e86f`** (#327/#427, #790) — added the first opt-in: a `watchNamespaces` Helm
   value and matching `-watch-namespaces` flag, narrowing both cache and RBAC together
   when set. Explicit in the commit message: *"The default (unset) behavior, including the
   rendered manifests, is unchanged."* A real opt-in, deliberately not a default change.
4. **`4b8a2614`** (#1224) — attempted the exact default flip this ADR now makes: a
   sub-commit set `rbac.clusterScoped` to default `false` (namespace-scoped). A **later
   sub-commit in the same PR** reverted it, titled `fix(helm): correct operator
   rbac.clusterScoped default and template precedence` — the chart's `if`/`else if`/`else`
   ordering was backwards, and the default render emitted **neither** a `RoleBinding` nor a
   `ClusterRoleBinding` at all: a silent no-RBAC misrender, caught pre-merge only because
   `9171e86f`'s CI chart-render assertion happened to exist. Rather than fix the template
   ordering, the default was reverted to `true` to restore exact prior behavior as a
   stopgap.

**What's different this time:** both prior narrowing attempts treated this as a *chart*
problem — a Helm value default and a template `if` chain. The chart is where both attempts
broke, in two different ways (a silent no-binding misrender in #1224; a live wiring gap
described below that neither attempt closed). This ADR moves the fail-closed behavior into
the **binary** instead: the manager's own default scope becomes own-namespace regardless of
what the chart renders, so a future chart defect produces an operator that is *broken*
(fails to start, or watches too little), never one that is silently *over-privileged*. This
is the same fail-closed posture already applied to this codebase's auth/RBAC/AAD paths —
the failure direction is chosen deliberately, not left to whichever path happens to be
checked first.

**The live wiring gap referenced above** (found during this ADR's investigation, not
previously documented): the chart's *other* narrowing option, `rbac.clusterScoped: false`
(added by `4b8a2614`, survived the revert), binds a namespace-scoped `RoleBinding` — but
nothing in `deployment.yaml` passes `-watch-namespaces` in that path; the flag is rendered
**only** when `.Values.watchNamespaces` is non-empty, a separate value `clusterScoped: false`
doesn't touch. So `rbac.clusterScoped: false` alone today produces a manager that still
defaults to watching **all namespaces** (`operator/cmd/main.go`'s `secretCacheOptions`
leaves `cache.Options.DefaultNamespaces` unset whenever `-watch-namespaces` is empty) against
RBAC that only grants **one**. In a real cluster this means repeated `Forbidden` errors on
every list/watch outside the release namespace, likely fatal to controller startup. This has
apparently shipped, unnoticed, since `4b8a2614`.

**Investigation finding: no residual `ClusterRole` is justified by anything other than the
"watch every namespace with no static list" mechanism itself.** Checked directly, not
assumed:
- `KeyorixSecretSpec` (`operator/api/v1alpha1/keyorixsecret_types.go`) has no namespace
  field anywhere — `tokenSecretRef`/`target` resolve only against `ks.Namespace` (the
  watch-derived `req.NamespacedName`), never an attacker- or cross-namespace-supplied value.
- No webhooks exist in the module.
- No cluster-scoped Kubernetes resource type (`Node`, `Namespace`, `CustomResourceDefinition`)
  is read anywhere in `operator/` — grepped and confirmed absent.
- The operator's only external call (`operator/internal/keyorix/client.go`) is a single
  `GET /api/v1/secrets/value` HTTP request to the configured Keyorix server — an
  out-of-cluster API call, not an in-cluster cross-namespace K8s operation. Any secret
  sharing / cross-project authorization gap that exists lives in that server's own
  authorization for that endpoint, not in this operator's Kubernetes RBAC footprint — out of
  scope for this ADR.

Once the default stops requiring "watch every namespace with no static list," the only
reason a `ClusterRole`/`ClusterRoleBinding` exists at all is the explicit, opt-in
cluster-wide deployment mode this ADR keeps available.

## Decision

### A. The binary is the fail-closed boundary, not the chart

`operator/cmd/main.go` gets a new, explicit contract:

| Flags passed | Resulting scope |
|---|---|
| neither flag set, `POD_NAMESPACE` non-empty | **Own namespace only**, read from `POD_NAMESPACE` (populated via the Kubernetes Downward API, `fieldRef: metadata.namespace`, in the chart's Deployment spec) |
| `-watch-namespaces=a,b,c` | Exactly those namespaces |
| `-all-namespaces` | Cluster-wide — the **only** route to cluster-wide; there is no other way to make the manager watch every namespace |
| both `-watch-namespaces` and `-all-namespaces` set | Startup validation error, non-zero exit — contradictory config is rejected, never silently resolved by precedence |
| neither flag set, `POD_NAMESPACE` unset or empty | Startup validation error, non-zero exit, message naming `POD_NAMESPACE` specifically |

The current behavior — unset `-watch-namespaces` defaults to all-namespaces — is the root
fail-open every chart-level defect found during investigation is downstream of. Every failure
mode in the reversal history (the #1224 no-binding misrender, and the live RBAC/cache wiring
gap above) is a chart bug that happened to matter *because* the binary's own default was
permissive. Fixing the default here means the failure direction of a future chart defect is
always "the operator doesn't watch enough" or "the operator fails to start," never "the
operator silently holds more access than intended."

**Why an empty `POD_NAMESPACE` is a hard failure, not a silent fallback to all-namespaces**:
falling back would rebuild exactly the fail-open this ADR exists to remove — but there's a
second, sharper reason beyond that symmetry argument. `controller-runtime` treats an
empty-string key in `cache.Options.DefaultNamespaces` as all-namespaces. An unchecked blank
`POD_NAMESPACE` wouldn't even fail loudly on its own: it would silently produce a
cluster-wide watch through code that *reads* as correctly scoped — a map literally
constructed as `{"": {}}` looks, at the call site, like "watch namespace `\"\"`," not "watch
everything." That is precisely the shape of bug this ADR is written to stop reintroducing.
Refuse to start instead of guessing.

**This makes the binary's own default dependent on the chart** — row 1 only holds if the
chart actually supplies `POD_NAMESPACE` via the Downward API (`deployment.yaml`,
`fieldRef: metadata.namespace`); that dependency is real, not just documentation. The hard
fail in row 5 is what makes it *safe*: under a version-skewed chart/image pair (an old chart
missing the env-var wiring paired with a new image, or a hand-rolled non-Helm deployment that
forgets it entirely), the operator fails to start immediately and loudly instead of silently
reverting to cluster-wide.

### B. Chart: one named template computes effective scope once

`rbac.yaml` and `deployment.yaml` currently each branch on `.Values.watchNamespaces` /
`.Values.rbac.clusterScoped` independently — the exact shape of divergence that produced the
#1224 misrender and the live wiring gap. Both templates instead render from a single named
helper (in `_helpers.tpl`) that resolves the effective scope once and returns it in a form
both templates consume — neither template reads `.Values.watchNamespaces` /
`.Values.rbac.clusterScoped` directly again. Four paths, no fifth:

| `rbac.clusterScoped` | `watchNamespaces` | RBAC binding | `-watch-namespaces` / `-all-namespaces` flag |
|---|---|---|---|
| `false` (default) | `[]` (default) | `RoleBinding` in `.Release.Namespace` | `-watch-namespaces={{ .Release.Namespace }}` |
| `false` | set | `RoleBinding` per listed namespace | `-watch-namespaces={{ join "," .Values.watchNamespaces }}` |
| `true` | `[]` | `ClusterRoleBinding` | `-all-namespaces` |
| `true` | set | Helm `fail`, naming both `rbac.clusterScoped` and `watchNamespaces` in the message | — (render aborts) |

No precedence-based resolution of the fourth (contradictory) combination — `4b8a2614`
demonstrated precedence ordering is exactly how this class of chart produces a silent
misrender. Reject it explicitly instead.

### C. Rejected alternative: collapse into a single `scope` enum

Considered replacing `rbac.clusterScoped` + `watchNamespaces` with one Helm value (e.g.
`scope: namespace | multi-namespace | cluster`). Cleaner schema on its own — but it breaks
values compatibility for the existing `watchNamespaces`/`rbac.clusterScoped` keys
(`4b8a2614` already shipped and documented `rbac.clusterScoped`) for no security benefit:
once the single named helper in (B) makes divergence between the two values structurally
impossible, a two-value schema is exactly as safe as an enum, at zero migration cost to
whoever already set `rbac.clusterScoped: true`. Rejected; keep both existing values, resolved
through the shared helper.

### D. Testing: extend the chart-render assertion, and add direct binary-level coverage of the fail-closed default

`9171e86f` (#790) added a CI chart-render assertion that already caught the `4b8a2614`
misrender before merge — the mechanism worked exactly as intended once. Extend that same
assertion to cover all four rows of the table in (B), asserting in each case that the
rendered RBAC binding kind (`RoleBinding` vs `ClusterRoleBinding`, and its namespace(s)) and
the rendered manager flag (`-watch-namespaces=...` vs `-all-namespaces`) actually agree with
each other — not just that *something* renders. That agreement check is what (B)'s failure
mode would have violated; asserting it directly is what makes this bug class non-recurring
rather than merely fixed once more.

That chart-render assertion, however, can never exercise (A)'s own fail-closed default: row 1
of (B)'s table renders `-watch-namespaces={{ .Release.Namespace }}` explicitly, so a real
Helm-deployed instance always receives an explicit flag — it never falls through to (A) row
1's `POD_NAMESPACE` path. Keeping the explicit flag in the chart is a deliberate, separate
choice (manifest readability — the rendered Deployment shows its own scope without
cross-referencing a Downward API env var — and (D)'s own flag-agrees-with-binding assertion
needs an actual flag value to compare against), but it means the binary's fail-closed default
needs test coverage that doesn't route through the chart at all. Two new unit tests in
`operator/cmd`:
- no flags set, `POD_NAMESPACE=foo` → the constructed cache options scope to `foo` only.
- no flags set, `POD_NAMESPACE` empty/unset → non-zero exit, exercising (A) row 5 directly.

### E. Out of scope for this ADR, noted so it isn't rediscovered as new

- The dead `keyorixsecrets/finalizers` RBAC grant (round-143 finding #535, fix already
  pending in unmerged PR #1329) — unrelated axis (verb/resource hygiene, not namespace
  scope), left to that PR.
- The full CRUD verb set on core `Secrets` (`create/update/patch/delete`, not just
  `get/list/watch`) — a real, separate question (`delete` in particular is a likely finding
  on its own, scoped to `wipeTargetSecret`'s use of it per #428). Verb scope and namespace
  scope are independent axes; conflating them here would block this fix on a second, larger
  design discussion. Deferred to its own future ADR.

## Consequences

**This is a deployment-behavior change, not a pure bug fix — it changes what an unmodified
`helm install` grants by default.** Two separate CHANGELOG entries, not one:

- **`BREAKING`**: default scope changes from cluster-wide to own-namespace-only. Existing
  installs that rely on today's default (a single cluster-wide instance, no values
  overridden) must set `rbac.clusterScoped: true` explicitly to preserve current behavior
  across the upgrade; the upgrade note states this exactly, not just "review your RBAC."
- **`Fixed`**: `rbac.clusterScoped: false` has been non-functional since `4b8a2614` — it
  binds namespace-scoped RBAC while the manager continues watching all namespaces (the live
  wiring gap documented in Context). Checked tags/release history directly rather than
  assuming: `4b8a2614` landed 2026-07-29, three days *after* the most recent tag, `v0.88.0`
  (2026-07-26); `git tag --contains 4b8a2614` returns no tags. **No released version has ever
  shipped this option** — it has only ever existed on trunk. The CHANGELOG entry can state
  this plainly (e.g. "never worked correctly; fixed before its first release") rather than
  naming affected versions, since there are none.

**Why now, specifically.** Per ADR-067, Keyorix is pre-1.0 with no paying production
deployment yet and no LTS line — the migration cost of a breaking default change is at its
lowest point it will ever be. Once the first LTS line exists (ADR-067: cut at v1.0, first
paying production deployment), a change to this operator's default RBAC scope becomes a
five-year-obligation-affecting change under CRA Article 13(8) for every customer already on
that line, not a values-file adjustment made once before anyone depends on the old default.
This is the last point at which the fix is cheap.

**Positive.** Closes the actual gap round 143's audit found (cluster-wide-by-default full
Secret CRUD) at its root — the binary's own default — rather than only in the chart, where
it has now failed to stay fixed twice. The chart-render assertion in (D) converts a bug class
that has recurred twice into one CI catches by construction.

**Negative.** Multi-namespace operators (today implicitly served by the permissive default)
must now set `watchNamespaces` explicitly, or `rbac.clusterScoped: true` for the genuinely
cluster-wide case — a required action on upgrade for that population, not a silent
improvement.

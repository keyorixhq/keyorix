# ADR-057: Kubernetes sync orphan cleanup

## Status

Accepted.

## Context

The `keyorix-k8s-sync` agent materialises selected Keyorix secrets into native
Kubernetes Secrets and refreshes them as upstream values rotate (see
[docs/k8s-sync.md](k8s-sync.md)). It writes each target Secret with Server-Side Apply
under the field manager `keyorix-sync`, so it owns the Secret's `data`: removing a
single *key* from a mapping prunes that key on the next pass automatically.

What it did **not** handle is a fully removed target. When an operator deletes *every*
mapping for a `namespace/name` Secret, the agent just stops reconciling it — the
Kubernetes Secret lingers indefinitely with stale, possibly sensitive values. There was
no mechanism to retire a Secret the agent had created once it fell out of the config, so
removing a workload's secrets from Keyorix left orphans behind in the cluster.

## Decision

Add an opt-in **orphan cleanup** pass that deletes agent-created Secrets whose target is
no longer in the config. Ownership is recorded **on-cluster via a label** rather than in
any external state, keeping the agent stateless and dependency-free (no `client-go`).

- **Ownership label.** Every Secret the agent applies is stamped
  `app.kubernetes.io/managed-by: keyorix-sync`. This is the sole record of ownership.
- **Cleanup pass.** After the apply loop, for each namespace the config still
  references, the agent lists Secrets carrying the label (`GET …/secrets?labelSelector=`)
  and deletes those whose `(namespace, name)` is no longer a desired target
  (`DELETE …/secrets/{name}`; a `404` is treated as success).
- **Opt-in.** Off by default — deleting Secrets is destructive. Enabled by `cleanup:
  true` in the config or the `-cleanup` flag. Composes with `-dry-run`, which reports the
  would-delete count without removing anything, and with `-once` for a previewable gate.
- **Observability.** A new `deleted` outcome joins the reconcile log line, the `/status`
  JSON, and the `keyorix_k8s_sync_secrets_total{outcome="deleted"}` metric.
- **RBAC.** The chart's `ClusterRole` gains `list` and `delete` on `secrets`; both are
  unused when cleanup is off.

### Safety properties

- **Label-scoped** — the list selector means the agent only ever sees Secrets it
  created, so an operator- or third-party-created Secret can never be deleted.
- **Config-scoped** — only namespaces still present in the config are scanned. Dropping
  a namespace from the config entirely leaves its Secrets unreaped (documented: remove
  the mappings, let one pass reap, then drop the namespace).
- **Fail-safe on upstream errors** — a target still in the config is kept even if its
  Keyorix fetch failed this pass, so a transient 404 cannot delete a live Secret. A ref
  deleted *in Keyorix* while its mapping remains fails that target closed and leaves the
  existing Secret in place; the value is never auto-pruned.
- **Single-owner assumption** — cleanup assumes one sync agent owns a managed namespace.
  Two agents with different mapping sets pointed at the same namespace with cleanup on
  would each treat the other's Secrets as orphans. Documented as a constraint.

## Alternatives considered

- **Auto-prune on a deleted upstream ref.** Deleting the Kubernetes Secret as soon as
  `Fetch` returns not-found. Rejected: indistinguishable from a transient error or a
  permissions blip, and would turn a momentary Keyorix outage into cluster-wide secret
  deletion. Fail-closed retention is safer; retiring a secret is an explicit
  mapping-removal action.
- **External ownership state** (a ConfigMap or the agent's own store tracking what it
  created). Rejected: adds a consistency problem (state vs. reality drift) and a write
  dependency. A label is the Kubernetes-native, self-healing record of ownership.
- **Owner references / garbage collection.** Rejected: there is no parent object to own
  the Secrets, and cross-namespace owner refs are disallowed.
- **On by default.** Rejected: deletion is destructive and the blast radius (a
  mis-scoped namespace, a second agent) warrants explicit opt-in plus a dry-run preview.

## Consequences

- Removing a mapping now retires its Kubernetes Secret on the next pass when `cleanup`
  is enabled, closing the stale-orphan gap; with cleanup off, behaviour is unchanged.
- Operators enabling cleanup must grant `list`/`delete` on Secrets and ensure a single
  agent owns each managed namespace. The `-cleanup -dry-run -once` combination previews
  deletions before committing.

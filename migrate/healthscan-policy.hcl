# healthscan-policy.hcl — the minimal, strictly read-only Vault policy `keyorix-migrate vault
# scan` needs. Attach this to the token (or AppRole role) the scan runs with.
#
# Every stanza below is scoped to exactly one G2 check (docs/vault-health-scan.md documents the
# same mapping in prose). A check whose path is denied by whatever policy you actually attach
# reports "NOT CHECKED (permission denied)" in the scan output — it never fails the run — and
# the report names the missing stanza so you can add it and re-run. You do not need to grant
# every stanza here; grant what you're comfortable with and read the "Not checked" section of
# the report for the rest.
#
# This policy grants "read" and "list" capabilities only. It never grants "create", "update",
# "delete", "sudo", or "*" — the scan's client (migrate/internal/healthscan) refuses to issue
# any HTTP method other than GET/LIST at the code level regardless of what a token is scoped to
# (see client.go's request()), so a broader policy would not let the scan do more, only let a
# *different* tool holding the same token do more. Least-privilege still means granting only
# what's below.

# a) Version / license / OpenBao detection.
path "sys/health" {
  capabilities = ["read"]
}
path "sys/seal-status" {
  capabilities = ["read"]
}

# b) Seal type, recovery/unseal key shares and threshold.
path "sys/seal-status" {
  capabilities = ["read"]
}

# c) HA/storage: leader/HA status, raft peers, autopilot health.
path "sys/leader" {
  capabilities = ["read"]
}
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}
path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}

# d) Audit devices.
path "sys/audit" {
  capabilities = ["read"]
}

# e) Root tokens via token accessors. This check is best-effort by design: identifying which
# accessor carries the root policy normally requires POST auth/token/lookup-accessor, which
# this tool never issues (it only ever GETs/LISTs — see docs/vault-health-scan.md's "Read-only
# guarantee"). Only the accessor *count* is checked here.
path "auth/token/accessors" {
  capabilities = ["list"]
}

# f) Auth methods, AppRole secret_id TTL/uses.
path "sys/auth" {
  capabilities = ["read"]
}

# g) Policies: wildcard/sudo grants, sprawl.
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/+" {
  capabilities = ["read"]
}

# h) Token/lease hygiene: default/max TTLs on mounts and auth methods.
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/mounts/+/tune" {
  capabilities = ["read"]
}
path "sys/auth/+/tune" {
  capabilities = ["read"]
}

# i) Secrets engines inventory, KV v2 config, staleness (metadata only — never KV *data*).
path "sys/mounts" {
  capabilities = ["read"]
}
path "+/config" {
  capabilities = ["read"]
}

# j) TLS/listener config.
path "sys/config/state/sanitized" {
  capabilities = ["read"]
}

# k) Namespaces (Vault Enterprise).
path "sys/namespaces" {
  capabilities = ["list"]
}

# l) Backups: raft auto-snapshot config (Enterprise). Reported "unknown, ask" when this path
# isn't visible even with read granted — Vault OSS has no such endpoint at all.
path "sys/storage/raft/snapshot-auto/config" {
  capabilities = ["list", "read"]
}

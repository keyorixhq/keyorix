# healthscan-policy.hcl — the minimal, strictly read-only Vault policy `keyorix-migrate vault
# scan` needs. Attach this to the token (or AppRole role) the scan runs with.
#
# Every stanza below is scoped to exactly one check in migrate/internal/healthscan (each check's
# own source file names the same paths). A check whose path is denied by whatever policy you
# actually attach reports "NOT CHECKED (permission denied)" in the scan output — it never fails
# the run — and the report names the missing stanza so you can add it and re-run. You do not
# need to grant every stanza here; grant what you're comfortable with and read the "Not checked"
# section of the report for the rest.
#
# This policy grants "read" and "list" capabilities only. It never grants "create", "update",
# "delete", "sudo", or "*" — the scan's client (migrate/internal/healthscan) refuses to issue any
# HTTP method other than GET/LIST at the code level regardless of what a token is scoped to (see
# client.go's request()), so a broader policy would not let the scan do more, only let a
# *different* tool holding the same token do more. Least-privilege still means granting only
# what's below.
#
# One check this scan cannot perform under ANY policy: identifying which tokens hold the root
# policy (check "root-tokens") requires Vault's POST auth/token/lookup-accessor, which this
# GET/LIST-only client never issues. See docs/vault-health-scan.md. No stanza below would change
# that — it's a method restriction, not a permission gap.

# checkVersionEOL / checkEnterpriseLicense (item a: version/EOL/license/product detection).
path "sys/health" {
  capabilities = ["read"]
}
path "sys/license/status" {
  capabilities = ["read"]
}

# checkSeal (item b: seal type, recovery/unseal shares, sealed status).
path "sys/seal-status" {
  capabilities = ["read"]
}

# checkHAStorage / checkRaftAutopilot (item c: HA/storage topology, raft peers, autopilot).
path "sys/leader" {
  capabilities = ["read"]
}
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}
path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}

# checkAuditDevices (item d).
path "sys/audit" {
  capabilities = ["read"]
}

# checkTokenAccessorCount (item e — total count only; see the note above on why the actual
# root-token identification can never be granted).
path "auth/token/accessors" {
  capabilities = ["list"]
}

# checkAuthMethods / checkAppRoleSecretIDHygiene (item f).
path "sys/auth" {
  capabilities = ["read"]
}
path "auth/+/role" {
  capabilities = ["list"]
}
path "auth/+/role/+" {
  capabilities = ["read"]
}

# checkPolicySprawl / checkWildcardSudoPolicies (item g).
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/+" {
  capabilities = ["read"]
}

# checkTTLHygiene / checkLeaseCounts (item h). Lease counts are best-effort — most deployments
# scope sys/leases/lookup tightly, and this check treats a denial as "not visible," not a gap.
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/leases/lookup/+" {
  capabilities = ["list"]
}

# checkSecretsEnginesInventory / checkKVv2Config / checkSecretStaleness (item i). Never reads
# a KV *data* path — only /metadata, and only the metadata's updated_time field.
path "+/config" {
  capabilities = ["read"]
}
path "+/metadata/*" {
  capabilities = ["list", "read"]
}

# checkTLSListener (item j) — usually sudo/root-only in a locked-down policy; expect this one to
# show up as "not checked" often, which is fine.
path "sys/config/state/sanitized" {
  capabilities = ["read"]
}

# checkNamespaces (item k, Enterprise only).
path "sys/namespaces" {
  capabilities = ["list"]
}

# checkRaftAutoSnapshot (item l, Enterprise + raft only).
path "sys/storage/raft/snapshot-auto/config" {
  capabilities = ["list", "read"]
}

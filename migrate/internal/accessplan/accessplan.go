// Package accessplan builds ADR-114's Vault-access-model migration plan (docs/adr-114-vault-
// access-model-migration.md): the mapping from Vault ACL policies and auth-method roles to
// proposed Keyorix roles, grants, and machine identities. It is pure and network-free — every
// function here takes already-read Vault data (migrate/internal/healthscan's exported readers)
// and already-read Keyorix data (this module's accesstarget package) and returns a Plan,
// exactly like internal/plan does for secret values. Nothing here ever makes a network call,
// so the mapping/rounding rules are unit-testable without a live Vault or Keyorix.
//
// The one rule every function in this package must honor (ADR-114's governing rule): an
// approximation must never produce an Item whose Create outcome would let a migrated principal
// do something in Keyorix it could not already do in Vault. When a clean subset isn't
// expressible, the item becomes Unmappable, never a guessed-at Create.
package accessplan

// Outcome classifies what this package decided for one proposed object.
type Outcome string

const (
	// Create: this object does not yet exist in Keyorix (by provenance or by name) and the
	// plan proposes creating it.
	Create Outcome = "create"
	// Skip: a prior run of this tool already created this exact object (provenance match).
	Skip Outcome = "skip"
	// Conflict: a same-named object exists that this tool did not create — never auto-resolved.
	Conflict Outcome = "conflict"
	// Unmappable: no Keyorix object is proposed for this Vault construct. Category/Reason
	// explain why.
	Unmappable Outcome = "unmappable"
)

// ObjectKind is which kind of Keyorix object an Item proposes (or, for Unmappable, would have
// proposed had the construct been mappable).
type ObjectKind string

const (
	KindRole             ObjectKind = "role"
	KindMachineIdentity  ObjectKind = "machine_identity"
	KindMachineRoleGrant ObjectKind = "machine_identity_role"
	KindOIDCBinding      ObjectKind = "oidc_binding"
)

// UnmappableCategory names why an Item is Unmappable — ADR-114's report format requires one of
// these on every Unmappable item, never a generic "could not migrate."
type UnmappableCategory string

const (
	CategorySudo                UnmappableCategory = "sudo"
	CategoryDenyOverlap         UnmappableCategory = "deny-overlap"
	CategorySentinelOrTemplated UnmappableCategory = "sentinel-or-templated"
	CategoryUserpass            UnmappableCategory = "userpass"
	CategoryToken               UnmappableCategory = "token"
	CategoryWildcardIdentity    UnmappableCategory = "wildcard-identity"
	CategoryUnresolvedPathScope UnmappableCategory = "unresolved-path-scope"
	CategoryMountManagement     UnmappableCategory = "mount-management"
)

// Item is one proposed (or rejected) Keyorix object, with everything a human reviewer or
// apply-access needs.
type Item struct {
	Kind    ObjectKind
	Outcome Outcome

	// SourceRef always names the exact Vault construct this item came from (a policy name +
	// path, or an auth-method role name) — ADR-114's report format requires this on every
	// item, including Unmappable ones, so a reviewer can find it in Vault directly.
	SourceRef string

	// Category/Reason are set for Unmappable items.
	Category UnmappableCategory
	Reason   string

	// ConflictReason is set for Conflict items.
	ConflictReason string

	// Proposed* describe what Create would do (and what an existing Skip'd object already
	// is, read back from its provenance line).
	ProposedName          string
	ProposedProjectID     int
	ProposedEnvironmentID int // 0 = global-within-project (ADR-114's env-0 sentinel use)
	// ProposedPermissions is set for KindRole: the Keyorix permission names (e.g.
	// ["secrets.read","secrets.write"]) the role should hold.
	ProposedPermissions []string
	// ProposedIdentityType is set for KindMachineIdentity: "service" (AppRole) or "k8s"
	// (Kubernetes auth).
	ProposedIdentityType string
	// ProposedOIDCIssuer/Subject are set for KindOIDCBinding.
	ProposedOIDCIssuer  string
	ProposedOIDCSubject string
	// ProposedRoleRef names the role a KindMachineRoleGrant/KindOIDCBinding's parent machine
	// identity should hold — the deterministic role name, resolved against ProposedName's
	// sibling Role items in the same Plan.
	ProposedRoleRef string
	// ProposedMachineRef names the parent machine identity a KindMachineRoleGrant/
	// KindOIDCBinding belongs to.
	ProposedMachineRef string

	// ProvenanceKey is the migrate.source-id this object would carry in its Description —
	// apply-access's idempotency key (ADR-114's "Provenance and idempotency").
	ProvenanceKey string
}

// Plan is the full output: every item this run produced, in a stable, deterministic order
// (callers sort before returning — see Build's doc comment) so two runs against unchanged
// input produce byte-identical reports.
type Plan struct {
	Items []Item
}

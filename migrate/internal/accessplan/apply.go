package accessplan

import (
	"context"
	"fmt"
)

// sourceOriginKey is apply.go's own context key, mirroring internal/target's identically-shaped
// WithSourceOrigin/SourceOrigin (module-boundary rule: migrate/internal packages don't import
// each other's unexported helpers). accesstarget reads this back via SourceOrigin to build the
// client-origin header on every write (#2545's fix, applied here too — see
// accesstarget.go's originEditor).
type sourceOriginKey struct{}

// WithSourceOrigin tags ctx with the human-readable source locator (an Item's own SourceRef,
// e.g. "policy:team-a-ro path:secret/data/team-a/*") of the item a KeyorixWriter call is
// writing.
func WithSourceOrigin(ctx context.Context, ref string) context.Context {
	return context.WithValue(ctx, sourceOriginKey{}, ref)
}

// SourceOrigin returns the locator WithSourceOrigin attached, or "".
func SourceOrigin(ctx context.Context) string {
	s, _ := ctx.Value(sourceOriginKey{}).(string)
	return s
}

// Key returns a canonical identity string for it — the same object always produces the same
// key, and two DIFFERENT objects (even sharing a Kind and SourceRef — e.g. two distinct role
// grants a single AppRole role needs, which share the role's own SourceRef) never collide.
// apply-access uses this to cross-reference a reviewed --plan file's items against a freshly
// re-derived Plan (ADR-114: never trust the file's snapshot) — only an item present in BOTH,
// under the SAME key, is ever executed.
func Key(it Item) string {
	switch it.Kind {
	case KindRole:
		return "role:" + it.ProposedName
	case KindMachineIdentity:
		return "machine:" + it.ProposedName
	case KindMachineRoleGrant:
		return "grant:" + it.ProposedMachineRef + "|" + it.ProposedRoleRef
	case KindOIDCBinding:
		return "binding:" + it.ProposedMachineRef + "|" + it.ProposedOIDCIssuer + "|" + it.ProposedOIDCSubject
	default:
		return string(it.Kind) + ":" + it.SourceRef
	}
}

// KeyorixWriter is the write-executing Keyorix surface Apply needs — every mutation
// apply-access ever performs, nothing more. A real implementation
// (migrate/internal/accesstarget) talks to Keyorix only through the public REST API, matching
// this module's module-boundary rule; Apply itself never does.
type KeyorixWriter interface {
	// CreateRole creates a role with the given permission names, tagging description onto it
	// (apply-access always passes FormatProvenanceLine's output). Returns the new role's id.
	CreateRole(ctx context.Context, name, description string, permissions []string) (id int, err error)
	// CreateMachineIdentity creates a machine identity in projectID, tagging description onto
	// it the same way CreateRole does. Returns the new identity's id. core.CreateMachineIdentity
	// creates it already in state "active" (internal/core/machine_identities.go) — confirmed
	// live against a real server (the access-equivalence e2e check, which found this the hard
	// way: an unconditional activate-after-create call 409'd with "cannot transition from
	// active to active") — so no separate activation step exists in this interface.
	CreateMachineIdentity(ctx context.Context, projectID int, name, identityType, description string) (id int, err error)
	// it the same way CreateRole does. Returns the new identity's id. The identity is created
	// in Keyorix's default "pending" state — ActivateMachineIdentity must be called before any
	// credential can be issued or any role granted that requires an active identity (ADR-030).
	CreateMachineIdentity(ctx context.Context, projectID int, name, identityType, description string) (id int, err error)
	// IssueMachineCredential issues a fresh machine-identity bearer token and returns the raw
	// value — shown exactly once, by Apply's caller, to a 0600 file; never logged or returned
	// in any report (see ApplyResult.Credential's own doc comment).
	IssueMachineCredential(ctx context.Context, projectID, machineID int, name string) (rawToken string, err error)
	// GrantMachineRole grants roleID to machineID at projectID/environmentID scope.
	GrantMachineRole(ctx context.Context, projectID, environmentID, machineID, roleID int) error
	// CreateOIDCBinding binds (issuer, subject) to machineID.
	CreateOIDCBinding(ctx context.Context, projectID, machineID int, issuer, subject string) error
}

// ApplyResult is the outcome of actually executing one planned Item.
type ApplyResult struct {
	Item  Item
	Ran   bool // false when Apply left the item untouched (Skip, Conflict, Unmappable, or a dependency that never got created).
	Error string
	// Credential is the freshly issued machine-identity bearer token, set ONLY for a
	// successfully-run KindMachineIdentity item. The caller (cmd/vaultapplyaccess.go) writes
	// it to the operator's --credentials-out file immediately and discards it — Apply never
	// logs it, and no report type in this module ever carries it.
	Credential string
}

// Apply executes a plan's Create-outcome items in the given order — which MUST be the order
// Build/the plan file produced (a KindMachineIdentity item always precedes the
// KindMachineRoleGrant/KindOIDCBinding items that reference it; see authroles.go). Every other
// outcome (Skip, Conflict, Unmappable) is left untouched and reported as not-run.
//
// Idempotent within a single call: a Role/MachineIdentity item that resolves to the SAME
// ProposedName as one already created earlier in this same call (two AppRole roles needing the
// identical permission set, for instance — roleName() intentionally reuses one name for that
// case) is created only once; every subsequent reference reuses the first call's id. Idempotent
// ACROSS calls (a resumed run): a Skip-outcome Role/MachineIdentity item's ExistingID (set by
// Reconcile) seeds the same in-memory map, so a grant/binding whose parent was migrated by an
// earlier, killed run resolves correctly without re-creating anything.
func Apply(ctx context.Context, items []Item, writer KeyorixWriter) []ApplyResult {
	roleIDs := map[string]int{}
	machineIDs := map[string]int{}
	results := make([]ApplyResult, 0, len(items))

	for _, it := range items {
		switch {
		case it.Outcome == Skip && it.Kind == KindRole:
			roleIDs[it.ProposedName] = it.ExistingID
			results = append(results, ApplyResult{Item: it, Ran: false})
		case it.Outcome == Skip && it.Kind == KindMachineIdentity:
			machineIDs[it.ProposedName] = it.ExistingID
			results = append(results, ApplyResult{Item: it, Ran: false})
		case it.Outcome != Create:
			results = append(results, ApplyResult{Item: it, Ran: false})
		default:
			results = append(results, applyOne(ctx, it, writer, roleIDs, machineIDs))
		}
	}
	return results
}

// applyOne tags ctx with it's own SourceRef (WithSourceOrigin) before every writer call, so
// accesstarget's client-origin header — and so the audit event the server records for the
// write — names the exact Vault policy/role/path this object came from, not just "keyorix-
// migrate" generically (mirrors internal/plan's identical use of target.WithSourceOrigin for
// the value-migration path; #2545 applied here too, see accesstarget.go's originEditor).
func applyOne(ctx context.Context, it Item, writer KeyorixWriter, roleIDs, machineIDs map[string]int) ApplyResult {
	ctx = WithSourceOrigin(ctx, it.SourceRef)
func applyOne(ctx context.Context, it Item, writer KeyorixWriter, roleIDs, machineIDs map[string]int) ApplyResult {
	switch it.Kind {
	case KindRole:
		if _, ok := roleIDs[it.ProposedName]; ok {
			return ApplyResult{Item: it, Ran: false} // a sibling item already created this role earlier in this same run.
		}
		id, err := writer.CreateRole(ctx, it.ProposedName, FormatProvenanceLine(it.ProvenanceKey), it.ProposedPermissions)
		if err != nil {
			return ApplyResult{Item: it, Ran: true, Error: err.Error()}
		}
		roleIDs[it.ProposedName] = id
		return ApplyResult{Item: it, Ran: true}

	case KindMachineIdentity:
		if _, ok := machineIDs[it.ProposedName]; ok {
			return ApplyResult{Item: it, Ran: false}
		}
		id, err := writer.CreateMachineIdentity(ctx, it.ProposedProjectID, it.ProposedName, it.ProposedIdentityType, FormatProvenanceLine(it.ProvenanceKey))
		if err != nil {
			return ApplyResult{Item: it, Ran: true, Error: err.Error()}
		}
		machineIDs[it.ProposedName] = id
		token, err := writer.IssueMachineCredential(ctx, it.ProposedProjectID, id, "migrated-from-vault")
		if err != nil {
			return ApplyResult{Item: it, Ran: true, Error: fmt.Sprintf("created machine identity %d but failed to issue a credential: %v", id, err)}
		if err := writer.ActivateMachineIdentity(ctx, it.ProposedProjectID, id); err != nil {
			machineIDs[it.ProposedName] = id // created, just not usable yet -- later grants will still correctly find it and fail clearly on the actual gate, not silently retry creation.
			return ApplyResult{Item: it, Ran: true, Error: fmt.Sprintf("created machine identity %d but failed to activate it: %v", id, err)}
		}
		machineIDs[it.ProposedName] = id
		token, err := writer.IssueMachineCredential(ctx, it.ProposedProjectID, id, "migrated-from-vault")
		if err != nil {
			return ApplyResult{Item: it, Ran: true, Error: fmt.Sprintf("created machine identity %d but failed to issue a credential: %v", id, err)}
		}
		return ApplyResult{Item: it, Ran: true, Credential: token}

	case KindMachineRoleGrant:
		roleID, okRole := roleIDs[it.ProposedRoleRef]
		machineID, okMachine := machineIDs[it.ProposedMachineRef]
		if !okRole || !okMachine {
			return ApplyResult{Item: it, Ran: false, Error: fmt.Sprintf("parent role %q or machine identity %q was not created in this run — rerun plan-access/apply-access to pick it up", it.ProposedRoleRef, it.ProposedMachineRef)}
		}
		if err := writer.GrantMachineRole(ctx, it.ProposedProjectID, it.ProposedEnvironmentID, machineID, roleID); err != nil {
			return ApplyResult{Item: it, Ran: true, Error: err.Error()}
		}
		return ApplyResult{Item: it, Ran: true}

	case KindOIDCBinding:
		machineID, okMachine := machineIDs[it.ProposedMachineRef]
		if !okMachine {
			return ApplyResult{Item: it, Ran: false, Error: fmt.Sprintf("parent machine identity %q was not created in this run — rerun plan-access/apply-access to pick it up", it.ProposedMachineRef)}
		}
		if err := writer.CreateOIDCBinding(ctx, it.ProposedProjectID, machineID, it.ProposedOIDCIssuer, it.ProposedOIDCSubject); err != nil {
			return ApplyResult{Item: it, Ran: true, Error: err.Error()}
		}
		return ApplyResult{Item: it, Ran: true}

	default:
		return ApplyResult{Item: it, Ran: false, Error: fmt.Sprintf("unknown item kind %q", it.Kind)}
	}
}

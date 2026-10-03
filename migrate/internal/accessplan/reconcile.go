package accessplan

import (
	"context"
	"fmt"
)

// KeyorixReader is the read-only Keyorix surface Reconcile needs to turn a builder's tentative
// Create outcome into the real Create/Skip/Conflict triad — exactly mirroring internal/plan's
// by-name-then-provenance check for secret values, applied to the two named object kinds this
// package creates. A real implementation (migrate/internal/accesstarget) talks to Keyorix only
// through the public REST API, matching this module's module-boundary rule; Reconcile itself
// never does.
type KeyorixReader interface {
	// RoleDescriptionByName returns the role's own Description (where the migrate.source-id
	// line lives, see provenance.go), or found=false if no role has this name.
	RoleDescriptionByName(ctx context.Context, name string) (description string, found bool, err error)
	// MachineIdentityDescriptionByName returns a project-scoped machine identity's own
	// Description, or found=false. Machine identities are project-scoped (ADR-030); Reconcile
	// never looks one up outside the project it's proposed in.
	MachineIdentityDescriptionByName(ctx context.Context, projectID int, name string) (description string, found bool, err error)
	// MachineHasRoleGrant reports whether machineName (within projectID) already holds
	// roleName. A grant has no name of its own to conflict on — existence alone resolves it to
	// Skip or Create.
	MachineHasRoleGrant(ctx context.Context, projectID int, machineName, roleName string) (bool, error)
	// MachineHasOIDCBinding reports whether machineName (within projectID) already has an
	// OIDC binding for (issuer, subject). Same no-conflict-concept reasoning as
	// MachineHasRoleGrant.
	MachineHasOIDCBinding(ctx context.Context, projectID int, machineName, issuer, subject string) (bool, error)
}

// Reconcile resolves every Create-outcome Item in items against live Keyorix state, mutating
// each one's Outcome in place to Create (confirmed), Skip (already migrated by a prior run), or
// Conflict (a same-named object this tool did not create). Unmappable items are left untouched.
// A read error for one item is folded into that item's own Outcome=Conflict-shaped error path —
// actually, per docs/design-keyorix-migrate.md's existing convention (BuildPlan's own per-item
// Error handling), a lookup failure must not silently become Create (that would risk a
// duplicate) or silently vanish — Reconcile returns the first error immediately, matching
// plan-access's own "never guess, never silently proceed" discipline: an unreachable Keyorix is
// a run failure, not a per-item skip, because every subsequent item's conflict detection depends
// on the SAME connectivity.
func Reconcile(ctx context.Context, items []Item, reader KeyorixReader) error {
	// A machine identity's "home" project (what it must be created under, and what
	// KindOIDCBinding items — which carry no project of their own — must be looked up against)
	// is never set directly by the builders; it's derived from the FIRST KindMachineRoleGrant
	// that references it, in item order (deterministic — see authroles.go's doc comments on
	// why a role/SA with zero mappable grants never gets a machine identity item in the first
	// place, so every machine identity that reaches here is guaranteed to have at least one
	// grant to derive a project from). Computed in its own pass since a grant can appear after
	// the identity item it belongs to.
	projectByMachineName := map[string]int{}
	for _, it := range items {
		if it.Kind == KindMachineRoleGrant && it.Outcome == Create {
			if _, ok := projectByMachineName[it.ProposedMachineRef]; !ok {
				projectByMachineName[it.ProposedMachineRef] = it.ProposedProjectID
			}
		}
	}

	for i := range items {
		it := &items[i]
		if it.Outcome != Create {
			continue
		}
		switch it.Kind {
		case KindRole:
			desc, found, err := reader.RoleDescriptionByName(ctx, it.ProposedName)
			if err != nil {
				return fmt.Errorf("reconcile role %q: %w", it.ProposedName, err)
			}
			resolveNamedObject(it, found, desc)
		case KindMachineIdentity:
			projectID := projectByMachineName[it.ProposedName]
			it.ProposedProjectID = projectID
			desc, found, err := reader.MachineIdentityDescriptionByName(ctx, projectID, it.ProposedName)
			if err != nil {
				return fmt.Errorf("reconcile machine identity %q: %w", it.ProposedName, err)
			}
			resolveNamedObject(it, found, desc)
		case KindMachineRoleGrant:
			has, err := reader.MachineHasRoleGrant(ctx, it.ProposedProjectID, it.ProposedMachineRef, it.ProposedRoleRef)
			if err != nil {
				return fmt.Errorf("reconcile grant %s/%s: %w", it.ProposedMachineRef, it.ProposedRoleRef, err)
			}
			if has {
				it.Outcome = Skip
			}
		case KindOIDCBinding:
			projectID := projectByMachineName[it.ProposedMachineRef]
			it.ProposedProjectID = projectID
			has, err := reader.MachineHasOIDCBinding(ctx, projectID, it.ProposedMachineRef, it.ProposedOIDCIssuer, it.ProposedOIDCSubject)
			if err != nil {
				return fmt.Errorf("reconcile oidc binding %s: %w", it.ProposedMachineRef, err)
			}
			if has {
				it.Outcome = Skip
			}
		}
	}
	return nil
}

// resolveNamedObject applies the by-name-then-provenance triad (internal/plan's existing
// pattern, applied here to Role/MachineIdentity) to one Create-outcome item in place.
func resolveNamedObject(it *Item, found bool, description string) {
	if !found {
		return // stays Create.
	}
	existingKey, hasProvenance := ParseProvenanceKey(description)
	if hasProvenance && existingKey == it.ProvenanceKey {
		it.Outcome = Skip
		return
	}
	it.Outcome = Conflict
	it.ConflictReason = fmt.Sprintf("a %s named %q already exists that this tool did not create — rename one side, or review and merge manually", it.Kind, it.ProposedName)
}

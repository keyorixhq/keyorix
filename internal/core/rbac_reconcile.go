// rbac_reconcile.go — idempotent, additive reconciliation of the canonical RBAC
// permission catalog on startup (ADR-044). BootstrapSystem seeds permissions once on
// first boot; this tops up an ALREADY-initialised install with any canonical
// permission added in a later release, granting it only to its baseline roles.
//
// Non-clobbering: it only ever CREATES missing permissions and grants those new ones
// to their canonical roles. Permissions that already exist are left entirely alone —
// no grant is added or removed — so an operator's grant customizations are preserved.
// The one exception is a (permission, role) pair still on the pending list below:
// that role's first grant of a newly-created permission has not landed yet, so
// it is retried until it has. A role that already received it is off the list.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rbacReconcilePendingRow is the system_metadata row holding the baseline
// grants this reconcile still owes, per (permission, role): a JSON object from
// permission name to the sorted names of the baseline roles that have not
// received it yet. It is written BEFORE the permissions are created, so a
// failed grant, a failed role read, or a stop between the create and the grants
// leaves the pair listed and the next startup retries exactly that pair. A role
// leaves a permission's list as soon as its grant lands, it is seen holding the
// permission, or it does not exist; it stays listed only on an error. A role off
// the list is never granted the permission again, so an operator who removes it
// from that role keeps it removed, even while another role's grant of the same
// permission keeps failing (REVIEW-4542-M1: the v1 row kept one entry per
// permission, and re-granted it to every baseline role until all had landed).
const rbacReconcilePendingRow = "rbac_reconcile_pending_grants_v2"

// rbacReconcileLegacyPendingRow is the v1 row: a JSON list of permission names
// with at least one grant owed, without saying to which roles. A baseline role
// that lacks such a permission may be one whose grant failed or one an operator
// stripped, and nothing tells the two apart. The v1 entries are therefore
// dropped, not granted (fail closed), and logged by name so an operator can
// grant a missed baseline permission by hand.
const rbacReconcileLegacyPendingRow = "rbac_reconcile_pending_grants_v1"

// rbacReconcileLockKey is the WithNamedLock key serialising
// ReconcileRBACPermissions across replicas: each run reads the pending row,
// grants, and writes the row back, so two replicas starting together could
// otherwise save a stale copy over a row the other one had already cleared.
const rbacReconcileLockKey = "rbac-permission-reconcile"

// ReconcileRBACPermissions creates any canonical permission missing from an
// initialised install and grants each newly-created permission to the canonical
// roles whose definition lists it. It is a no-op on a pre-bootstrap (empty) install
// — BootstrapSystem seeds those — and best-effort: errors are logged, never fatal,
// and a grant that fails is retried on the next startup (rbacReconcilePendingRow).
// The whole run holds rbacReconcileLockKey.
func (c *KeyorixCore) ReconcileRBACPermissions(ctx context.Context) error { // NOSONAR -- cognitive complexity, suppress go:S3776
	return c.storage.WithNamedLock(ctx, rbacReconcileLockKey, func(ctx context.Context) error {
		existing, err := c.storage.ListPermissions(ctx)
		if err != nil {
			return fmt.Errorf("rbac reconcile: list permissions: %w", err)
		}
		if len(existing) == 0 {
			return nil // not yet bootstrapped; first-boot seeding owns this
		}
		have := make(map[string]uint, len(existing))
		for _, p := range existing {
			have[p.Name] = p.ID
		}

		pending, err := c.loadRBACReconcilePending(ctx)
		if err != nil {
			return err
		}
		if err := c.dropLegacyRBACReconcilePending(ctx); err != nil {
			return err
		}
		var missing []string
		for _, def := range defaultPermissions {
			if _, ok := have[def.Name]; !ok {
				missing = append(missing, def.Name)
			}
		}
		if len(missing) > 0 {
			for _, name := range missing {
				for _, rdef := range defaultRoles {
					if slices.Contains(rdef.Permissions, name) {
						owePendingGrant(pending, name, rdef.Name)
					}
				}
			}
			// Record the debt before creating anything: if this write fails, nothing
			// has been created, and the next startup starts from the same state.
			if err := c.saveRBACReconcilePending(ctx, pending); err != nil {
				return err
			}
		}

		created := make([]string, 0, len(missing))
		for _, def := range defaultPermissions {
			if _, ok := have[def.Name]; ok {
				continue
			}
			p, err := c.storage.CreatePermission(ctx, &models.Permission{
				Name:        def.Name,
				Description: def.Description,
				Resource:    def.Resource,
				Action:      def.Action,
			})
			if err != nil {
				log.Printf("rbac reconcile: create permission %s: %v", def.Name, err)
				continue // stays pending; created again next startup
			}
			have[def.Name] = p.ID
			created = append(created, def.Name)
		}

		// Grant each owed (permission, role) pair whose permission now exists. Only
		// listed pairs are granted: an existing permission is never granted to a
		// role that is not listed for it. A listed role whose current definition no
		// longer names the permission is dropped, not granted.
		if len(pending) == 0 {
			return nil
		}
		for _, rdef := range defaultRoles {
			var owed []string
			for permName, roles := range pending {
				if _, ok := have[permName]; !ok || !roles[rdef.Name] {
					continue
				}
				if !slices.Contains(rdef.Permissions, permName) {
					settlePendingGrant(pending, permName, rdef.Name)
					continue
				}
				owed = append(owed, permName)
			}
			if len(owed) == 0 {
				continue
			}
			sort.Strings(owed)
			role, err := c.storage.GetRoleByName(ctx, rdef.Name)
			if err != nil || role == nil {
				if err != nil && !storage.IsRoleNotFound(err) {
					// The role may exist; we cannot tell. Keep its grants owed.
					log.Printf("rbac reconcile: read role %s: %v (its grants stay pending)", rdef.Name, err)
					continue
				}
				// Role not present in this install: nothing is owed to it.
				for _, permName := range owed {
					settlePendingGrant(pending, permName, rdef.Name)
				}
				continue
			}
			rolePerms, err := c.storage.GetRolePermissions(ctx, role.ID)
			if err != nil {
				log.Printf("rbac reconcile: read permissions of role %s: %v (its grants stay pending)", rdef.Name, err)
				continue
			}
			held := make(map[string]bool, len(rolePerms))
			for _, p := range rolePerms {
				held[p.Name] = true
			}
			for _, permName := range owed {
				if held[permName] {
					settlePendingGrant(pending, permName, rdef.Name)
					continue
				}
				// Routed through the audited core wrapper (actor 0 = system, the same
				// convention every other system-initiated grant uses) so this startup
				// top-up emits permission.assigned like every other permission grant
				// path, instead of leaving the tamper-evident audit chain silent (#293).
				if err := c.AssignPermissionToRole(ctx, 0, role.ID, have[permName], false); err != nil {
					log.Printf("rbac reconcile: grant %s to role %s: %v (stays pending)", permName, rdef.Name, err)
					continue
				}
				settlePendingGrant(pending, permName, rdef.Name)
			}
		}

		if err := c.saveRBACReconcilePending(ctx, pending); err != nil {
			// The grants themselves landed; a stale row only lists pairs whose
			// grant has landed, and the next startup skips every one it finds held.
			log.Printf("rbac reconcile: %v", err)
		}

		if len(created) > 0 {
			log.Printf("RBAC reconcile: added %d new permission(s) and granted them to baseline roles: %v", len(created), created)
		}
		if len(pending) > 0 {
			log.Printf("RBAC reconcile: %d permission(s) still owe baseline grants, retried next startup: %v", len(pending), sortedRBACNames(pending))
		}
		return nil
	})
}

// owePendingGrant lists role as still owed perm.
func owePendingGrant(pending map[string]map[string]bool, perm, role string) {
	if pending[perm] == nil {
		pending[perm] = make(map[string]bool)
	}
	pending[perm][role] = true
}

// settlePendingGrant takes role off perm's list, and perm off the row once no
// role is owed it.
func settlePendingGrant(pending map[string]map[string]bool, perm, role string) {
	delete(pending[perm], role)
	if len(pending[perm]) == 0 {
		delete(pending, perm)
	}
}

func sortedRBACNames[V any](set map[string]V) []string {
	return slices.Sorted(maps.Keys(set))
}

// loadRBACReconcilePending reads the pending-grants row. A missing row is an
// empty debt. A failed read is an error, so the run stops before creating
// anything rather than losing track of what it owes. An unreadable row is
// dropped like an unreadable v1 row (fail closed): it is logged by length,
// replaced with an empty debt, and nothing is granted from it, so the rest of
// the reconcile still runs on this and every later startup (review L1 of
// REVIEW-4542-M1). A pair it held is not retried; the log says to grant a
// missed baseline permission by hand.
func (c *KeyorixCore) loadRBACReconcilePending(ctx context.Context) (map[string]map[string]bool, error) {
	raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
	if err != nil {
		return nil, fmt.Errorf("rbac reconcile: read pending grants: %w", err)
	}
	pending := make(map[string]map[string]bool)
	if !found || raw == "" {
		return pending, nil
	}
	var owed map[string][]string
	if err := json.Unmarshal([]byte(raw), &owed); err != nil {
		log.Printf("RBAC reconcile: dropping an unreadable pending-grants row (%d bytes); nothing is granted from it. Grant any missed baseline permission by hand.", len(raw))
		if err := c.saveRBACReconcilePending(ctx, pending); err != nil {
			// Nothing is granted from the row either way; the next startup drops it again.
			log.Printf("rbac reconcile: %v", err)
		}
		return pending, nil
	}
	for perm, roles := range owed {
		for _, role := range roles {
			owePendingGrant(pending, perm, role)
		}
	}
	return pending, nil
}

// dropLegacyRBACReconcilePending empties the v1 row (rbacReconcileLegacyPendingRow)
// without granting anything from it, and logs the names it held. An unreadable
// v1 row is dropped the same way: nothing would be granted from it either.
func (c *KeyorixCore) dropLegacyRBACReconcilePending(ctx context.Context) error {
	raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcileLegacyPendingRow)
	if err != nil {
		return fmt.Errorf("rbac reconcile: read legacy pending grants: %w", err)
	}
	if !found || raw == "" || raw == "[]" {
		return nil
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil {
		log.Printf("RBAC reconcile: dropping an unreadable legacy pending-grants row (%d bytes); nothing is granted from it", len(raw))
	} else {
		log.Printf("RBAC reconcile: dropping legacy pending grants %v without granting them: the old format does not say which baseline roles were still owed, and a role without the permission may be one an operator removed it from. Grant any missed baseline permission by hand.", names)
	}
	if err := c.storage.SetSystemMetadata(ctx, rbacReconcileLegacyPendingRow, "[]"); err != nil {
		return fmt.Errorf("rbac reconcile: clear legacy pending grants: %w", err)
	}
	return nil
}

func (c *KeyorixCore) saveRBACReconcilePending(ctx context.Context, pending map[string]map[string]bool) error {
	owed := make(map[string][]string, len(pending))
	for perm, roles := range pending {
		owed[perm] = sortedRBACNames(roles)
	}
	data, err := json.Marshal(owed)
	if err != nil {
		return fmt.Errorf("rbac reconcile: encode pending grants: %w", err)
	}
	if err := c.storage.SetSystemMetadata(ctx, rbacReconcilePendingRow, string(data)); err != nil {
		return fmt.Errorf("rbac reconcile: record pending grants: %w", err)
	}
	return nil
}

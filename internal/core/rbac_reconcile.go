// rbac_reconcile.go — idempotent, additive reconciliation of the canonical RBAC
// permission catalog on startup (ADR-044). BootstrapSystem seeds permissions once on
// first boot; this tops up an ALREADY-initialised install with any canonical
// permission added in a later release, granting it only to its baseline roles.
//
// Non-clobbering: it only ever CREATES missing permissions and grants those new ones
// to their canonical roles. Permissions that already exist are left entirely alone —
// no grant is added or removed — so an operator's grant customizations are preserved.
// The one exception is a permission still on the pending list below: its first
// grants have not all landed yet, so they are retried until they have.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rbacReconcilePendingKey is the system_metadata key holding the JSON list of
// permission names this reconcile created (or is about to create) whose
// baseline grants have not all succeeded yet. It is written BEFORE the
// permissions are created, so a failed grant, a failed role read, or a stop
// between the create and the grants leaves the name listed and the next startup
// retries exactly those grants. A name leaves the list only once every grant it
// owes has landed; from then on it is an existing permission like any other and
// is never re-granted, so an operator who later removes the grant keeps it
// removed. Before this list existed a failed grant was only logged, and the next
// startup saw the permission as existing and skipped it for good.
const rbacReconcilePendingKey = "rbac_reconcile_pending_grants_v1"

// ReconcileRBACPermissions creates any canonical permission missing from an
// initialised install and grants each newly-created permission to the canonical
// roles whose definition lists it. It is a no-op on a pre-bootstrap (empty) install
// — BootstrapSystem seeds those — and best-effort: errors are logged, never fatal,
// and a grant that fails is retried on the next startup (rbacReconcilePendingKey).
func (c *KeyorixCore) ReconcileRBACPermissions(ctx context.Context) error { // NOSONAR -- cognitive complexity, suppress go:S3776
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
	var missing []string
	for _, def := range defaultPermissions {
		if _, ok := have[def.Name]; !ok {
			missing = append(missing, def.Name)
		}
	}
	if len(missing) > 0 {
		for _, name := range missing {
			pending[name] = true
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

	// grantable: every pending permission that now exists. Only these are granted;
	// an existing permission that is not pending is never touched.
	grantable := make(map[string]uint)
	for name := range pending {
		if id, ok := have[name]; ok {
			grantable[name] = id
		}
	}
	if len(grantable) == 0 {
		return nil
	}

	// Grant each grantable permission to the canonical roles that should hold it
	// (only roles that exist, only when the grant is missing). incomplete collects
	// every permission with at least one grant that did not land this run.
	incomplete := make(map[string]bool)
	for _, rdef := range defaultRoles {
		owed := make([]string, 0, len(rdef.Permissions))
		for _, permName := range rdef.Permissions {
			if _, ok := grantable[permName]; ok {
				owed = append(owed, permName)
			}
		}
		if len(owed) == 0 {
			continue
		}
		role, err := c.storage.GetRoleByName(ctx, rdef.Name)
		if err != nil || role == nil {
			if err != nil && !storage.IsRoleNotFound(err) {
				// The role may exist; we cannot tell. Keep its grants owed.
				log.Printf("rbac reconcile: read role %s: %v (its grants stay pending)", rdef.Name, err)
				markRBACIncomplete(incomplete, owed)
			}
			continue // role not present in this install: nothing is owed to it
		}
		rolePerms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			log.Printf("rbac reconcile: read permissions of role %s: %v (its grants stay pending)", rdef.Name, err)
			markRBACIncomplete(incomplete, owed)
			continue
		}
		held := make(map[string]bool, len(rolePerms))
		for _, p := range rolePerms {
			held[p.Name] = true
		}
		for _, permName := range owed {
			if held[permName] {
				continue
			}
			// Routed through the audited core wrapper (actor 0 = system, the same
			// convention every other system-initiated grant uses) so this startup
			// top-up emits permission.assigned like every other permission grant
			// path, instead of leaving the tamper-evident audit chain silent (#293).
			if err := c.AssignPermissionToRole(ctx, 0, role.ID, grantable[permName], false); err != nil {
				log.Printf("rbac reconcile: grant %s to role %s: %v (stays pending)", permName, rdef.Name, err)
				incomplete[permName] = true
			}
		}
	}

	for name := range grantable {
		if !incomplete[name] {
			delete(pending, name)
		}
	}
	if err := c.saveRBACReconcilePending(ctx, pending); err != nil {
		// The grants themselves landed; a stale list only means the next startup
		// re-checks them, and every grant it finds already held is skipped.
		log.Printf("rbac reconcile: %v", err)
	}

	if len(created) > 0 {
		log.Printf("RBAC reconcile: added %d new permission(s) and granted them to baseline roles: %v", len(created), created)
	}
	if len(incomplete) > 0 {
		log.Printf("RBAC reconcile: %d permission(s) still owe baseline grants, retried next startup: %v", len(incomplete), sortedRBACNames(incomplete))
	}
	return nil
}

func markRBACIncomplete(incomplete map[string]bool, names []string) {
	for _, n := range names {
		incomplete[n] = true
	}
}

func sortedRBACNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// loadRBACReconcilePending reads the pending-grants list. A missing key is an
// empty list; an unreadable one is an error, so the run stops before creating
// anything rather than losing track of what it owes.
func (c *KeyorixCore) loadRBACReconcilePending(ctx context.Context) (map[string]bool, error) {
	raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingKey)
	if err != nil {
		return nil, fmt.Errorf("rbac reconcile: read pending grants: %w", err)
	}
	pending := make(map[string]bool)
	if !found || raw == "" {
		return pending, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil {
		return nil, fmt.Errorf("rbac reconcile: decode pending grants %q: %w", raw, err)
	}
	for _, n := range names {
		pending[n] = true
	}
	return pending, nil
}

func (c *KeyorixCore) saveRBACReconcilePending(ctx context.Context, pending map[string]bool) error {
	data, err := json.Marshal(sortedRBACNames(pending))
	if err != nil {
		return fmt.Errorf("rbac reconcile: encode pending grants: %w", err)
	}
	if err := c.storage.SetSystemMetadata(ctx, rbacReconcilePendingKey, string(data)); err != nil {
		return fmt.Errorf("rbac reconcile: record pending grants: %w", err)
	}
	return nil
}

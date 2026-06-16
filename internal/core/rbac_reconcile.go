// rbac_reconcile.go — idempotent, additive reconciliation of the canonical RBAC
// permission catalog on startup (ADR-044). BootstrapSystem seeds permissions once on
// first boot; this tops up an ALREADY-initialised install with any canonical
// permission added in a later release, granting it only to its baseline roles.
//
// Non-clobbering: it only ever CREATES missing permissions and grants those new ones
// to their canonical roles. Permissions that already exist are left entirely alone —
// no grant is added or removed — so an operator's grant customizations are preserved.
package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ReconcileRBACPermissions creates any canonical permission missing from an
// initialised install and grants each newly-created permission to the canonical
// roles whose definition lists it. It is a no-op on a pre-bootstrap (empty) install
// — BootstrapSystem seeds those — and best-effort: errors are logged, never fatal.
func (c *KeyorixCore) ReconcileRBACPermissions(ctx context.Context) error {
	existing, err := c.storage.ListPermissions(ctx)
	if err != nil {
		return fmt.Errorf("rbac reconcile: list permissions: %w", err)
	}
	if len(existing) == 0 {
		return nil // not yet bootstrapped; first-boot seeding owns this
	}
	have := make(map[string]bool, len(existing))
	for _, p := range existing {
		have[p.Name] = true
	}

	created := make(map[string]uint)
	for _, def := range defaultPermissions {
		if have[def.Name] {
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
			continue
		}
		created[def.Name] = p.ID
	}
	if len(created) == 0 {
		return nil
	}

	// Grant each newly-created permission to the canonical roles that should hold it
	// (only roles that exist, only when the grant is missing). Existing permissions
	// are never re-granted here.
	for _, rdef := range defaultRoles {
		role, err := c.storage.GetRoleByName(ctx, rdef.Name)
		if err != nil || role == nil {
			continue // role not present in this install
		}
		rolePerms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			continue
		}
		held := make(map[string]bool, len(rolePerms))
		for _, p := range rolePerms {
			held[p.Name] = true
		}
		for _, permName := range rdef.Permissions {
			id, isNew := created[permName]
			if !isNew || held[permName] {
				continue
			}
			if err := c.storage.AssignPermissionToRole(ctx, role.ID, id); err != nil {
				log.Printf("rbac reconcile: grant %s to role %s: %v", permName, rdef.Name, err)
			}
		}
	}

	names := make([]string, 0, len(created))
	for name := range created {
		names = append(names, name)
	}
	log.Printf("RBAC reconcile: added %d new permission(s) and granted them to baseline roles: %v", len(created), names)
	return nil
}

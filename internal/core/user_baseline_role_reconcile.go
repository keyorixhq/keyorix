// user_baseline_role_reconcile.go — idempotent startup repair for an install
// bootstrapped before #2188 fixed the seeding-order bug in bootstrapSystemLocked
// (auth_bootstrap.go): every fresh install, on every backend, created its admin
// user before the "system_viewer" role row existed, so CreateUser's own
// best-effort auto-assign (ADR-021) deterministically missed on the very first
// user and only logged a non-fatal warning. #2188 fixes the ordering for NEW
// installs; this repairs installs that already ran the old ordering — v0.95.0
// and earlier, SQLite and PostgreSQL alike.
package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// userBaselineRoleReconcilePageSize bounds a single ListUsers page. Chosen well
// under the storage layer's own page-size ceiling (10000) so a very large
// install still reconciles in a handful of pages rather than one giant query.
const userBaselineRoleReconcilePageSize = 500

// ReconcileUserBaselineRoles grants every user the "system_viewer" baseline
// role (ADR-021) at global scope if they don't already hold it anywhere. It is
// the user-level counterpart to ReconcileRBACPermissions (rbac_reconcile.go):
// a no-op on a pre-bootstrap (empty) install — BootstrapSystem's own ordering
// fix (#2188) owns that case now — and additive-only on an initialised one.
//
// Never touches any role other than system_viewer, and never removes or
// modifies an existing grant — only ever grants the one baseline role to a
// user who is missing it. Idempotent: a user who already holds system_viewer
// (from a successful bootstrap, an explicit grant, or a prior run of this
// same reconcile) is left untouched, so running this on every startup is safe
// and a second run after a successful first run grants nothing.
//
// Soft-deleted users are skipped (ListUsers' default IncludeDeleted=false) —
// there is no operational reason to grant a baseline role to an account that
// is not usable.
//
// Best-effort per user: one user's grant failure (SoD conflict, storage
// error) is logged and does not stop the sweep or block startup, matching
// ReconcileRBACPermissions' own never-fatal contract.
func (c *KeyorixCore) ReconcileUserBaselineRoles(ctx context.Context) error {
	role, err := c.storage.GetRoleByName(ctx, "system_viewer")
	if err != nil || role == nil {
		return nil // not yet bootstrapped; first-boot seeding (as fixed by #2188) owns this
	}

	granted := 0
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{
			Page:     page,
			PageSize: userBaselineRoleReconcilePageSize,
		})
		if err != nil {
			return fmt.Errorf("baseline role reconcile: list users: %w", err)
		}

		for _, u := range users {
			roles, rerr := c.storage.GetUserRoles(ctx, u.ID)
			if rerr != nil {
				log.Printf("baseline role reconcile: list roles for user %d: %v", u.ID, rerr)
				continue
			}
			if userHoldsRole(roles, role.ID) {
				continue
			}
			if gerr := c.grantBaselineRoleBackfill(ctx, u.ID, role.ID); gerr != nil {
				log.Printf("baseline role reconcile: grant system_viewer to user %d: %v", u.ID, gerr)
				continue
			}
			granted++
		}

		if int64(page*userBaselineRoleReconcilePageSize) >= total || len(users) < userBaselineRoleReconcilePageSize {
			break
		}
	}

	if granted > 0 {
		log.Printf("Baseline role reconcile: granted system_viewer to %d user(s) missing it", granted)
	}
	return nil
}

func userHoldsRole(roles []*models.Role, roleID uint) bool {
	for _, r := range roles {
		if r.ID == roleID {
			return true
		}
	}
	return false
}

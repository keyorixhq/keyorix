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
	"encoding/json"
	"fmt"
	"log"
	"regexp"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// userBaselineRoleReconcilePageSize bounds a single ListUsers/GetAuditLogs
// page. Chosen well under the storage layer's own page-size ceiling (10000)
// so a very large install still reconciles in a handful of pages rather than
// one giant query.
const userBaselineRoleReconcilePageSize = 500

// userBaselineRoleBackfillMarkerKey is the system_metadata key (ADR-029's
// key/value store, local_system_metadata.go) recording that the one-time
// baseline-role backfill sweep below has already run. Coordinator review on
// #2195: running this sweep on EVERY startup silently undoes an admin's own
// deliberate removal of system_viewer from a user (RemoveUserRole permits
// it; nothing protected the baseline) and would override an SSO DefaultRole
// config that intentionally gives JIT-provisioned users a different
// baseline role than system_viewer — both because the sweep can't tell "this
// user was never granted the role because of the pre-#2188 bug" apart from
// "this user was never granted the role on purpose." The marker turns the
// repair into a single one-time pass over whatever the install looked like
// the first time it ran on the fixed code, never touching a user's role set
// again afterward; the SSO-JIT case additionally needs its own per-user skip
// (usersSSOJITNonDefaultRole below) because a non-default-role JIT account
// created DURING that one sweep would otherwise still get grafted onto by
// it, marker or no marker.
const userBaselineRoleBackfillMarkerKey = "baseline_role_backfill_v1"

// ReconcileUserBaselineRoles grants the "system_viewer" baseline role
// (ADR-021) at global scope to every user who doesn't already hold it, but
// only ONCE per install — see userBaselineRoleBackfillMarkerKey. It exists to
// repair an install bootstrapped before #2188 fixed the seeding-order bug
// that made every fresh install (any backend) miss the grant on its first
// user; #2188 itself owns every install bootstrapped after that fix, so this
// reconcile is a one-shot backfill, not an ongoing invariant enforcer.
//
// Never touches any role other than system_viewer, and never removes or
// modifies an existing grant. Three categories of user are left untouched
// even on the one sweep that does run:
//   - a user with a role.removed audit event for system_viewer (any scope) —
//     an admin's deliberate removal of it, which a repair sweep must not
//     undo;
//   - a user JIT-provisioned via SSO whose provider config sets a
//     DefaultRole other than system_viewer (sso.go) — that user never held
//     system_viewer because the install's own SSO config says so, not
//     because of the pre-#2188 bug this reconcile repairs;
//   - once the completion marker is set, EVERY user, unconditionally — a
//     later restart must not re-litigate role state the install may have
//     changed on purpose since the one-time repair ran.
//
// Soft-deleted users are skipped (ListUsers' default IncludeDeleted=false) —
// there is no operational reason to grant a baseline role to an account that
// is not usable.
//
// Best-effort per user within the one sweep: one user's grant failure (SoD
// conflict, storage error) is logged and does not stop the sweep or block
// startup, matching ReconcileRBACPermissions' own never-fatal contract. Note
// this means a user whose grant fails on the one sweep stays missing
// system_viewer permanently (the marker still gets set) — an accepted
// tradeoff of making this one-time rather than an ongoing top-up.
func (c *KeyorixCore) ReconcileUserBaselineRoles(ctx context.Context) error {
	if _, done, err := c.storage.GetSystemMetadata(ctx, userBaselineRoleBackfillMarkerKey); err != nil {
		return fmt.Errorf("baseline role reconcile: check completion marker: %w", err)
	} else if done {
		return nil
	}

	role, err := c.storage.GetRoleByName(ctx, "system_viewer")
	if err != nil || role == nil {
		return nil // not yet bootstrapped; first-boot seeding (as fixed by #2188) owns this — retry next startup, don't mark complete
	}

	removedFor, err := c.usersWithBaselineRoleRemoved(ctx, role.ID)
	if err != nil {
		return fmt.Errorf("baseline role reconcile: list role-removal history: %w", err)
	}
	ssoNonDefaultFor, err := c.usersSSOJITNonDefaultRole(ctx)
	if err != nil {
		return fmt.Errorf("baseline role reconcile: list SSO JIT non-default-role history: %w", err)
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
			if removedFor[u.ID] || ssoNonDefaultFor[u.ID] {
				continue
			}
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

	if err := c.storage.SetSystemMetadata(ctx, userBaselineRoleBackfillMarkerKey, "1"); err != nil {
		return fmt.Errorf("baseline role reconcile: record completion marker: %w", err)
	}
	return nil
}

// usersWithBaselineRoleRemoved returns the set of user IDs carrying a
// role.removed audit event for roleID at any scope — the signal
// ReconcileUserBaselineRoles uses to tell an admin's deliberate removal of
// the baseline role apart from a user who was simply never granted it (which
// is exactly what this reconcile exists to repair). Paginates
// role.removed-only events, so this stays far cheaper than scanning the
// whole audit log even on an install with a long history.
func (c *KeyorixCore) usersWithBaselineRoleRemoved(ctx context.Context, roleID uint) (map[uint]bool, error) {
	removed := make(map[uint]bool)
	for page := 1; ; page++ {
		events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
			Actions:  []string{EventRoleRemoved},
			Page:     page,
			PageSize: userBaselineRoleReconcilePageSize,
		})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			var d rbacAuditDetail
			if e.Diff == "" || json.Unmarshal([]byte(e.Diff), &d) != nil {
				continue
			}
			if d.RoleID == roleID && d.TargetUserID != 0 {
				removed[d.TargetUserID] = true
			}
		}
		if int64(page*userBaselineRoleReconcilePageSize) >= total || len(events) < userBaselineRoleReconcilePageSize {
			break
		}
	}
	return removed, nil
}

// usersSSOJITNonDefaultRole returns the set of user IDs JIT-provisioned via
// SSO (sso.go's provisionSSOUser) whose provider config set a DefaultRole
// other than system_viewer — the second category ReconcileUserBaselineRoles
// must never touch, alongside usersWithBaselineRoleRemoved: such a user
// never held system_viewer because the install's own SSO config says so, not
// because of the pre-#2188 bug this reconcile repairs. Reads the structured
// Diff (ssoJITProvisionDetail) each auth.sso_jit_provisioned event carries,
// not the event's free-text Description — the same choice
// usersWithBaselineRoleRemoved makes for role.removed events, for the same
// reason: a machine-checked field, not a string a future log-message edit
// could silently break.
func (c *KeyorixCore) usersSSOJITNonDefaultRole(ctx context.Context) (map[uint]bool, error) {
	skip := make(map[uint]bool)
	for page := 1; ; page++ {
		events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
			Actions:  []string{EventSSOJITProvision},
			Page:     page,
			PageSize: userBaselineRoleReconcilePageSize,
		})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			if e.UserID == nil {
				continue
			}
			var d ssoJITProvisionDetail
			if e.Diff != "" && json.Unmarshal([]byte(e.Diff), &d) == nil {
				if d.NonDefaultRole {
					skip[*e.UserID] = true
				}
				continue
			}
			// Legacy event (written before the structured Diff existed): every
			// install this one-time backfill exists to repair predates it, so the
			// Description's own "role=<name>)" suffix is the only record of which
			// role the provider config granted. Historical rows never change
			// format, so parsing them is stable. Fail toward skipping: an
			// unparseable legacy row is treated as non-default (never grant
			// system_viewer on top of a role we can't identify).
			if m := legacySSOJITRoleRe.FindStringSubmatch(e.Description); m == nil || m[1] != ssoDefaultRole {
				skip[*e.UserID] = true
			}
		}
		if int64(page*userBaselineRoleReconcilePageSize) >= total || len(events) < userBaselineRoleReconcilePageSize {
			break
		}
	}
	return skip, nil
}

// legacySSOJITRoleRe extracts the role name from a pre-structured-Diff
// auth.sso_jit_provisioned Description: "SSO JIT-provisioned user %d via %s
// (externalId=%q, role=%s)".
var legacySSOJITRoleRe = regexp.MustCompile(`, role=(.*)\)$`)

func userHoldsRole(roles []*models.Role, roleID uint) bool {
	for _, r := range roles {
		if r.ID == roleID {
			return true
		}
	}
	return false
}

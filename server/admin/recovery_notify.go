// recovery_notify.go implements design-b2-recover-admin.md §4's "notify
// admins" requirement, shared by `recovery-key rotate` and `recover-admin` —
// both are exactly the kind of event every admin should see. Decision taken
// for the notification question (design §9 review addendum 7, "the simple
// path"): in-app Notification rows written directly, no outbox. Best-effort
// SMTP is NOT implemented here — server/admin has no wired email-channel
// client (that lives in internal/core/service.go's NotificationSink set,
// constructed only inside a running server process); adding one is sized as
// a small, explicit follow-up, not silently promised and skipped.
package admin

import (
	"context"
	"fmt"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// notifyAllAdmins writes an in-app Notification row for every currently
// active global-admin user. Best-effort: a notification failure never fails
// the caller's own action (the action already happened, or didn't, on its
// own terms) -- only downgrades to a printed note, matching
// recordAdminAction's own convention.
func notifyAllAdmins(store corestorage.Storage, title, message string) {
	ctx := context.Background()
	adminIDs, err := listGlobalAdminUserIDs(ctx, store)
	if err != nil {
		fmt.Printf("note: could not enumerate admins to notify (%v)\n", err)
		return
	}
	for _, id := range adminIDs {
		_, err := store.CreateNotification(ctx, &models.Notification{
			UserID:   id,
			Type:     "admin.recovery_event",
			Title:    title,
			Message:  message,
			Severity: models.NotificationSeverityCritical,
		})
		if err != nil {
			fmt.Printf("note: could not write in-app notification for admin user %d (%v)\n", id, err)
		}
	}
}

// listGlobalAdminUserIDs enumerates every ACTIVE user currently holding a
// global-admin role, direct or group-derived -- the same structural check
// core.targetHasGlobalAdminRole uses (ADR-084's BypassesPermissionChecks
// flag on the role, internal/core/authz.go), applied per-user over a paged
// ListUsers scan rather than core.resolveGlobalAdminHolders' assignment-
// expansion approach, since server/admin has no core.KeyorixCore instance
// to call that on (see admin.go's package doc: admin commands use the
// storage factory directly, never construct a full core). O(active users)
// storage calls -- acceptable here: this runs once per rotate/recovery
// event, not on a request hot path.
func listGlobalAdminUserIDs(ctx context.Context, store corestorage.Storage) ([]uint, error) {
	const pageSize = 200
	active := true
	var admins []uint
	for page := 1; ; page++ {
		users, total, err := store.ListUsers(ctx, &corestorage.UserFilter{
			IsActive: &active,
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("list users (page %d): %w", page, err)
		}
		for _, u := range users {
			isAdmin, err := userHoldsGlobalAdminRole(ctx, store, u.ID)
			if err != nil {
				return nil, fmt.Errorf("check admin role for user %d: %w", u.ID, err)
			}
			if isAdmin {
				admins = append(admins, u.ID)
			}
		}
		if len(users) == 0 || page*pageSize >= int(total) {
			break
		}
	}
	return admins, nil
}

// userHoldsGlobalAdminRole reports whether userID currently holds a role
// (direct or group-inherited) with the structural BypassesPermissionChecks
// flag (ADR-084) at global scope.
func userHoldsGlobalAdminRole(ctx context.Context, store corestorage.Storage, userID uint) (bool, error) {
	direct, err := store.GetUserRoleIDsAt(ctx, userID, corestorage.Scope{})
	if err != nil {
		return false, err
	}
	viaGroups, err := store.GetUserGroupRoleIDsAt(ctx, userID, corestorage.Scope{})
	if err != nil {
		return false, err
	}
	roleIDs := append(direct, viaGroups...)
	if len(roleIDs) == 0 {
		return false, nil
	}
	return store.RoleSetBypassesPermissionChecks(ctx, roleIDs)
}

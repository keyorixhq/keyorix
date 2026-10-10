package admin

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestPerformRecoverAdmin_SSOOnlyLastAdminWithNoPassword (#2903 finding 5b):
// recover-admin is one of the two documented ways back when SSO reconcile
// refuses the install's last administrator's login (the IdP revoked their admin
// group, the last-admin guard refused the removal, and the login stays refused
// -- Andrei, 2026-10-10). That administrator is typically a JIT-provisioned SSO
// account: a provider-scoped external id, NO password hash, and admin held
// through a GROUP rather than a direct grant. None of the existing
// recover-admin tests has that shape -- seedAdminUser always sets a password
// and grants the role directly -- so whether the documented way back works for
// the case it is now documented for was unproven.
//
// Drives the documented sequence end to end through internal/core: recover-admin
// -> log in with the printed one-time password -> forced password change -> log
// in with the new password, still an administrator.
func TestPerformRecoverAdmin_SSOOnlyLastAdminWithNoPassword(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)

	usernameFolded, err := identity.NewFoldedName("ada")
	if err != nil {
		t.Fatalf("fold username: %v", err)
	}
	emailFolded, err := identity.NewFoldedName("ada@corp.example")
	if err != nil {
		t.Fatalf("fold email: %v", err)
	}
	user, err := store.CreateUser(ctx, &models.User{
		Username: "ada", UsernameFolded: usernameFolded.Folded(),
		Email: "ada@corp.example", EmailFolded: emailFolded.Folded(),
		ExternalID:   "sso:corp:corp|123", // JIT-provisioned, provider-scoped
		PasswordHash: "",                  // SSO-only: never had a password
		IsActive:     true, AccountState: "active",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Admin held ONLY through the IdP-synced group, as an SSO install has it.
	roleName, err := identity.NewFoldedName("global-admin-sso")
	if err != nil {
		t.Fatalf("fold role name: %v", err)
	}
	role, err := store.CreateRole(ctx, roleName, "test admin role")
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := store.SetRoleBypassesPermissionChecks(ctx, role.ID, true); err != nil {
		t.Fatalf("set bypass: %v", err)
	}
	group, err := store.CreateGroup(ctx, &models.Group{Name: "idp-admins"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := store.AssignRoleToGroup(ctx, group.ID, role.ID, storage.Scope{}); err != nil {
		t.Fatalf("grant role to group: %v", err)
	}
	if err := store.AddUserToGroup(ctx, user.ID, group.ID, 0); err != nil {
		t.Fatalf("add user to group: %v", err)
	}
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("recover-admin refused the SSO-only last administrator: %v", err)
	}
	if summary.oneTimePassword == "" {
		t.Fatalf("no one-time password printed")
	}

	c := core.NewKeyorixCore(store)
	loggedIn, err := c.VerifyPasswordCredentials(ctx, user.Username, summary.oneTimePassword)
	if err != nil {
		t.Fatalf("an SSO-only account could not log in with the recover-admin one-time password: %v", err)
	}
	if loggedIn.AccountState != "password_reset_required" {
		t.Fatalf("AccountState = %q, want password_reset_required", loggedIn.AccountState)
	}

	const newPassword = "Recovered-SSO-Adm1n-Passw0rd!-2026"
	if err := c.ChangePassword(ctx, user.ID, summary.oneTimePassword, newPassword, ""); err != nil {
		t.Fatalf("forced password change failed for the SSO-only account: %v", err)
	}
	relogged, err := c.VerifyPasswordCredentials(ctx, user.Username, newPassword)
	if err != nil {
		t.Fatalf("login with the new password failed: %v", err)
	}
	if relogged.AccountState == "password_reset_required" {
		t.Errorf("AccountState still password_reset_required after a real password change")
	}

	// Admin access is what was being restored: the account must still hold it.
	isAdmin, err := userHoldsGlobalAdminRole(ctx, store, user.ID)
	if err != nil {
		t.Fatalf("check admin role: %v", err)
	}
	if !isAdmin {
		t.Errorf("the recovered account no longer holds global admin")
	}
}

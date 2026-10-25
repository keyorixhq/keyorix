package core

// sso_jit_default_role_scope_test.go — #3546 review (MERGE-MASTER, #3585):
// the SSO JIT default_role scope check ran on a pre-read outside the
// provisioning transaction and was SKIPPED when that read failed; the
// transaction then re-read the role and granted it at the global scope with no
// check. A transient read error, or a role narrowed between the two reads,
// made every JIT user hold a project-only role in every project. The check now
// runs on the transaction's own read, before any write, and a failed read
// refuses the provision.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// jitGrantsAndUser reports whether a user with email exists and how many grant
// rows the install holds (users and groups).
func jitGrantsAndUser(t *testing.T, w *roleScopeWorld, email string) (bool, []string) {
	t.Helper()
	_, err := w.c.storage.GetUserByEmail(context.Background(), email)
	return err == nil, w.grantRows(t)
}

// TestProvisionSSOUser_DefaultRoleReadErrorFailsClosed: the first
// GetRoleByName of the provision fails. Before the fix that was the pre-read,
// whose error skipped the scope check, so the transaction's second read
// granted project_developer install-wide. Now the provision is refused and
// nothing is written.
func TestProvisionSSOUser_DefaultRoleReadErrorFailsClosed(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	ctx := context.Background()
	before := w.grantRows(t)

	fs := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "GetRoleByName", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetRoleByName"),
	})
	real := c.storage
	c.storage = fs
	_, err := c.provisionSSOUser(ctx, &SSOProvider{Name: "okta", AutoProvision: true, DefaultRole: "project_developer"},
		"okta|frank", "frank@example.com", true, "Frank")
	c.storage = real

	require.True(t, fs.Fired(), "the role read must have been attempted and faulted")
	require.Error(t, err, "a failed default_role read must refuse the provision")
	exists, after := jitGrantsAndUser(t, w, "frank@example.com")
	require.False(t, exists, "no JIT user may be created behind an unread default_role")
	require.ElementsMatch(t, before, after, "no grant row may be written")

	// Calibration: without the fault the same provision is refused for its scope.
	_, err = c.provisionSSOUser(ctx, &SSOProvider{Name: "okta", AutoProvision: true, DefaultRole: "project_developer"},
		"okta|frank", "frank@example.com", true, "Frank")
	require.ErrorIs(t, err, ErrRoleScopeInvalid)
}

// narrowOnTx returns c.storage wrapped so that a role is narrowed to
// project-only when the provisioning transaction opens: the shape of an
// administrator's UpdateRole landing between an earlier read of the role and
// the grant.
func narrowOnTx(inner storage.Storage, roleID uint) storage.Storage {
	done := false
	return hooked(inner, &storeHooks{WithTransaction: func(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error {
		if !done {
			done = true
			if err := next.SetRoleAssignableScope(ctx, roleID, models.RoleAssignableProject); err != nil {
				return err
			}
		}
		return next.WithTransaction(ctx, fn)
	}})
}

// TestProvisionSSOUser_DefaultRoleNarrowedBeforeGrantIsRefused: a custom
// default_role assignable anywhere is narrowed to project-only before the
// grant. The check must see the narrowed role (the row the grant uses), not a
// stale earlier read. Before the fix the pre-read saw "any" and the
// transaction granted the now project-only role install-wide.
func TestProvisionSSOUser_DefaultRoleNarrowedBeforeGrantIsRefused(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	ctx := context.Background()
	p := &SSOProvider{Name: "okta", AutoProvision: true, DefaultRole: w.customAny.Name}

	// Positive control: while the role is assignable anywhere, JIT works.
	u, err := c.provisionSSOUser(ctx, p, "okta|gina", "gina@example.com", true, "Gina")
	require.NoError(t, err)
	require.Contains(t, w.grantRows(t), fmtGrant("user", u.ID, w.customAny.ID, 0, 0))

	before := w.grantRows(t)
	real := c.storage
	c.storage = narrowOnTx(real, w.customAny.ID)
	_, err = c.provisionSSOUser(ctx, p, "okta|hank", "hank@example.com", true, "Hank")
	c.storage = real

	require.ErrorIs(t, err, ErrRoleScopeInvalid, "a default_role narrowed to project-only must refuse the provision")
	exists, after := jitGrantsAndUser(t, w, "hank@example.com")
	require.False(t, exists, "no JIT user may be created behind a refused default_role")
	require.ElementsMatch(t, before, after, "no grant row may be written")
}

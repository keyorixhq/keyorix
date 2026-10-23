package core

// sso_jit_default_role_scope_test.go — #3546 backport (v0.96) of the #3585
// review fix: SSO JIT provisioning resolves and scope-checks default_role on
// the provisioning transaction's own read, before any write, and a failed read
// refuses the provision. On v0.96 the check is by name (no stored scope), so
// the earlier pre-transaction shape was not fail-open here; this pins the
// same fail-closed shape as main so the two cannot drift.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestProvisionSSOUser_DefaultRoleReadErrorFailsClosed(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	ctx := context.Background()
	before := w.grantRows(t)
	p := &SSOProvider{Name: "okta", AutoProvision: true, DefaultRole: "system_viewer"}

	fs := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "GetRoleByName", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: GetRoleByName"),
	})
	real := c.storage
	c.storage = fs
	_, err := c.provisionSSOUser(ctx, p, "okta|frank", "frank@example.com", true, "Frank")
	c.storage = real

	require.True(t, fs.Fired(), "the role read must have been attempted and faulted")
	require.Error(t, err, "a failed default_role read must refuse the provision")
	_, uerr := c.storage.GetUserByEmail(ctx, "frank@example.com")
	require.Error(t, uerr, "no JIT user may be created behind an unread default_role")
	require.ElementsMatch(t, before, w.grantRows(t), "no grant row may be written")

	// Calibration: without the fault the same provision succeeds.
	_, err = c.provisionSSOUser(ctx, p, "okta|frank", "frank@example.com", true, "Frank")
	require.NoError(t, err)
}

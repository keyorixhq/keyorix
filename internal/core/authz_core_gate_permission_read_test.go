// authz_core_gate_permission_read_test.go — #4161 review (REVIEW-4558-DEEP-1 LOW):
// requireActorHoldsPermissions classifies a failed permission read like the role
// reads of the same gate.
package core

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCoreGateParity_UpdateRolePermissionReadFaultAnswersRetry: a read FAULT on a
// permission the update bundles answers retry (ErrStorageReadUnavailable), like
// the role reads of the same gate, not "not found"; a permission that does not
// exist still answers not found.
func TestCoreGateParity_UpdateRolePermissionReadFaultAnswersRetry(t *testing.T) {
	t.Parallel()
	w := newParityWorld(t)
	ctx := w.ctx
	target := w.customRole("parity-role-fault")
	update := func(permIDs ...uint) error {
		_, _, err := w.c.UpdateRole(ctx, w.admin, &models.Role{ID: target.ID, Name: target.Name, Description: "d"}, &permIDs)
		return err
	}

	base := w.c.storage
	faulty := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetPermission", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("connection reset by peer"),
	})
	w.c.storage = faulty
	err := update(w.permissionID("secrets.read"))
	w.c.storage = base
	require.True(t, faulty.Fired(), "the fault must fire on the permission read")
	require.ErrorIs(t, err, ErrStorageReadUnavailable, "a permission read fault must answer retry")

	err = update(999999)
	require.ErrorIs(t, err, storage.ErrPermissionNotFound)
	require.NotErrorIs(t, err, ErrStorageReadUnavailable, "a missing permission is not a read fault")
}

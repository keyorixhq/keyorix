package http

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestUpdateUserRolesHTTP_CeilingReadFault_Is503 is #3938 over PUT
// /api/v1/users/{id}/roles: the grant ceiling's read of the actor's own grants (the
// self-replacement pre-check, ListUserRoleGrants) fails with a storage fault. The
// actor was not judged and nothing committed, so the answer is the family's 503
// storage_unavailable with Retry-After, not a 403 refusal and not a 500.
func TestUpdateUserRolesHTTP_CeilingReadFault_Is503(t *testing.T) {
	var fs *faultstorage.FaultyStorage
	w := newRoleScopeHTTPWorldOn(t, func(st corestorage.Storage) corestorage.Storage {
		fs = faultstorage.NewFaultyStorage(st, nil)
		return fs
	})
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
	require.NoError(t, w.db.Create(&models.User{ID: 4, Username: "admin2", Email: "admin2@test.com", IsActive: true, AccountState: "active"}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error) // second global admin
	require.NoError(t, w.db.Create(&models.Role{ID: 12, Name: "viewer", NameFolded: "viewer"}).Error)

	before := w.userGrants(t, 2)
	fs.Arm(&faultstorage.FaultSpec{Method: "ListUserRoleGrants", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: grants read failed")})
	status, body := w.put(t, "/api/v1/users/2/roles", `{"role_ids":[12],"project_id":0}`)
	require.True(t, fs.Fired(), "the fault must fire inside the core's self-replacement pre-check")
	fs.Arm(nil)

	require.Equal(t, http.StatusServiceUnavailable, status, body)
	require.Contains(t, body, "storage_unavailable", body)
	require.NotContains(t, body, "MutationPartiallyApplied", "nothing committed")
	require.NotContains(t, body, "injected", "the driver cause stays in the server log")
	require.Equal(t, before, w.userGrants(t, 2), "nothing may change")
}

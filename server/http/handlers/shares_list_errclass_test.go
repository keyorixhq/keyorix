// shares_list_errclass_test.go — GET /api/v1/secrets/{id}/shares: every error from
// core.ListSecretSharesWithPermissionCheck maps to a declared status (#4653). The
// strict stateful fuzz saw `500 Failed to list secret shares`; the cause reproduced
// here is an expired secret (core.ErrSecretExpired, in no errclass class, fell to the
// legacy switch's `default: 500`).
package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// listSharesFixture seeds a project, a secret owned by user 1 (the identity
// withUserCtx injects) and the project-scoped role requireLiveOwnerAuthority needs,
// and returns a handler over a FaultyStorage wrapping the same database.
func listSharesFixture(t *testing.T, mutate func(*models.SecretNode)) (*ShareHandler, *faultstorage.FaultyStorage, *models.SecretNode) {
	t.Helper()
	_, db := freshCoreS26WithAdmin(t)

	proj := &models.Project{Name: "list-shares-errclass-proj"}
	require.NoError(t, db.Create(proj).Error)
	secret := &models.SecretNode{
		ProjectID: proj.ID,
		Name:      "list-shares-errclass-secret",
		IsSecret:  true,
		Status:    "active",
		OwnerID:   1,
	}
	if mutate != nil {
		mutate(secret)
	}
	require.NoError(t, db.Create(secret).Error)

	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID, ProjectID: proj.ID}).Error)

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err := NewShareHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	return h, faulty, secret
}

func listSharesDo(h *ShareHandler, id string) *httptest.ResponseRecorder {
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+id+"/shares", nil),
		"id", id,
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	return w
}

func TestListSecretShares_ErrorClasses(t *testing.T) {
	past := time.Now().Add(-time.Hour)

	cases := []struct {
		name   string
		mutate func(*models.SecretNode)
		// fault arms a storage fault on this method before the request ("" = none); the
		// answer is then the shared 503 storage_unavailable and wantStatus is unused.
		fault string
		// id overrides the secret id in the URL ("" = the seeded secret).
		id         string
		wantStatus int
		wantError  string
	}{
		{name: "owner lists shares", wantStatus: http.StatusOK},
		{name: "absent secret is 404", id: "999999", wantStatus: http.StatusNotFound, wantError: "NotFound"},
		{name: "expired secret is 404, not 500 (#4653)", mutate: func(s *models.SecretNode) { s.Expiration = &past },
			wantStatus: http.StatusNotFound, wantError: "NotFound"},
		{name: "non-owner is 403", mutate: func(s *models.SecretNode) { s.OwnerID = 2 },
			wantStatus: http.StatusForbidden, wantError: "Forbidden"},
		{name: "zero id is a validation 400", id: "0", wantStatus: http.StatusBadRequest, wantError: "ValidationError"},
		{name: "secret read fault is 503", fault: "GetSecret"},
		{name: "membership read fault is 503", fault: "IsProjectMember"},
		{name: "share list read fault is 503", fault: "ListSharesBySecret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, faulty, secret := listSharesFixture(t, tc.mutate)
			id := tc.id
			if id == "" {
				id = fmt.Sprint(secret.ID)
			}
			if tc.fault != "" {
				faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
			}
			w := listSharesDo(h, id)
			if tc.fault != "" {
				require.True(t, faulty.Fired(), "the %s read must be reached", tc.fault)
				assert.NotContains(t, w.Body.String(), "cache_epoch", "the driver cause must not reach the client")
				requireStorageUnavailable503(t, w)
				return
			}
			require.Equal(t, tc.wantStatus, w.Code, "body=%s", w.Body.String())
			if tc.wantError != "" {
				assert.Equal(t, tc.wantError, decodeShareResponse(t, w)["error"])
			}
		})
	}
}

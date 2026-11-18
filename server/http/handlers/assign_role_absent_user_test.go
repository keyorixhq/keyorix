package handlers

// assign_role_absent_user_test.go — ERRMAP-TAILS-NOV-4 item 3. POST /user-roles for a user
// id that does not exist answered 201 and wrote an orphan user_roles row plus a
// role.assigned audit row for nobody (UserRole has no foreign key). The grant is now
// refused 404 AFTER the grant ceiling is judged, so an actor who may not grant the role
// gets the same 403 for an absent and an existing target (OWNERSHIP-ORACLE-1: the answer
// must not tell which user ids exist). A fault reading the target is the shared 503.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestAssignRole_AbsentTargetUser(t *testing.T) {
	_, db := freshCoreS12WithAdmin(t)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewRBACHandler(core.NewKeyorixCore(faulty))

	role := &models.Role{Name: "absent-target-role", Description: "d", AssignableScope: models.RoleAssignableAny}
	require.NoError(t, db.Create(role).Error)
	existing := &models.User{Username: "absent-target-existing", Email: "absent-target-existing@example.test", AccountState: "active"}
	require.NoError(t, db.Create(existing).Error)
	plain := &models.User{Username: "absent-target-plain", Email: "absent-target-plain@example.test", AccountState: "active"}
	require.NoError(t, db.Create(plain).Error)
	const absent = uint(999999)

	assign := func(actor, target uint, expires bool) *httptest.ResponseRecorder {
		payload := map[string]any{"user_id": target, "role_id": role.ID}
		if expires {
			payload["expires_at"] = "2099-01-01T00:00:00Z"
		}
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewReader(body)), actor, "actor")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.AssignRole(w, req)
		return w
	}
	grants := func(user uint) int64 {
		var n int64
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ?", user).Count(&n).Error)
		return n
	}
	require.EqualValues(t, 1, secretsAdminID, "freshCoreS12WithAdmin makes user 1 the global admin")

	for _, expires := range []bool{false, true} {
		name := map[bool]string{false: "permanent", true: "time-bound"}[expires]
		t.Run("an authorized actor is refused 404 for an absent user ("+name+")", func(t *testing.T) {
			w := assign(secretsAdminID, absent, expires)
			assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
			assert.Zero(t, grants(absent), "no orphan grant row")
		})
	}

	t.Run("an actor who may not grant the role gets one answer for every target", func(t *testing.T) {
		wAbsent := assign(plain.ID, absent, false)
		wExisting := assign(plain.ID, existing.ID, false)
		assert.Equal(t, http.StatusForbidden, wExisting.Code, wExisting.Body.String())
		assert.Equal(t, wExisting.Code, wAbsent.Code)
		assert.Equal(t, wExisting.Body.String(), wAbsent.Body.String(), "the refusal must not say whether the user exists")
		assert.Zero(t, grants(absent))
		assert.Zero(t, grants(existing.ID))
	})

	t.Run("a fault reading the target is 503, and the grant is not written", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
		w := assign(secretsAdminID, existing.ID, false)
		fired := faulty.Fired()
		faulty.Arm(nil)
		require.True(t, fired, "the GetUser read fault must be reached")
		requireStorageUnavailable503(t, w)
		assert.Zero(t, grants(existing.ID))
	})

	t.Run("an existing user is still assigned 201", func(t *testing.T) {
		w := assign(secretsAdminID, existing.ID, false)
		assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		assert.EqualValues(t, 1, grants(existing.ID))
	})
}

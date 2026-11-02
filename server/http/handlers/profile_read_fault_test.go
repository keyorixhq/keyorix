package handlers

// profile_read_fault_test.go — AUTH-ENDPOINT-OUTAGE-1 item 1.
//
// GET /auth/profile reads the caller's own user row. A storage READ fault on that
// read used to answer 404 "User not found", telling a signed-in user that their
// account does not exist while the database was merely unreachable. It is now 503
// + Retry-After with the storage_unavailable code; a true not-found (row gone) and
// a machine principal (UserID 0, no user row by construction) keep their 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func profileReq(uc *middleware.UserContext) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/profile", nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

func TestProfile_GetUserReadFaultIs503NotFound404(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxprofilefault_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewAuthHandler(core.NewKeyorixCore(faulty), false)

	user := &models.User{Username: "profile-fault", Email: "profile-fault@example.com", IsActive: true}
	require.NoError(t, db.Create(user).Error)
	self := &middleware.UserContext{UserID: user.ID, Username: user.Username, ActorType: core.ActorTypeUser}

	t.Run("a GetUser read fault answers 503 + Retry-After, never 404", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		defer faulty.Arm(nil)
		w := httptest.NewRecorder()
		h.Profile(w, profileReq(self))
		require.True(t, faulty.Fired(), "the GetUser fault must be reached")
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, "a read fault is not 'user not found': %s", w.Body.String())
		assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
		var body suErrBody
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, storageUnavailableCode, body.Error)
		assert.Equal(t, core.StorageReadUnavailableMessage, body.Message)
		assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
	})

	t.Run("the same request without a fault is 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.Profile(w, profileReq(self))
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})

	t.Run("a deleted user row is still 404", func(t *testing.T) {
		gone := &middleware.UserContext{UserID: user.ID + 1000, Username: "gone", ActorType: core.ActorTypeUser}
		w := httptest.NewRecorder()
		h.Profile(w, profileReq(gone))
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		assert.Empty(t, w.Header().Get("Retry-After"))
	})

	t.Run("a machine principal (UserID 0) is still 404 and reads nothing", func(t *testing.T) {
		mid := uint(7)
		machine := &middleware.UserContext{UserID: 0, MachineIdentityID: &mid, ActorType: core.ActorTypeMachine, Username: "m"}
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
		defer faulty.Arm(nil)
		w := httptest.NewRecorder()
		h.Profile(w, profileReq(machine))
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		assert.Empty(t, w.Header().Get("Retry-After"))
	})
}

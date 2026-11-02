package handlers

// mfa_stepup_user_read_fault_test.go — AUTH-ENDPOINT-OUTAGE-1 item 3 (#3873 step-up rows).
//
// POST /api/v1/auth/mfa/stepup first reads the caller's own account (GetUser), before
// any code is evaluated. A storage fault there was folded into "user not found" and
// answered 401, a verdict on a credential that was never judged (oracle (h)). It now
// answers 503 + Retry-After (storage_unavailable) and hands the per-IP slot back, as a
// pre-verdict fault does. Nothing is confirmed by it: the account is the caller's own
// and no code was looked at. A gone account keeps its 401.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func TestMFAStepUp_GetUserReadFaultIs503AndHandsTheSlotBack(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxstepupuserfault_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewAuthHandler(core.NewKeyorixCore(faulty), false)

	user := &models.User{Username: "stepup-fault", Email: "stepup-fault@example.com", IsActive: true, AccountState: core.AccountActive, MFAEnabled: true}
	require.NoError(t, db.Create(user).Error)

	post := func(userID uint, kind *faultstorage.FaultKind) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/stepup", strings.NewReader(`{"code":"123456"}`))
		r.RemoteAddr = "198.51.100.7:4000"
		uc := &middleware.UserContext{UserID: userID, Username: "stepup-fault", ActorType: core.ActorTypeUser, SessionAuth: true}
		r = r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
		if kind != nil {
			faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: *kind, Err: assert.AnError})
			defer faulty.Arm(nil)
		}
		w := httptest.NewRecorder()
		h.MFAStepUp(w, r)
		if kind != nil {
			require.True(t, faulty.Fired(), "the GetUser fault must be reached")
		}
		return w
	}
	slots := func() int64 {
		var n int64
		require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
		return n
	}

	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
		t.Run(kind.String(), func(t *testing.T) {
			before := slots()
			w := post(user.ID, &kind)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "no code was evaluated, so this is not a verdict: %s", w.Body.String())
			assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
			var body suErrBody
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, storageUnavailableCode, body.Error)
			assert.NotContains(t, w.Body.String(), assert.AnError.Error())
			assert.Equal(t, before, slots(), "a pre-verdict fault hands the per-IP slot back")
		})
	}

	t.Run("a gone account is still a 401", func(t *testing.T) {
		w := post(user.ID+1000, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		assert.Empty(t, w.Header().Get("Retry-After"))
	})
}

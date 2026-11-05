package handlers

// auth_lane_user_read_fault_test.go — AUTH-LANE-FOLDS-1 item 2.
//
// The MFA and passkey account endpoints read the caller's own account (GetUser) before
// any code, password or passkey is evaluated. A storage fault there was folded into
// "user not found" and answered 400. It now answers 503 + Retry-After
// (storage_unavailable) with the sentinel's fixed text, never the storage error, and a
// credential-checking endpoint hands its per-IP slot back (pre-verdict). The request is
// refused either way. FinishWebAuthnRegistration / FinishWebAuthnReauth answer through
// the same writeWebAuthnErr (TestWriteWebAuthnErr_StorageReadFaultIs503).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func assertStorageUnavailable503(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "a faulted account read is not a verdict: %s", w.Body.String())
	assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
	var body suErrBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, storageUnavailableCode, body.Error)
	assert.Equal(t, core.StorageReadUnavailableMessage, body.Message)
	assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "no storage text in the response body")
	assert.NotContains(t, w.Body.String(), "not found")
}

func TestAuthLaneEndpoints_GetUserReadFaultIs503(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxauthlaneuserfault_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	c := core.NewKeyorixCore(faulty)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	c.SetAuthEncryptor(enc)
	h := NewAuthHandler(c, false)

	user := &models.User{Username: "lane-fault", Email: "lane-fault@example.com", IsActive: true, AccountState: core.AccountActive, MFAEnabled: true}
	require.NoError(t, db.Create(user).Error)
	slots := func() int64 {
		var n int64
		require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
		return n
	}

	const proof = `{"code":"123456","password":"Secret#Passw0rd!"}`
	for _, ep := range []struct {
		name, method, path, body string
		serve                    func(http.ResponseWriter, *http.Request)
	}{
		{"enroll", http.MethodPost, "/api/v1/auth/mfa/enroll", "", h.EnrollMFA},
		{"activate", http.MethodPost, "/api/v1/auth/mfa/activate", proof, h.ActivateMFA},
		{"disable", http.MethodPost, "/api/v1/auth/mfa/disable", proof, h.DisableMFA},
		{"regenerate recovery codes", http.MethodPost, "/api/v1/auth/mfa/recovery-codes", proof, h.RegenerateRecoveryCodes},
		{"recovery codes status", http.MethodGet, "/api/v1/auth/mfa/recovery-codes", "", h.RecoveryCodesStatus},
		{"delete passkey", http.MethodDelete, "/api/v1/auth/webauthn/credentials/1", proof, h.DeleteWebAuthnCredential},
	} {
		t.Run(ep.name, func(t *testing.T) {
			r := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			r.RemoteAddr = "198.51.100.9:4000"
			uc := &middleware.UserContext{UserID: user.ID, Username: user.Username, ActorType: core.ActorTypeUser, SessionAuth: true}
			ctx := context.WithValue(r.Context(), middleware.GetUserContextKey(), uc)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", "1")
			r = r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))

			before := slots()
			faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			defer faulty.Arm(nil)
			w := httptest.NewRecorder()
			ep.serve(w, r)
			require.True(t, faulty.Fired(), "the GetUser fault must be reached")
			assertStorageUnavailable503(t, w)
			assert.Equal(t, before, slots(), "a pre-verdict fault hands the per-IP slot back")
		})
	}
}

func TestWriteWebAuthnErr_StorageReadFaultIs503(t *testing.T) {
	h := &AuthHandler{}
	w := httptest.NewRecorder()
	h.writeWebAuthnErr(w, core.ReadFault(assert.AnError))
	assertStorageUnavailable503(t, w)

	w = httptest.NewRecorder()
	h.writeMFAErr(w, core.ReadFault(assert.AnError))
	assertStorageUnavailable503(t, w)
}

package handlers

// storage_unavailable_own_revoke_test.go — STORAGE-ERR-CLASS-2 item 1 (REST).
//
// DELETE /auth/sessions/{id} and DELETE /auth/tokens/{id} answered 404 for any read
// error. A storage fault is now 503 storage_unavailable + Retry-After; a true
// not-found stays 404 and the retry after the fault clears succeeds (204).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestStorageUnavailable_OwnRevokeREST(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxownrevoke_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	cs := core.NewKeyorixCore(faulty)
	authH := &AuthHandler{coreService: cs}
	patH := NewPATHandler(cs)

	// withUserCtx authenticates as user 1.
	sess := &models.Session{UserID: 1, SessionToken: "own-revoke-sess", CreatedAt: time.Now()}
	require.NoError(t, db.Create(sess).Error)
	pat := &models.PersonalAccessToken{UserID: 1, Name: "own-revoke", TokenHash: "own-revoke-pat", TokenPrefix: "kx_pat_"}
	require.NoError(t, db.Create(pat).Error)

	cases := []struct {
		name   string
		fault  string
		handle func(http.ResponseWriter, *http.Request)
		id     uint
	}{
		{"revoke own session", "GetSessionByID", authH.RevokeSession, sess.ID},
		{"revoke own PAT", "GetPersonalAccessTokenByID", patH.RevokePAT, pat.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			w := httptest.NewRecorder()
			tc.handle(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(tc.id)}))
			require.True(t, faulty.Fired(), "the read fault must be reached")
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, "a storage read fault is 503, not 404: %s", w.Body.String())
			assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
			var body suErrBody
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, storageUnavailableCode, body.Error)
			assert.NotContains(t, w.Body.String(), assert.AnError.Error(), "the driver cause must not reach the client")
			faulty.Arm(nil)

			w = httptest.NewRecorder()
			tc.handle(w, suReq(http.MethodDelete, "", map[string]string{"id": "9999999"}))
			assert.Equal(t, http.StatusNotFound, w.Code, "a true not-found stays 404")
			assert.Empty(t, w.Header().Get("Retry-After"))
		})
	}

	t.Run("the retried revokes succeed after the fault clears", func(t *testing.T) {
		w := httptest.NewRecorder()
		authH.RevokeSession(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(sess.ID)}))
		assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
		w = httptest.NewRecorder()
		patH.RevokePAT(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(pat.ID)}))
		assert.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	})
}

package handlers

// err_family6_revoke_session_test.go — CORE-ERR-FAMILY-6 item 2 (REST).
//
// DELETE /auth/sessions/{id} answered 404 "Session not found" for every error that was
// not a read fault, including a failed delete. core.RevokeOwnSession now returns
// core.ErrSessionNotFound for a missing or foreign session; the handler maps that to 404
// and anything else to 500.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func TestErrFamily6_Item2_RevokeOwnSession(t *testing.T) {
	fw := newFoldWorld(t)
	authH := &AuthHandler{coreService: fw.cs}
	mine := &models.Session{UserID: fw.admin.ID, SessionToken: "fam6-mine"}
	require.NoError(t, fw.db.Create(mine).Error)
	theirs := &models.Session{UserID: fw.admin.ID + 1, SessionToken: "fam6-theirs"}
	require.NoError(t, fw.db.Create(theirs).Error)

	revoke := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		authH.RevokeSession(w, suReq(http.MethodDelete, "", map[string]string{"id": id}))
		return w
	}

	t.Run("a failed delete is not a missing session", func(t *testing.T) {
		fw.faulty.Arm(&faultstorage.FaultSpec{Method: "DeleteSession", NthCall: 1, Kind: faultstorage.KindError, Err: errFaultNotFoundText})
		w := revoke(suID(mine.ID))
		require.True(t, fw.faulty.Fired())
		assert.Equal(t, http.StatusInternalServerError, w.Code, "a write fault must not read as 'Session not found': %s", w.Body.String())
		fw.faulty.Arm(nil)
	})
	t.Run("not found and not mine are the same 404", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, revoke("9999999").Code)
		assert.Equal(t, http.StatusNotFound, revoke(suID(theirs.ID)).Code)
	})
	t.Run("a machine principal owns no session: 404, not 500", func(t *testing.T) {
		r := suReq(http.MethodDelete, "", map[string]string{"id": suID(mine.ID)})
		machine := &customMiddleware.UserContext{UserID: 0}
		r = r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), machine))
		w := httptest.NewRecorder()
		authH.RevokeSession(w, r)
		assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	})
	t.Run("a read fault whose text says not found is 503", func(t *testing.T) {
		armFamily6(fw, "GetSessionByID")
		requireFold503(t, revoke(suID(mine.ID)), "GetSessionByID fault")
		fw.faulty.Arm(nil)
	})
	t.Run("retry succeeds", func(t *testing.T) {
		assert.Equal(t, http.StatusNoContent, revoke(suID(mine.ID)).Code)
	})
}

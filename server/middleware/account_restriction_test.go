package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnforceAccountRestriction(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := EnforceAccountRestriction(next)

	run := func(userCtx *UserContext, path string) *httptest.ResponseRecorder {
		nextCalled = false
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if userCtx != nil {
			req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	t.Run("unrestricted account passes through", func(t *testing.T) {
		rr := run(&UserContext{UserID: 1, Restricted: false}, "/api/v1/secrets")
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, nextCalled)
	})

	t.Run("restricted account is blocked on a normal endpoint", func(t *testing.T) {
		rr := run(&UserContext{UserID: 1, Restricted: true}, "/api/v1/secrets")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), "PasswordChangeRequired")
	})

	t.Run("restricted account may reach change-password", func(t *testing.T) {
		rr := run(&UserContext{UserID: 1, Restricted: true}, "/api/v1/auth/change-password")
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, nextCalled)
	})

	t.Run("restricted account may reach its profile", func(t *testing.T) {
		rr := run(&UserContext{UserID: 1, Restricted: true}, "/api/v1/auth/profile")
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, nextCalled)
	})

	t.Run("no user context passes through (auth handles it)", func(t *testing.T) {
		rr := run(nil, "/api/v1/secrets")
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, nextCalled)
	})
}

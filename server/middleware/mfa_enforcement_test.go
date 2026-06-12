package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
)

func TestEnforceMFAEnrollment(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	run := func(requireMFA bool, userCtx *UserContext, path string) *httptest.ResponseRecorder {
		nextCalled = false
		h := EnforceMFAEnrollment(requireMFA)(next)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if userCtx != nil {
			req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	t.Run("policy off: passes through", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, run(false, sessionNoMFA, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
	})

	t.Run("policy on, session without MFA: blocked on a normal endpoint", func(t *testing.T) {
		rr := run(true, sessionNoMFA, "/api/v1/secrets")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, nextCalled)
		assert.Contains(t, rr.Body.String(), "MFAEnrollmentRequired")
	})

	t.Run("policy on, session without MFA: may reach enrolment", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, run(true, sessionNoMFA, "/api/v1/auth/mfa/enroll").Code)
		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, run(true, sessionNoMFA, "/api/v1/auth/mfa/activate").Code)
	})

	t.Run("policy on, session WITH MFA: passes through", func(t *testing.T) {
		ctx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
		assert.Equal(t, http.StatusOK, run(true, ctx, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
	})

	t.Run("policy on, PAT (non-interactive) without MFA: EXEMPT", func(t *testing.T) {
		pat := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: false, MFAEnabled: false}
		assert.Equal(t, http.StatusOK, run(true, pat, "/api/v1/secrets").Code)
		assert.True(t, nextCalled, "PAT/automation must not be confined by the MFA policy")
	})

	t.Run("policy on, machine identity: EXEMPT", func(t *testing.T) {
		mid := uint(5)
		machine := &UserContext{MachineIdentityID: &mid, ActorType: core.ActorTypeMachine, SessionAuth: false}
		assert.Equal(t, http.StatusOK, run(true, machine, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
	})
}

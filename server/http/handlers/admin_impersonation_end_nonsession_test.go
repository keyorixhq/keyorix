package handlers

// MSG-ACCURACY-1 item 3 (#3465): POST /auth/end-impersonation with a PAT bearer answered
// 500 "session not found". Like the machine-token case it is a 403 with the standard
// error body, for any bearer that is not an interactive session.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/server/middleware"
)

func TestImpersonationHandler_End_NonSessionBearerIs403(t *testing.T) {
	cases := []struct {
		name  string
		token string
		uc    *middleware.UserContext
	}{
		{"PAT bearer", "kx_pat_0123456789abcdef", &middleware.UserContext{UserID: 1, Username: "alice", ActorType: "user"}},
		{"PAT bearer without user context", "kx_pat_0123456789abcdef", nil},
		{"other non-session bearer", "not-a-session-token", &middleware.UserContext{UserID: 1, Username: "alice", ActorType: "user"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newImpersonationHandlerS6(t)
			req := withBearerToken(httptest.NewRequest(http.MethodPost, "/", nil), tc.token)
			if tc.uc != nil {
				req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), tc.uc))
			}
			w := httptest.NewRecorder()
			h.End(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "Forbidden")
			assert.Contains(t, w.Body.String(), errSessionOnlyEndpoint)
			assert.False(t, strings.Contains(w.Body.String(), "session not found"), w.Body.String())
		})
	}
}

func TestImpersonationHandler_End_SessionBearerIsNotRefusedAs403(t *testing.T) {
	h := newImpersonationHandlerS6(t)
	req := withBearerToken(httptest.NewRequest(http.MethodPost, "/", nil), "invalid-token-xyz")
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(),
		&middleware.UserContext{UserID: 1, Username: "alice", ActorType: "user", SessionAuth: true}))
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.NotEqual(t, http.StatusForbidden, w.Code, "a session bearer must reach EndImpersonation")
}

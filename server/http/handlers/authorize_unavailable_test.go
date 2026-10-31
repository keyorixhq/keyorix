package handlers

// authorize_unavailable_test.go — AUTHZ-OUTAGE-HANDLERS-1 item 1: the in-handler
// permission check answers a storage outage 503 + Retry-After, a genuine denial 403.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefuseUnlessAuthorized(t *testing.T) {
	transient := fmt.Errorf("resolve permission: %w", syscall.ECONNREFUSED)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name        string
		ctx         context.Context
		allowed     bool
		err         error
		wantRefused bool
		wantStatus  int
		wantRetry   bool
	}{
		{"transient error is 503 with Retry-After", context.Background(), false, transient, true, http.StatusServiceUnavailable, true},
		{"transient error with allowed=true still refuses", context.Background(), true, transient, true, http.StatusServiceUnavailable, true},
		{"canceled request context is 503", canceled, false, errors.New("anything"), true, http.StatusServiceUnavailable, true},
		{"real denial error is 403", context.Background(), false, errors.New("role resolution returned no result"), true, http.StatusForbidden, false},
		{"unrecognised error with allowed=true fails closed to 403", context.Background(), true, errors.New("boom"), true, http.StatusForbidden, false},
		{"nil error and allowed=false is 403", context.Background(), false, nil, true, http.StatusForbidden, false},
		{"nil error and allowed=true proceeds", context.Background(), true, nil, false, http.StatusOK, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(tc.ctx)
			w := httptest.NewRecorder()
			refused := refuseUnlessAuthorized(w, r, tc.allowed, tc.err, func() {
				sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
			})
			require.Equal(t, tc.wantRefused, refused)
			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantRetry {
				assert.Equal(t, "2", w.Header().Get("Retry-After"))
				assert.Contains(t, w.Body.String(), "authorization temporarily unavailable, please retry")
				assert.NotContains(t, w.Body.String(), "ECONNREFUSED", "no storage detail reaches the client")
				assert.NotContains(t, w.Body.String(), "connection refused")
			} else {
				assert.Empty(t, w.Header().Get("Retry-After"))
			}
		})
	}
}

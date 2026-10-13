package k8ssync

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ERRMAP-1: a value read the secret's own state refuses carries a code. Suspended
// and expired are definitive (ErrUpstreamGone: the materialized value is removed);
// outside the access schedule and max-reads exhausted are not (the synced value
// stays). A bare 403 is still a revoked grant.
func TestKeyorixFetcher_SecretStateRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		gone   bool
	}{
		{http.StatusConflict, "SecretSuspended", true},
		{http.StatusConflict, "SecretExpired", true},
		{http.StatusForbidden, "SecretAccessOutsideSchedule", false},
		{http.StatusConflict, "SecretMaxReadsExhausted", false},
		{http.StatusForbidden, "Forbidden", true},
		{http.StatusConflict, "ConflictError", false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"success":false,"code":%d,"error":%q,"message":"refused"}`, tc.status, tc.code)
			}))
			defer srv.Close()
			var out struct{}
			err := NewKeyorixFetcher(srv.URL, "tok", 1).getJSON(context.Background(), "/api/v1/secrets/7?include_value=true", &out)
			require.Error(t, err)
			assert.Equal(t, tc.gone, errors.Is(err, ErrUpstreamGone), "%d %s: %v", tc.status, tc.code, err)
		})
	}
}

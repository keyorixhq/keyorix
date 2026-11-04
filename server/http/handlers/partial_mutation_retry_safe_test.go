package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestSendPartialMutation_RetrySafeFollowsRetryRefused (#3684): a partial apply whose
// second commit was refused on the actor's own authority answers retry_safe false and
// does not tell the client to retry; a fault (an audit outage) keeps retry_safe true.
// Neither body carries the underlying error's text.
func TestSendPartialMutation_RetrySafeFollowsRetryRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		retryRefused bool
		cause        error
	}{
		{"ceiling refused", true, core.ErrPermissionDenied},
		{"audit outage", false, core.ErrMutationAuditUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := &core.PartialMutationError{Applied: "removal of role(s) [1]", NotApplied: "addition of role(s) [2]", Err: tc.cause, RetryRefused: tc.retryRefused}
			require.True(t, sendPartialMutation(rec, err))
			require.Equal(t, http.StatusServiceUnavailable, rec.Code)

			var body struct {
				Error   string         `json:"error"`
				Message string         `json:"message"`
				Details map[string]any `json:"details"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, core.PartialMutationErrorType, body.Error)
			require.Equal(t, !tc.retryRefused, body.Details["retry_safe"])
			require.Equal(t, !tc.retryRefused, strings.Contains(body.Message, "retry the same request"))
			require.NotContains(t, rec.Body.String(), tc.cause.Error(), "the cause's text stays server-side")
		})
	}
}

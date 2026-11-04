package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestPartialMutationStatus_RetrySafeFollowsRetryRefused (#3684): the gRPC answer to
// a partial apply whose second commit was refused on the actor's own authority
// carries retry_safe "false" in its ErrorInfo and does not tell the client to retry;
// a fault (an audit outage) keeps retry_safe "true". Neither carries the cause's text.
func TestPartialMutationStatus_RetrySafeFollowsRetryRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		retryRefused bool
		cause        error
	}{
		{"ceiling refused", true, core.ErrPermissionDenied},
		{"audit outage", false, core.ErrMutationAuditUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &core.PartialMutationError{Applied: "removal of role(s) [1]", NotApplied: "addition of role(s) [2]", Err: tc.cause, RetryRefused: tc.retryRefused}
			out, ok := partialMutationStatus(err)
			require.True(t, ok)
			st := status.Convert(out)
			require.Equal(t, codes.Unavailable, st.Code())

			var info *errdetails.ErrorInfo
			for _, d := range st.Details() {
				if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo {
					info = ei
				}
			}
			require.NotNil(t, info, "the ErrorInfo detail is missing")
			require.Equal(t, core.PartialMutationErrorType, info.GetReason())
			want := "true"
			if tc.retryRefused {
				want = "false"
			}
			require.Equal(t, want, info.GetMetadata()["retry_safe"])
			require.Equal(t, !tc.retryRefused, strings.Contains(st.Message(), "retry the same request"))
			require.NotContains(t, st.Message(), tc.cause.Error(), "the cause's text stays server-side")
		})
	}
}

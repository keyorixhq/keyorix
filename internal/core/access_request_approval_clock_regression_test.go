// access_request_approval_clock_regression_test.go — #1653 (follow-up to
// #1632): exploit-shaped test for the access-request-approval lazy-expire-
// and-refuse check, shared between ApproveSecretAccessRequest
// (classification_gate.go) and ApproveAccessRequestWithExpiry
// (invitations.go). Both bind a fresh c.now() directly against a DB-loaded
// ExpiresAt with no seam — this exercises ApproveSecretAccessRequest, the
// same fix applies identically to ApproveAccessRequestWithExpiry via the
// shared checkAccessRequestApprovalClockNotRegressed watermark.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestApproveSecretAccessRequest_ClockSteppedBackward_ExpiredRequestStaysRefused
// is the exploit-shaped test. Uses TWO separate requests, not one reused
// across both steps: ApproveSecretAccessRequest's pre-existing expiry check
// persists AccessRequestExpired on a genuinely-expired request as a side
// effect, which would make a second approval attempt on the SAME request
// fail via "only a pending request can be approved" regardless of the new
// guard — masking whether the guard itself did anything. Using an untouched
// second request for the actual exploit attempt isolates the guard's effect.
//
//  1. Create warmupReq and exploitReq at the same base time (identical
//     ExpiresAt).
//  2. Approve warmupReq at a baseline c.now() two hours past ExpiresAt —
//     correctly refused ("access request has expired"), and this warms
//     checkAccessRequestApprovalClockNotRegressed's watermark to that
//     baseline. exploitReq is untouched so far, still Pending.
//  3. Step c.now() BACKWARD to 10 minutes BEFORE ExpiresAt (i.e., if trusted
//     naively, exploitReq would look not-yet-expired) and approve
//     exploitReq. Before this fix, the approver could approve a request
//     that has genuinely already expired. After the fix, the regression
//     guard refuses before the expiry check is ever reached.
func TestApproveSecretAccessRequest_ClockSteppedBackward_ExpiredRequestStaysRefused(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return base }
	warmupReq, err := c.RequestSecretAccess(ctx, secretID, requesterID, "warmup")
	require.NoError(t, err)
	exploitReq, err := c.RequestSecretAccess(ctx, secretID, requesterID, "exploit")
	require.NoError(t, err)
	expiresAt := base.Add(accessRequestTTL)
	require.Equal(t, expiresAt, *warmupReq.ExpiresAt)
	require.Equal(t, expiresAt, *exploitReq.ExpiresAt)

	// Step 1: baseline, clearly past expiry — correctly refused, warms the
	// watermark. Only warmupReq is touched.
	c.now = func() time.Time { return expiresAt.Add(2 * time.Hour) }
	_, err = c.ApproveSecretAccessRequest(ctx, warmupReq.ID, approverID)
	require.Error(t, err, "sanity: approval must be refused at the baseline time before the clock ever moves")
	require.Contains(t, err.Error(), "expired")

	// Step 2: the exploit. Step c.now() BACKWARD to before expiry, and
	// attempt exploitReq -- still Pending, never touched until now.
	c.now = func() time.Time { return expiresAt.Add(-10 * time.Minute) }
	_, err = c.ApproveSecretAccessRequest(ctx, exploitReq.ID, approverID)
	require.Error(t, err, "approval must still be refused after the clock steps backward to before the request's expiry")
	require.Contains(t, err.Error(), "expired")
}

// TestApproveSecretAccessRequest_ClockSteppedBackward_LegitimatelyLiveRequestStillApproves
// is the positive control: a request well within its TTL, approved after a
// SMALL in-tolerance backward step, must still succeed.
func TestApproveSecretAccessRequest_ClockSteppedBackward_LegitimatelyLiveRequestStillApproves(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return base }
	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "")
	require.NoError(t, err)

	c.now = func() time.Time { return base.Add(-1 * time.Second) }
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err, "a small in-tolerance backward step must not refuse approval of a request well within its TTL")
}

// TestCheckAccessRequestApprovalClockNotRegressed_FreshWatermarkNeverRefuses
// covers the zero-value watermark case directly.
func TestCheckAccessRequestApprovalClockNotRegressed_FreshWatermarkNeverRefuses(t *testing.T) {
	c := &KeyorixCore{}
	err := c.checkAccessRequestApprovalClockNotRegressed(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err, "an unset watermark must never itself cause a refusal")
}

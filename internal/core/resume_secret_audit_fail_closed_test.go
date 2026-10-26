// resume_secret_audit_fail_closed_test.go — UNLOCK-AUDIT-1 family check.
//
// ResumeSecret lifts a suspension (a restriction an operator placed on value
// reads), so, like UnlockUser, it must not happen without a record: the status
// flip and secret.resumed commit in one transaction.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestResumeSecret_AuditWriteFault_StaysSuspended(t *testing.T) {
	for name, kind := range map[string]faultstorage.FaultKind{"error": faultstorage.KindError, "panic": faultstorage.KindPanic} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c, _, _, secretID := newResumeLiveParentFixture(t)

			base := c.storage
			fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
				Method: "LogAuditEvent", NthCall: 1, Kind: kind, Err: errors.New("injected: LogAuditEvent"),
			})
			c.storage = fs
			var err error
			require.NotPanics(t, func() { _, err = c.ResumeSecret(ctx, secretID, 1) })
			c.storage = base

			require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
			require.Error(t, err, "an unrecorded resume must fail")
			got, gerr := c.storage.GetSecret(ctx, secretID)
			require.NoError(t, gerr)
			assert.Equal(t, SecretStatusSuspended, got.Status, "the secret must stay suspended")
		})
	}
}

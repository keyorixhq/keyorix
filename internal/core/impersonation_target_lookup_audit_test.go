package core

// impersonation_target_lookup_audit_test.go — #3786: StartImpersonation refused a
// target whose GetUser failed with a storage error (not "not found") without writing
// the impersonation.start_failed row every other refusal writes. The refusal now
// audits, best effort: an audit log that refuses the row too never turns the
// refusal into anything else. SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStartImpersonation_TargetLookupFails_RefusedAndAudited(t *testing.T) {
	smaBackends(t, func(t *testing.T, w *smaWorld) {
		target := w.f.user("imp-lookup-target", "")
		blip := errors.New("storage: connection reset")
		var auditDown atomic.Bool
		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			GetUser: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
				if id == target.ID {
					return nil, blip
				}
				return next.GetUser(ctx, id)
			},
			LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
				if auditDown.Load() {
					return errors.New("audit log refuses writes")
				}
				return next.LogAuditEvent(ctx, e)
			},
		}))
		ctx := WithSessionAuth(context.Background(), true)
		denied := func() int64 {
			var n int64
			require.NoError(t, w.db.Model(&models.AuditEvent{}).
				Where("event_type = ? AND acting_as = ?", EventImpersonationStartFailed, target.ID).Count(&n).Error)
			return n
		}
		sessions := func() int64 {
			var n int64
			require.NoError(t, w.db.Model(&models.Session{}).Where("user_id = ?", target.ID).Count(&n).Error)
			return n
		}

		before := denied()
		sess, u, err := c.StartImpersonation(ctx, w.f.adminID, target.ID, "198.51.100.9")
		require.Error(t, err)
		require.Nil(t, sess)
		require.Nil(t, u)
		require.ErrorIs(t, err, blip)
		require.NotErrorIs(t, err, storage.ErrUserNotFound, "a storage failure is not a missing user")
		require.Equal(t, before+1, denied(), "exactly one impersonation.start_failed row for the refusal")
		var row models.AuditEvent
		require.NoError(t, w.db.Where("event_type = ? AND acting_as = ?", EventImpersonationStartFailed, target.ID).
			Order("id DESC").First(&row).Error)
		require.Contains(t, row.Description, "target lookup failed")
		require.NotNil(t, row.Success)
		require.False(t, *row.Success)
		require.Zero(t, sessions(), "no impersonation session may exist")

		// Best effort: the audit log refusing the row does not change the refusal.
		auditDown.Store(true)
		_, _, err = c.StartImpersonation(ctx, w.f.adminID, target.ID, "198.51.100.9")
		auditDown.Store(false)
		require.ErrorIs(t, err, blip)
		require.Equal(t, before+1, denied())
		require.Zero(t, sessions())
	})
}

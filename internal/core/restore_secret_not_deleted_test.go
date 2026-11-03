package core

// restore_secret_not_deleted_test.go — #3737: RestoreSecret on a live (not
// soft-deleted) secret is ErrSecretNotDeleted, a state conflict, not a storage failure
// or "not found"; it changes nothing and writes no secret.restored row. A missing
// secret stays storage.ErrSecretNotFound. SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN).

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRestoreSecret_LiveSecretIsNotDeletedConflict(t *testing.T) {
	smaBackends(t, func(t *testing.T, w *smaWorld) {
		restored := func(id uint) int64 {
			var n int64
			require.NoError(t, w.db.Model(&models.AuditEvent{}).
				Where("event_type = ? AND secret_node_id = ?", EventSecretRestored, id).Count(&n).Error)
			return n
		}
		s := w.secret("restore-live")
		err := w.c.RestoreSecret(w.ctx, w.f.adminID, s.ID)
		require.ErrorIs(t, err, ErrSecretNotDeleted)
		require.NotErrorIs(t, err, storage.ErrSecretNotFound)
		require.Contains(t, err.Error(), "is not deleted; nothing to restore")
		require.NotContains(t, err.Error(), "Storage operation failed")
		require.Zero(t, restored(s.ID))

		require.NoError(t, w.c.DeleteSecret(w.ctx, s.ID))
		require.NoError(t, w.c.RestoreSecret(w.ctx, w.f.adminID, s.ID))
		require.EqualValues(t, 1, restored(s.ID))

		err = w.c.RestoreSecret(w.ctx, w.f.adminID, 987654)
		require.ErrorIs(t, err, storage.ErrSecretNotFound)
		require.NotErrorIs(t, err, ErrSecretNotDeleted)
	})
}

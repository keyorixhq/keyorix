package http

// secret_restore_live_conflict_test.go — #3737: POST /api/v1/secrets/{id}/restore on a
// secret that is not deleted (what `keyorix secret restore --id N` sends) answered
// "Storage operation failed: Secret not found (HTTP 404)". It is a state conflict:
// 409 "secret N is not deleted; nothing to restore", no secret.restored row. A
// soft-deleted secret still restores; an unknown id stays 404. Through the real
// router (route gate included), SQLite and PostgreSQL.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRestoreSecretHTTP_LiveSecretIsConflictNotStorageFailure(t *testing.T) {
	cgBackends(t, func(t *testing.T, backend string) {
		w := newSVWorld(t, backend, 1)
		token := w.tokens["human"]
		restore := func(id uint) (int, string) {
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/restore", id), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			w.a.router.ServeHTTP(rec, req)
			return rec.Code, rec.Body.String()
		}
		restoredRows := func(id uint) int64 {
			var n int64
			require.NoError(t, w.a.db.Model(&models.AuditEvent{}).
				Where("event_type = ? AND secret_node_id = ?", core.EventSecretRestored, id).Count(&n).Error)
			return n
		}

		live, _ := w.newSecret(t, nil)
		code, body := restore(live.ID)
		require.Equal(t, http.StatusConflict, code, body)
		require.Contains(t, body, fmt.Sprintf("secret %d is not deleted; nothing to restore", live.ID))
		require.NotContains(t, body, "Storage operation failed")
		require.NotContains(t, body, "not found")
		require.Zero(t, restoredRows(live.ID), "a refused restore writes no secret.restored row")

		deleted, _ := w.newSecret(t, nil)
		require.NoError(t, w.a.c.DeleteSecret(context.Background(), deleted.ID))
		code, body = restore(deleted.ID)
		require.Equal(t, http.StatusOK, code, body)
		require.EqualValues(t, 1, restoredRows(deleted.ID))
		_, err := w.a.c.Storage().GetSecret(context.Background(), deleted.ID)
		require.NoError(t, err, "the secret is live again")

		// Restoring it a second time is now the conflict, not a 404.
		code, body = restore(deleted.ID)
		require.Equal(t, http.StatusConflict, code, body)
		require.EqualValues(t, 1, restoredRows(deleted.ID))

		code, body = restore(999999)
		require.Equal(t, http.StatusNotFound, code, body)
	})
}

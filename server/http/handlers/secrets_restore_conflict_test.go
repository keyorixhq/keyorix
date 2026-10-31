// secrets_restore_conflict_test.go — POST /secrets/{id}/restore on a secret that
// is not deleted answers 409 with a fixed message instead of a storage-flavoured
// 404 "Secret not found" (LIFECYCLE-WORDING-1, #3737). A secret that does not
// exist still answers the 404 it always did. The route's scoped secrets.write
// gate runs before the handler (router.go), so a caller without access never
// reaches this code and cannot use the 409 as an existence oracle. Like the other
// locale tests these flip the process-global localizer and are NOT t.Parallel().
package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretRestore_LiveSecretIs409WithFixedMessage(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := secretsDo(h.RestoreSecret, http.MethodPost, "", fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "secret "+fx.id()+" is not deleted; nothing to restore")
			assert.NotContains(t, w.Body.String(), "Storage operation failed")
		})
	}
}

func TestSecretRestore_MissingSecretStays404WithSameBody(t *testing.T) {
	h, _, _ := newSecretsHandlerWithDB(t, "en")
	w := secretsDo(h.RestoreSecret, http.MethodPost, "", secretsMissingID, secretsAdminID)
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "Storage operation failed: Secret not found")
	assert.NotContains(t, w.Body.String(), "not deleted")
}

// A deleted secret still restores (200), and a second restore is then the 409.
func TestSecretRestore_DeletedSecretRestoresThenConflicts(t *testing.T) {
	h, db, fx := newSecretsHandlerWithDB(t, "en")
	require.NoError(t, db.Exec("UPDATE secret_nodes SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", fx.secretID).Error)
	w := secretsDo(h.RestoreSecret, http.MethodPost, "", fx.id(), secretsAdminID)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	w = secretsDo(h.RestoreSecret, http.MethodPost, "", fx.id(), secretsAdminID)
	assert.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
}

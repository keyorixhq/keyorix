package handlers

// secrets_bulk_delete_audit_outage_test.go — ERRMAP-TAILS-NOV-4 item 4 (leftover of
// GRPC-OUTAGE-TAILS-1). Core reports a bulk-delete audit-log outage per item, with the
// stable code "audit_unavailable" and retryable=true, but only when the delete commits its
// audit row in its own transaction, which it does for a context tagged with
// WithSecretMutationAudit. The HTTP handler passed the bare request context, so the
// delete committed with no in-transaction audit row and an outage never showed. It is
// tagged now: an outage rolls the item back and says so, and a delete writes one
// secret.deleted row, not the in-transaction row plus a second post-commit one.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bulkDeleteAuditFixture is a SecretHandler over a fault-injecting store holding one
// secret of project 1 that the caller (the global admin of freshFolderFixture) may delete.
func bulkDeleteAuditFixture(t *testing.T) (h *SecretHandler, faulty *faultstorage.FaultyStorage, db *gorm.DB, secretID uint) {
	t.Helper()
	_, plain, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	secret, err := plain.CreateSecret(t.Context(), &core.CreateSecretRequest{
		Name: "bulk-audit", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)
	faulty = faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err = NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	return h, faulty, db, secret.ID
}

func bulkDeleteOne(t *testing.T, h *SecretHandler, secretID uint) core.BulkDeleteResult {
	t.Helper()
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, bulkDeleteRequest(http.MethodPost, "1", fmt.Sprintf(`{"secret_ids":[%d]}`, secretID)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data core.BulkDeleteResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Data
}

func TestBulkDeleteSecrets_AuditOutageIsRetryablePerItem(t *testing.T) {
	h, faulty, db, secretID := bulkDeleteAuditFixture(t)

	faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEventWithAccessLog", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	res := bulkDeleteOne(t, h, secretID)
	fired := faulty.Fired()
	faulty.Arm(nil)

	require.True(t, fired, "the delete must append its audit row through storage")
	assert.Empty(t, res.Deleted)
	assert.Equal(t, 1, res.Retryable, "the summary counts the outage as retryable")
	require.Len(t, res.Failed, 1)
	assert.Equal(t, secretID, res.Failed[0].SecretID)
	assert.Equal(t, core.BulkErrCodeAuditUnavailable, res.Failed[0].Code)
	assert.True(t, res.Failed[0].Retryable)
	assert.Equal(t, core.MutationAuditUnavailableMessage, res.Failed[0].Error)

	var live int64
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", secretID).Count(&live).Error)
	assert.EqualValues(t, 1, live, "an audit outage must leave the secret in place")

	t.Run("the same call succeeds once the audit log is back", func(t *testing.T) {
		res := bulkDeleteOne(t, h, secretID)
		assert.Equal(t, []uint{secretID}, res.Deleted)
		assert.Empty(t, res.Failed)
	})
}

func TestBulkDeleteSecrets_WritesOneDeleteAuditRowPerSecret(t *testing.T) {
	h, _, db, secretID := bulkDeleteAuditFixture(t)

	res := bulkDeleteOne(t, h, secretID)
	require.Equal(t, []uint{secretID}, res.Deleted)

	var events, accessLogs int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ? AND secret_node_id = ?", "secret.deleted", secretID).Count(&events).Error)
	require.NoError(t, db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ? AND action = ?", secretID, "delete").Count(&accessLogs).Error)
	assert.EqualValues(t, 1, events, "one secret.deleted event per deleted secret")
	assert.EqualValues(t, 1, accessLogs, "one delete access-log row per deleted secret")
}

package handlers

// secrets_bulk_delete_error_text_test.go — STORAGE-ERR-CLASS-3 item 3.
//
// A bulk-delete item whose delete failed carried err.Error() verbatim in failed[].error,
// i.e. storage/driver text (table and column names, SQL). It now carries one fixed
// class: permission denied, secret not found, storage unavailable or internal error.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bulkDeleteFailures runs BulkDeleteSecrets for one secret of project 1 (caller: the
// global admin of freshFolderFixture) with the given fault armed and returns the
// response body and its failed[] entries.
func bulkDeleteFailures(t *testing.T, spec *faultstorage.FaultSpec) (string, []core.BulkOpError) {
	t.Helper()
	_, plain, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	secret, err := plain.CreateSecret(t.Context(), &core.CreateSecretRequest{
		Name: "bulk-fault", Value: []byte("v"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)
	secretID := secret.ID
	_, err = plain.GetSecretWithPermissionCheck(t.Context(), secretID, 1)
	require.NoError(t, err, "precondition: the caller may delete the secret")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)

	faulty.Arm(spec)
	w := httptest.NewRecorder()
	h.BulkDeleteSecrets(w, bulkDeleteRequest(http.MethodPost, "1", fmt.Sprintf(`{"secret_ids":[%d]}`, secretID)))
	require.True(t, faulty.Fired(), "the delete must be reached: %s", w.Body.String())
	faulty.Arm(nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Data core.BulkDeleteResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Failed, 1, w.Body.String())
	assert.Empty(t, resp.Data.Deleted)
	return w.Body.String(), resp.Data.Failed
}

func TestBulkDeleteSecrets_FailedItemCarriesNoStorageText(t *testing.T) {
	t.Run("a non-transient storage error is internal error", func(t *testing.T) {
		body, failed := bulkDeleteFailures(t, &faultstorage.FaultSpec{Method: "DeleteSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
		assert.Equal(t, "internal error", failed[0].Error)
		for _, leak := range []string{"secret_nodes", "cache_epoch", "UPDATE", "no such column"} {
			assert.NotContains(t, body, leak, "storage text must not reach the client")
		}
	})
	t.Run("a transient storage error is the retry message", func(t *testing.T) {
		down := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		body, failed := bulkDeleteFailures(t, &faultstorage.FaultSpec{Method: "DeleteSecret", NthCall: 1, Kind: faultstorage.KindError, Err: down})
		assert.Equal(t, core.StorageReadUnavailableMessage, failed[0].Error)
		assert.False(t, strings.Contains(body, "refused"), "the driver cause must not reach the client")
	})
}

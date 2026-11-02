package handlers

// storage_err_class3_test.go — STORAGE-ERR-CLASS-3 item 2.
//
// Item 2: handler pre-checks that re-read the target the route gate already resolved
// (DeleteFolder's "is it a folder" read, the dynamic-secret handlers' loadConfig)
// answered ANY read error with 404, so a storage fault told the caller the target was
// gone while nothing was done. A fault is now the shared 503 storage_unavailable +
// Retry-After (sendStorageUnavailable); a true not-found keeps its 404.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// errSchemaLeak is a non-transient storage failure whose text names a table and a
// column: none of it may reach a client.
var errSchemaLeak = errors.New(`UPDATE "secret_nodes" SET "deleted_at"=?: no such column: cache_epoch`)

func requireStorageUnavailable503(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "a read fault is not \"not found\": %s", w.Body.String())
	var body suErrBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, storageUnavailableCode, body.Error)
	assert.Equal(t, core.StorageReadUnavailableMessage, body.Message)
	assert.Equal(t, strconv.Itoa(storageUnavailableRetryAfterSeconds), w.Header().Get("Retry-After"))
	assert.NotContains(t, w.Body.String(), "secret_nodes", "the driver cause must not reach the client")
}

func TestDeleteFolder_ReadFaultIs503(t *testing.T) {
	_, plain, db := freshFolderFixture(t)
	folder, err := plain.CreateFolder(t.Context(), 1, "fault-folder", 1, 10, nil)
	require.NoError(t, err)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewFolderHandler(core.NewKeyorixCore(faulty))

	del := func(id uint) *httptest.ResponseRecorder {
		r := withFolderAdminCtx(withChiParam(
			httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", id), nil), "id", fmt.Sprint(id)))
		w := httptest.NewRecorder()
		h.DeleteFolder(w, r)
		return w
	}

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := del(folder.ID)
	require.True(t, faulty.Fired(), "the handler's folder read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)
	_, gerr := plain.GetSecret(t.Context(), folder.ID)
	require.NoError(t, gerr, "the 503 means the folder was not deleted")

	assert.Equal(t, http.StatusNotFound, del(999999).Code, "a true not-found keeps its 404")
	assert.Equal(t, http.StatusNoContent, del(folder.ID).Code, "the retried delete succeeds once the fault clears")
}

func TestDynamicSecretLoadConfig_ReadFaultIs503(t *testing.T) {
	_, _, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	cfg := &models.DynamicSecretConfig{Name: "c", ProjectID: 1, EnvironmentID: 10, BackendType: "postgres"}
	require.NoError(t, db.Create(cfg).Error)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewDynamicSecretHandler(core.NewKeyorixCore(faulty))

	get := func(id uint) *httptest.ResponseRecorder {
		r := withFolderAdminCtx(withChiParam(
			httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d", id), nil), "id", fmt.Sprint(id)))
		w := httptest.NewRecorder()
		h.GetConfig(w, r)
		return w
	}

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetDynamicSecretConfig", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := get(cfg.ID)
	require.True(t, faulty.Fired(), "loadConfig's read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)

	assert.Equal(t, http.StatusNotFound, get(999999).Code, "a true not-found keeps its 404")
	assert.Equal(t, http.StatusOK, get(cfg.ID).Code)
}

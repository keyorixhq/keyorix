package handlers

// secrets_copy_read_fault_test.go — STORAGE-ERR-CLASS-4 item 5: CopySecret's source
// read answered a storage fault 500. The copy was never attempted, so it is the shared
// 503 storage_unavailable + Retry-After, and a true miss keeps its 404.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCopySecret_SourceReadFaultIs503(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	body := fmt.Sprintf(`{"environment_id":%d,"name":"copy"}`, fx.envID)

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := secretsDo(fh.CopySecret, http.MethodPost, body, fx.id(), secretsAdminID)
	require.True(t, faulty.Fired(), "the source read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)
	assert.NotContains(t, w.Body.String(), "cache_epoch", "the driver cause must not reach the client")

	w = secretsDo(fh.CopySecret, http.MethodPost, body, "999999", secretsAdminID)
	assert.Equal(t, http.StatusNotFound, w.Code, "a true miss keeps its 404: %s", w.Body.String())
}

package handlers

// storage_err_class4_sweep_test.go — STORAGE-ERR-CLASS-4 item 4: CreateFolder's parent
// read fault answered 404 "Parent folder not found" (the handler text-matches "not found"
// on a core wrapper that wrapped any read error). It is the shared 503 now.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCreateFolder_ParentReadFaultIs503(t *testing.T) {
	_, plain, db := freshFolderFixture(t)
	parent, err := plain.CreateFolder(t.Context(), 1, "parent", 1, 10, nil)
	require.NoError(t, err)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewFolderHandler(core.NewKeyorixCore(faulty))

	create := func(parentID uint) *httptest.ResponseRecorder {
		body := `{"name":"child","project_id":1,"environment_id":10,"parent_id":` + strings.TrimSpace(itoa(parentID)) + `}`
		r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders/", strings.NewReader(body)))
		w := httptest.NewRecorder()
		h.CreateFolder(w, r)
		return w
	}

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := create(parent.ID)
	require.True(t, faulty.Fired(), "the parent read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)

	assert.Equal(t, http.StatusNotFound, create(999999).Code, "a true miss keeps its 404")
}

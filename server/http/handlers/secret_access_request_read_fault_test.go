package handlers

// secret_access_request_read_fault_test.go — STORAGE-ERR-CLASS-4 item 2.
//
// CreateSecretAccessRequest's visibility pre-check and core.GetSecretAccessRequest folded
// every read error into "not found", so a storage fault told the requester the secret or
// request did not exist while nothing was done. A fault is now the shared 503
// storage_unavailable + Retry-After; a true not-found keeps its 404.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestCreateSecretAccessRequest_ReadFaultIs503(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	faulty := faultstorage.NewFaultyStorage(f.st, nil)
	h := NewCatalogHandler(core.NewKeyorixCore(faulty))

	create := func(secretID uint) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"secret_id":%d,"reason":"need it"}`, secretID)
		r := withUserCtxSAR(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)), f.requesterID)
		w := httptest.NewRecorder()
		h.CreateSecretAccessRequest(w, r)
		return w
	}

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := create(f.secretID)
	require.True(t, faulty.Fired(), "the pre-check's secret read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)

	assert.Equal(t, http.StatusNotFound, create(999999).Code, "a true not-found keeps its 404")
	assert.Equal(t, http.StatusCreated, create(f.secretID).Code, "the retried request succeeds once the fault clears")
}

func TestRequestSecretAccess_ReadFaultIsNotNotFound(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	faulty := faultstorage.NewFaultyStorage(f.st, nil)
	c := core.NewKeyorixCore(faulty)

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	_, err := c.RequestSecretAccess(t.Context(), f.secretID, f.requesterID, "need it")
	require.True(t, faulty.Fired())
	faulty.Arm(nil)
	require.Error(t, err)
	assert.True(t, core.IsStorageReadUnavailable(err), "a read fault must be the storage-unavailable class, got: %v", err)

	_, err = c.RequestSecretAccess(t.Context(), 999999, f.requesterID, "need it")
	require.Error(t, err)
	assert.False(t, core.IsStorageReadUnavailable(err), "a true not-found stays a not-found: %v", err)
}

func TestGetSecretAccessRequest_ReadFaultIs503(t *testing.T) {
	f := newSecretAccessRequestFixture(t)
	ar, err := f.core.RequestSecretAccess(t.Context(), f.secretID, f.requesterID, "need it")
	require.NoError(t, err)
	faulty := faultstorage.NewFaultyStorage(f.st, nil)
	h := NewCatalogHandler(core.NewKeyorixCore(faulty))

	get := func(id uint) *httptest.ResponseRecorder {
		r := withUserCtxSAR(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "requestId", fmt.Sprint(id)), f.requesterID)
		w := httptest.NewRecorder()
		h.GetSecretAccessRequest(w, r)
		return w
	}

	faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
	w := get(ar.ID)
	require.True(t, faulty.Fired(), "the request read must be reached")
	faulty.Arm(nil)
	requireStorageUnavailable503(t, w)

	assert.Equal(t, http.StatusNotFound, get(999999).Code, "a true not-found keeps its 404")
	assert.Equal(t, http.StatusOK, get(ar.ID).Code)
}

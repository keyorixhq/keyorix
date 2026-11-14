package handlers

// secrets_crud_read_fault_test.go — ERRMAP-CATALOG-NOV-1 item 4. Core answers a storage
// READ fault with core.ErrStorageReadUnavailable; the secret create, read and copy routes
// answered it 500 generic. They answer the shared 503 storage_unavailable + Retry-After:
// the operation was not applied (or not answered), a retry is right, and the driver cause
// stays out of the body.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func TestSecretRoutes_ReadFaultIs503(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)
	secret := &models.SecretNode{ID: fx.secretID, Name: "ec-secret", ProjectID: fx.projectID, EnvironmentID: fx.envID}

	do := func(fn http.HandlerFunc, method, target, body string, withRef bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiParam(withUserCtxID(req, secretsAdminID, "actor"), "id", fx.id())
		if withRef {
			req = req.WithContext(middleware.WithResolvedSecretRef(req.Context(), secret))
		}
		w := httptest.NewRecorder()
		fn(w, req)
		return w
	}

	cases := []struct {
		name   string
		method string // storage method the fault is armed on
		nth    int
		call   func() *httptest.ResponseRecorder
	}{
		{"GetSecret", "GetSecret", 1, func() *httptest.ResponseRecorder {
			return do(h.GetSecret, http.MethodGet, "/", "", false)
		}},
		{"GetSecret value", "GetSecret", 1, func() *httptest.ResponseRecorder {
			return do(h.GetSecret, http.MethodGet, "/?include_value=true", "", false)
		}},
		{"GetSecretValueByRef", "GetSecret", 1, func() *httptest.ResponseRecorder {
			return do(h.GetSecretValueByRef, http.MethodGet, "/", "", true)
		}},
		{"CreateSecret parent folder read", "GetSecret", 1, func() *httptest.ResponseRecorder {
			body := fmt.Sprintf(`{"name":"made","type":"static","value":"v","project_id":%d,"environment_id":%d,"parent_id":%d}`, fx.projectID, fx.envID, fx.secretID)
			return do(h.CreateSecret, http.MethodPost, "/", body, false)
		}},
		{"CopySecret", "GetSecret", 2, func() *httptest.ResponseRecorder {
			return do(h.CopySecret, http.MethodPost, "/", fmt.Sprintf(`{"environment_id":%d,"name":"copy"}`, fx.envID), false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: tc.nth, Kind: faultstorage.KindError, Err: errSchemaLeak})
			w := tc.call()
			fired := faulty.Fired()
			faulty.Arm(nil)
			require.True(t, fired, "the %s read fault must be reached", tc.method)
			requireStorageUnavailable503(t, w)
		})
	}
}

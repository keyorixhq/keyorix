package handlers

// secrets_classify_rotate_byname_fault_test.go — ERRMAP-TAILS-NOV-4 item 3. Core wraps a
// storage READ fault of the secret behind PATCH /secrets/{id}/classification, PATCH
// /secrets/{id}/auto-rotate and GET /secrets/by-name as core.ErrStorageReadUnavailable;
// the handlers answered the first two 500 and the third 500 "Failed to get secret". They
// answer the shared 503 storage_unavailable + Retry-After, the driver cause stays out of the
// body, and a true not-found stays 404 on the same routes.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

func TestClassifyAutoRotateByName_ReadFaultIs503(t *testing.T) {
	_, db, fx := newSecretsHandlerWithDB(t, "en")
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h, err := NewSecretHandler(core.NewKeyorixCore(faulty))
	require.NoError(t, err)

	byName := func(name string, machine bool) *httptest.ResponseRecorder {
		target := fmt.Sprintf("/?name=%s&project_id=%d&environment_id=%d", name, fx.projectID, fx.envID)
		req := withUserCtxID(httptest.NewRequest(http.MethodGet, target, nil), secretsAdminID, "actor")
		if machine {
			mid := uint(1)
			uc := &customMiddleware.UserContext{UserID: secretsAdminID, Username: "actor", MachineIdentityID: &mid}
			req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), uc))
		}
		w := httptest.NewRecorder()
		h.GetSecretByName(w, req)
		return w
	}

	cases := []struct {
		name  string
		fault string
		call  func() *httptest.ResponseRecorder
	}{
		{"ClassifySecret", "GetSecret", func() *httptest.ResponseRecorder {
			return secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, fx.id(), secretsAdminID)
		}},
		{"SetAutoRotate", "GetSecret", func() *httptest.ResponseRecorder {
			return secretsDo(h.SetAutoRotate, http.MethodPatch, `{"enabled":false}`, fx.id(), secretsAdminID)
		}},
		{"GetSecretByName", "GetSecretByName", func() *httptest.ResponseRecorder { return byName("ec-secret", false) }},
		{"GetSecretByName as a machine principal", "GetSecretByName", func() *httptest.ResponseRecorder { return byName("ec-secret", true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
			w := tc.call()
			fired := faulty.Fired()
			faulty.Arm(nil)
			require.True(t, fired, "the %s read fault must be reached", tc.fault)
			requireStorageUnavailable503(t, w)
		})
	}

	t.Run("a true not-found is still 404 on the same routes", func(t *testing.T) {
		for name, w := range map[string]*httptest.ResponseRecorder{
			"classify":           secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, secretsMissingID, secretsAdminID),
			"auto-rotate":        secretsDo(h.SetAutoRotate, http.MethodPatch, `{"enabled":false}`, secretsMissingID, secretsAdminID),
			"by-name":            byName("no-such-secret", false),
			"by-name as machine": byName("no-such-secret", true),
		} {
			assert.Equal(t, http.StatusNotFound, w.Code, "%s: %s", name, w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"), name)
		}
	})

	t.Run("the retried classification succeeds after the fault clears", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
		w := secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, fx.id(), secretsAdminID)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		faulty.Arm(nil)
		w = secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, fx.id(), secretsAdminID)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
}

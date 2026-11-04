package handlers

// dynamic_secrets_core_fault_test.go — REVFIX-3964-2 (review F1 on #3964).
//
// loadConfig/loadLease answer 503 for the handler's own pre-read (storage_err_class3_test.go),
// but the reads core makes INSIDE CreateDynamicSecretConfig, IssueLease, RenewLease,
// ClassifyDynamicSecretConfig and SetDynamicSecretConfigEnabled (the environment check,
// the config/lease re-read, requireLiveProjectAndEnvironment) now return
// core.ErrStorageReadUnavailable on a fault. Those five handlers went straight to a fixed
// 400/502, so a database outage read as a caller error. Each one must answer the shared
// 503 storage_unavailable + Retry-After, like RevokeLease.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestDynamicSecretHandlers_CoreReadFaultIs503(t *testing.T) {
	_, _, db := freshFolderFixture(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	cfg := &models.DynamicSecretConfig{Name: "c", ProjectID: 1, EnvironmentID: 10, BackendType: "postgres"}
	require.NoError(t, db.Create(cfg).Error)
	lease := &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: "lease-fault", ProjectID: 1, EnvironmentID: 10, Status: "active",
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, db.Create(lease).Error)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewDynamicSecretHandler(core.NewKeyorixCore(faulty))
	cfgID := fmt.Sprint(cfg.ID)

	cases := []struct {
		name   string
		method string // the core-internal read that faults
		nth    int    // which call of it (1 = the handler's own loadConfig pre-read)
		call   func(w http.ResponseWriter)
	}{
		{"CreateConfig/environment check", "GetEnvironment", 1, func(w http.ResponseWriter) {
			body := `{"name":"n","project_id":1,"environment_id":10,"backend_type":"postgres","admin_dsn":"postgres://a@db.example/x"}`
			h.CreateConfig(w, withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewBufferString(body))))
		}},
		{"IssueLease/project liveness", "GetProject", 1, func(w http.ResponseWriter) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/"+cfgID+"/issue", nil)
			h.IssueLease(w, withFolderAdminCtx(withChiParam(r, "id", cfgID)))
		}},
		{"RenewLease/lease re-read", "GetDynamicSecretLease", 2, func(w http.ResponseWriter) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/lease-fault/renew", nil)
			h.RenewLease(w, withFolderAdminCtx(withChiParam(r, "leaseID", lease.LeaseID)))
		}},
		{"ClassifyConfig/config re-read", "GetDynamicSecretConfig", 2, func(w http.ResponseWriter) {
			r := httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/"+cfgID+"/classification", bytes.NewBufferString(`{"classification":"internal"}`))
			h.ClassifyConfig(w, withFolderAdminCtx(withChiParam(r, "id", cfgID)))
		}},
		{"SetConfigEnabled/config re-read", "GetDynamicSecretConfig", 2, func(w http.ResponseWriter) {
			r := httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/"+cfgID+"/enabled", bytes.NewBufferString(`{"enabled":false}`))
			h.SetConfigEnabled(w, withFolderAdminCtx(withChiParam(r, "id", cfgID)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: tc.nth, Kind: faultstorage.KindError, Err: errSchemaLeak})
			w := httptest.NewRecorder()
			tc.call(w)
			require.True(t, faulty.Fired(), "the core-internal %s read must be reached", tc.method)
			faulty.Arm(nil)
			requireStorageUnavailable503(t, w)
		})
	}
}

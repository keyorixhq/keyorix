package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userCtxForTest returns a request with a UserContext injected, simulating an authenticated
// caller without constructing a full core service.
func userCtxForTest(r *http.Request) *http.Request {
	uc := &middleware.UserContext{UserID: 1, Username: "admin", Roles: []string{"admin"}}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// TestMakeSystemInfoHandler_Unauthenticated verifies a request without a user context
// is rejected with 401.
func TestMakeSystemInfoHandler_Unauthenticated(t *testing.T) {
	cfg := &config.Config{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg)(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestMakeSystemInfoHandler_Authenticated verifies a request with a user context returns
// 200 with the expected system info fields.
func TestMakeSystemInfoHandler_Authenticated(t *testing.T) {
	cfg := &config.Config{}
	cfg.Environment = "test"
	cfg.Storage.Type = "sqlite"
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg)(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool), "response must carry success:true")

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "data field must be a JSON object")
	assert.Equal(t, "test", data["environment"])
	assert.Contains(t, data, "go_version")
	assert.Contains(t, data, "uptime")
	assert.Contains(t, data, "features")
	assert.Contains(t, data, "database")
	assert.Contains(t, data, "security")
}

// TestMakeSystemInfoHandler_TLSFeaturesReflectConfig verifies that TLS-related feature
// flags in the response reflect the config.
func TestMakeSystemInfoHandler_TLSFeaturesReflectConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.GRPC.Enabled = true

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	data := resp["data"].(map[string]interface{})
	features := data["features"].(map[string]interface{})
	assert.True(t, features["tls_enabled"].(bool), "tls_enabled must reflect config")
	assert.True(t, features["grpc_enabled"].(bool), "grpc_enabled must reflect config")
}

// TestMakeSystemInfoHandler_KeylessRecoveryModeReflectsConfig exercises
// docs/design-b2-recover-admin.md §5: the keyless-mode boolean must be
// surfaced in GET /system/info so a customer's own compliance scanning can
// catch a misconfigured install, and must default to false when unset.
func TestMakeSystemInfoHandler_KeylessRecoveryModeReflectsConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.RecoverAdmin.KeylessMode = true

	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	data := resp["data"].(map[string]interface{})
	security := data["security"].(map[string]interface{})
	assert.True(t, security["keyless_recovery_mode"].(bool), "keyless_recovery_mode must reflect config when enabled")

	// Default (zero-value config) must be false, never a silent true.
	cfg2 := &config.Config{}
	req2 := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr2 := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg2)(rr2, req2)
	var resp2 map[string]interface{}
	require.NoError(t, json.NewDecoder(rr2.Body).Decode(&resp2))
	data2 := resp2["data"].(map[string]interface{})
	security2 := data2["security"].(map[string]interface{})
	assert.False(t, security2["keyless_recovery_mode"].(bool), "keyless_recovery_mode must default to false")
}

// TestGetMetrics_Unauthenticated verifies a request without a user context is 401.
func TestGetMetrics_Unauthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/metrics", nil)
	rr := httptest.NewRecorder()
	GetMetrics(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestGetMetrics_Authenticated verifies the metrics endpoint returns 200 with the
// expected top-level structure for an authenticated caller.
func TestGetMetrics_Authenticated(t *testing.T) {
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/metrics", nil))
	rr := httptest.NewRecorder()
	GetMetrics(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, data, "memory")
	assert.Contains(t, data, "goroutines")
	assert.Contains(t, data, "uptime")
}

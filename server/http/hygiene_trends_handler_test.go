package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cfg shared by all hygiene-trends handler tests.
var hygieneTrendsCfg = &config.Config{
	Server: config.ServerConfig{
		HTTP: config.ServerInstanceConfig{
			Enabled: true,
			Port:    "8080",
		},
	},
}

// TestGetCredentialTrends_DefaultDays verifies that GET /compliance/credential-trends
// with no query parameter returns 200 and a JSON response with days=30.
func TestGetCredentialTrends_DefaultDays(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(hygieneTrendsCfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/credential-trends", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data struct {
			Days   int   `json:"days"`
			Points []any `json:"points"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, 30, body.Data.Days)
	assert.NotNil(t, body.Data.Points)
}

// TestGetCredentialTrends_Days90 verifies that ?days=90 is honoured and the
// response carries days=90.
func TestGetCredentialTrends_Days90(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(hygieneTrendsCfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/credential-trends?days=90", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data struct {
			Days int `json:"days"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, 90, body.Data.Days)
}

// TestGetCredentialTrends_InvalidDaysDefaultsTo30 verifies that an invalid
// ?days=invalid parameter silently defaults to 30.
func TestGetCredentialTrends_InvalidDaysDefaultsTo30(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(hygieneTrendsCfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/credential-trends?days=invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data struct {
			Days int `json:"days"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	// core clamps anything != 30/60/90 to 30
	assert.Equal(t, 30, body.Data.Days)
}

// TestRecordHygieneSnapshot_ReturnsPoint verifies that
// POST /admin/jobs/record-hygiene-snapshot returns 200 and a trend point payload.
func TestRecordHygieneSnapshot_ReturnsPoint(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(hygieneTrendsCfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/record-hygiene-snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data struct {
			Date          string `json:"date"`
			StalePATs     int    `json:"stale_pats"`
			ExpiredPATs   int    `json:"expired_pats"`
			StaleMachines int    `json:"stale_machines"`
			TotalPATs     int    `json:"total_pats"`
			TotalMachines int    `json:"total_machines"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.NotEmpty(t, body.Data.Date, "trend point should carry a date")
}

// TestGetCredentialTrends_Unauthenticated verifies that an unauthenticated
// request returns 401.
func TestGetCredentialTrends_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	router, err := NewRouter(hygieneTrendsCfg, c)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/credential-trends", nil)
	// No Authorization header.
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

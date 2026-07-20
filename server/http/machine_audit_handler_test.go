// machine_audit_handler_test.go — integration tests for the machine identity audit
// report endpoints:
//   - GET /api/v1/machine-identities/audit    (JSON)
//   - GET /api/v1/machine-identities/audit.csv (CSV)
package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initMachineAuditTest initializes i18n and returns a cleanup function.
func initMachineAuditTest(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
}

// newMachineAuditServer spins up a full HTTP router backed by the given core.
func newMachineAuditServer(t *testing.T, c *core.KeyorixCore) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	return httptest.NewServer(router)
}

// authGet issues an authenticated GET request and returns the response.
func authGetMachineAudit(t *testing.T, srv *httptest.Server, token, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// Test 1: GET /machine-identities/audit → 200, JSON with expected fields.
func TestMachineAuditReport_JSON_200(t *testing.T) {
	initMachineAuditTest(t)
	c := newTestCore(t)
	token := createTestToken(t, c)
	srv := newMachineAuditServer(t, c)
	defer srv.Close()

	resp := authGetMachineAudit(t, srv, token, "/api/v1/machine-identities/audit")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var body struct {
		Data struct {
			TotalCount   int `json:"total_count"`
			StaleCount   int `json:"stale_count"`
			RevokedCount int `json:"revoked_count"`
			Machines     any `json:"machines"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.GreaterOrEqual(t, body.Data.TotalCount, 0)
	assert.GreaterOrEqual(t, body.Data.StaleCount, 0)
	assert.GreaterOrEqual(t, body.Data.RevokedCount, 0)
	assert.NotNil(t, body.Data.Machines)
}

// Test 2: GET /machine-identities/audit.csv → 200, text/csv.
func TestMachineAuditReport_CSV_200(t *testing.T) {
	initMachineAuditTest(t)
	c := newTestCore(t)
	token := createTestToken(t, c)
	srv := newMachineAuditServer(t, c)
	defer srv.Close()

	resp := authGetMachineAudit(t, srv, token, "/api/v1/machine-identities/audit.csv")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/csv")
	assert.Contains(t, resp.Header.Get("Content-Disposition"), "machine-audit.csv")

	// The body should contain the CSV header row.
	rawBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	body := strings.TrimSpace(string(rawBody))
	assert.Contains(t, body, "machine_id")
	assert.Contains(t, body, "credential_count")
	assert.Contains(t, body, "is_stale")
}

// Test 3: Create a machine identity, then GET audit — it appears in the report.
func TestMachineAuditReport_ContainsCreatedMachine(t *testing.T) {
	initMachineAuditTest(t)
	c := newTestCore(t)
	token := createTestToken(t, c)
	srv := newMachineAuditServer(t, c)
	defer srv.Close()

	// Create a project first (bootstrap already creates project ID=1).
	ctx := context.Background()
	machine, err := c.CreateMachineIdentity(ctx, 1, "audit-test-bot", "ci", "robot for audit test", "", 1)
	require.NoError(t, err)
	require.NotNil(t, machine)

	resp := authGetMachineAudit(t, srv, token, "/api/v1/machine-identities/audit")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Data struct {
			TotalCount int `json:"total_count"`
			Machines   []struct {
				MachineID uint   `json:"machine_id"`
				Name      string `json:"name"`
				IsStale   bool   `json:"is_stale"`
			} `json:"machines"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.GreaterOrEqual(t, body.Data.TotalCount, 1)

	found := false
	for _, m := range body.Data.Machines {
		if m.MachineID == machine.ID {
			assert.Equal(t, "audit-test-bot", m.Name)
			found = true
		}
	}
	assert.True(t, found, "created machine identity should appear in audit report")
}

// Test 4: Machine with no credentials is reported as stale (LastUsedAt nil).
func TestMachineAuditReport_NeverUsedIsStale(t *testing.T) {
	initMachineAuditTest(t)
	c := newTestCore(t)
	token := createTestToken(t, c)
	srv := newMachineAuditServer(t, c)
	defer srv.Close()

	ctx := context.Background()
	machine, err := c.CreateMachineIdentity(ctx, 1, "stale-bot", "ci", "never used", "", 1)
	require.NoError(t, err)

	resp := authGetMachineAudit(t, srv, token, "/api/v1/machine-identities/audit")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Data struct {
			StaleCount int `json:"stale_count"`
			Machines   []struct {
				MachineID int  `json:"machine_id"`
				IsStale   bool `json:"is_stale"`
			} `json:"machines"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Greater(t, body.Data.StaleCount, 0)

	for _, m := range body.Data.Machines {
		if uint(m.MachineID) == machine.ID {
			assert.True(t, m.IsStale, "machine with no credentials should be stale")
		}
	}
}

// Test 5: Unauthenticated request → 401.
func TestMachineAuditReport_Unauthenticated_401(t *testing.T) {
	initMachineAuditTest(t)
	c := newTestCore(t)
	srv := newMachineAuditServer(t, c)
	defer srv.Close()

	// JSON endpoint.
	resp := authGetMachineAudit(t, srv, "", "/api/v1/machine-identities/audit")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// CSV endpoint.
	resp2 := authGetMachineAudit(t, srv, "", "/api/v1/machine-identities/audit.csv")
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

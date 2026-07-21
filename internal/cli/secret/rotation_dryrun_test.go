package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotationSimulateStub creates a test server that returns a pre-canned dry-run result.
func rotationSimulateStub(t *testing.T, valid bool) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/v1/secrets/42/rotation/simulate":
			result := rotationDryRunResult{
				SecretID:    42,
				SecretName:  "my-secret",
				Backend:     "pg",
				Ref:         "myrole",
				Valid:       valid,
				SimulatedAt: "2026-01-01T12:00:00Z",
				Checks: []rotationDryRunCheck{
					{Name: "policy_exists", Passed: valid, Message: "covered by policy \"30-day\" (id 1)"},
					{Name: "backend_known", Passed: valid, Message: "backend \"pg\" is registered"},
					{Name: "ref_non_empty", Passed: true, Message: "ref \"myrole\" is non-empty"},
					{Name: "ref_valid", Passed: true, Message: "ref \"myrole\" passed metacharacter validation"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": result})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// TestRunRotationSimulate_Valid verifies that runRotationSimulate succeeds when the
// server returns a valid=true result.
func TestRunRotationSimulate_Valid(t *testing.T) {
	rc, done := rotationSimulateStub(t, true)
	defer done()
	err := runRotationSimulate(context.Background(), rc, 42)
	require.NoError(t, err)
}

// TestRunRotationSimulate_Invalid verifies that runRotationSimulate succeeds (no error)
// even when the server returns valid=false (the failure is communicated via the output,
// not a Go error).
func TestRunRotationSimulate_Invalid(t *testing.T) {
	rc, done := rotationSimulateStub(t, false)
	defer done()
	err := runRotationSimulate(context.Background(), rc, 42)
	require.NoError(t, err)
}

// TestRunRotationSimulate_NotFound verifies that runRotationSimulate returns an error
// when the server responds with 404.
func TestRunRotationSimulate_NotFound(t *testing.T) {
	rc, done := rotationSimulateStub(t, true)
	defer done()
	err := runRotationSimulate(context.Background(), rc, 9999)
	require.Error(t, err)
}

// TestPrintDryRunResult_Valid verifies the output helpers don't panic on a valid result.
func TestPrintDryRunResult_Valid(t *testing.T) {
	r := &rotationDryRunResult{
		SecretID:   1,
		SecretName: "s",
		Backend:    "pg",
		Ref:        "role",
		Valid:      true,
		Checks: []rotationDryRunCheck{
			{Name: "policy_exists", Passed: true, Message: "ok"},
			{Name: "backend_known", Passed: true, Message: "ok"},
			{Name: "ref_non_empty", Passed: true, Message: "ok"},
			{Name: "ref_valid", Passed: true, Message: "ok"},
		},
	}
	// should not panic
	printDryRunResult(r)
}

// TestPrintDryRunResult_Invalid verifies the output helpers handle valid=false.
func TestPrintDryRunResult_Invalid(t *testing.T) {
	r := &rotationDryRunResult{
		SecretID:   1,
		SecretName: "s",
		Valid:      false,
		Checks: []rotationDryRunCheck{
			{Name: "policy_exists", Passed: false, Message: "no active rotation policy"},
		},
	}
	printDryRunResult(r)
}

// TestRotationSimulateCmd_NoID verifies that the command requires --id.
func TestRotationSimulateCmd_NoID(t *testing.T) {
	// Reset the flag to 0 (it may have been set by a prior test).
	rotationSimulateID = 0
	err := rotationSimulateCmd.RunE(rotationSimulateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

// TestRotationSimulateCmd_NoServer verifies that the command fails gracefully when
// no server is configured.
func TestRotationSimulateCmd_NoServer(t *testing.T) {
	// Unset server env vars so NewRemoteClient returns false.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	rotationSimulateID = 42
	t.Cleanup(func() { rotationSimulateID = 0 })
	err := rotationSimulateCmd.RunE(rotationSimulateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

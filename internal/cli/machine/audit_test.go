package machine

import (
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureAuditStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, _ := io.ReadAll(r)
	return string(out)
}

func newAuditRemoteClient(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

const machineAuditPayload = `{"data":{
	"generated_at":"2026-06-05T12:00:00Z",
	"total_count":2,
	"stale_count":1,
	"revoked_count":0,
	"machines":[
		{"machine_id":1,"name":"ci-runner","description":"main ci","credential_count":3,"last_used_at":"2026-06-05T12:00:00Z","is_stale":false,"is_revoked":false,"created_at":"2026-01-01T00:00:00Z"},
		{"machine_id":2,"name":"old-bot","description":"legacy","credential_count":0,"is_stale":true,"is_revoked":false,"created_at":"2025-01-01T00:00:00Z"}
	]
}}`

func TestFetchMachineAuditReport(t *testing.T) {
	rc, done := newAuditRemoteClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/machine-identities/audit", r.URL.Path)
		_, _ = w.Write([]byte(machineAuditPayload))
	})
	defer done()

	report, err := fetchMachineAuditReport(context.Background(), rc)
	require.NoError(t, err)
	assert.Equal(t, 2, report.TotalCount)
	assert.Equal(t, 1, report.StaleCount)
	assert.Len(t, report.Machines, 2)
	assert.Equal(t, "ci-runner", report.Machines[0].Name)
	assert.False(t, report.Machines[0].IsStale)
	assert.True(t, report.Machines[1].IsStale)
}

func TestFetchMachineAuditReport_ServerError(t *testing.T) {
	rc, done := newAuditRemoteClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer done()

	_, err := fetchMachineAuditReport(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "machine audit report")
}

func TestPrintMachineAuditJSON(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	report := &core.MachineAuditReport{
		TotalCount:   1,
		StaleCount:   0,
		RevokedCount: 0,
		Machines: []core.MachineAuditRow{
			{MachineID: 1, Name: "runner", CredentialCount: 2, IsStale: false, CreatedAt: ts},
		},
	}

	out := captureAuditStdout(t, func() {
		require.NoError(t, printMachineAuditJSON(report))
	})

	assert.Contains(t, out, `"total_count": 1`)
	assert.Contains(t, out, `"name": "runner"`)
	assert.Contains(t, out, `"credential_count": 2`)
}

func TestPrintMachineAuditCSV_WithLastUsed(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	report := &core.MachineAuditReport{
		Machines: []core.MachineAuditRow{
			{
				MachineID:       42,
				Name:            "ci-runner",
				Description:     "main ci",
				CredentialCount: 3,
				LastUsedAt:      &lastUsed,
				IsStale:         false,
				IsRevoked:       false,
				CreatedAt:       ts,
			},
		},
	}

	out := captureAuditStdout(t, func() {
		require.NoError(t, printMachineAuditCSV(report))
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	assert.Equal(t, "machine_id,name,description,credential_count,last_used_at,is_stale,is_revoked,created_at", lines[0])
	assert.Contains(t, lines[1], "42,ci-runner,main ci,3,2026-06-05T12:00:00Z,false,false,")
}

func TestPrintMachineAuditCSV_NoLastUsed(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	report := &core.MachineAuditReport{
		Machines: []core.MachineAuditRow{
			{
				MachineID:       7,
				Name:            "old-bot",
				CredentialCount: 0,
				LastUsedAt:      nil,
				IsStale:         true,
				CreatedAt:       ts,
			},
		},
	}

	out := captureAuditStdout(t, func() {
		require.NoError(t, printMachineAuditCSV(report))
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	fields := strings.SplitN(lines[1], ",", 8)
	assert.Equal(t, "7", fields[0])
	assert.Equal(t, "", fields[4]) // last_used_at empty when nil
	assert.Equal(t, "true", fields[5])
}

// TestPrintMachineAuditCSV_FormulaInjection — a machine name/description starting with a
// formula-injection character (=, +, -, @) must be escaped with a leading single quote
// in the CSV export (G49: CSVSafe() formula-injection escaping).
func TestPrintMachineAuditCSV_FormulaInjection(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	report := &core.MachineAuditReport{
		Machines: []core.MachineAuditRow{
			{
				MachineID:       1,
				Name:            "=cmd|' /C calc'!A1",
				Description:     "@SUM(1+1)",
				CredentialCount: 1,
				CreatedAt:       ts,
			},
		},
	}

	out := captureAuditStdout(t, func() {
		require.NoError(t, printMachineAuditCSV(report))
	})

	r := csv.NewReader(strings.NewReader(out))
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2, "header + 1 data row")
	// header: machine_id, name, description, credential_count, last_used_at, is_stale, is_revoked, created_at
	assert.True(t, strings.HasPrefix(records[1][1], "'"), "name formula-injection prefix must be neutralized, got %q", records[1][1])
	assert.True(t, strings.HasPrefix(records[1][2], "'"), "description formula-injection prefix must be neutralized, got %q", records[1][2])
}

func TestPrintMachineAuditCSV_Empty(t *testing.T) {
	report := &core.MachineAuditReport{Machines: []core.MachineAuditRow{}}

	out := captureAuditStdout(t, func() {
		require.NoError(t, printMachineAuditCSV(report))
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "machine_id")
}

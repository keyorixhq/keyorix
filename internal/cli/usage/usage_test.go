// usage_test.go exercises runShow, runShowRemote, and the printReport
// branches (table/json format, sorting, empty-state) that
// terminal_injection_test.go's single G69 regression test doesn't cover.
package usage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFlags restores the package-level flag vars to their zero/default
// values after a test mutates them, so tests don't leak state into each
// other (these are cobra flag-backed globals, not per-test locals).
func resetFlags(t *testing.T) {
	t.Helper()
	origDays, origProjectID, origFormat := flagDays, flagProjectID, flagFormat
	t.Cleanup(func() {
		flagDays, flagProjectID, flagFormat = origDays, origProjectID, origFormat
	})
}

func TestRunShowRemote_Success(t *testing.T) {
	resetFlags(t)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok")
		}
		report := storage.UsageReport{
			WindowDays:  7,
			GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Projects: []storage.ProjectUsageStat{
				{ProjectID: 1, ProjectName: "alpha", SecretCount: 2, ReadsInWindow: 5, UniqueReaders: 1},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]interface{}{"data": report})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "tok")
	require.True(t, ok)

	flagDays = 7
	flagProjectID = 42
	flagFormat = "table"

	out, err := captureStdout(t, func() error { return runShowRemote(context.Background(), rc) })
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/admin/usage?days=7&project_id=42", gotPath)
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "last 7 days")
}

func TestRunShowRemote_OmitsProjectIDWhenZero(t *testing.T) {
	resetFlags(t)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		body, err := json.Marshal(map[string]interface{}{"data": storage.UsageReport{WindowDays: 30}})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "tok")
	require.True(t, ok)

	flagDays = 30
	flagProjectID = 0
	flagFormat = "table"

	_, err := captureStdout(t, func() error { return runShowRemote(context.Background(), rc) })
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/admin/usage?days=30", gotPath)
}

func TestRunShowRemote_ServerError(t *testing.T) {
	resetFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "tok")
	require.True(t, ok)

	flagDays = 30
	flagFormat = "table"

	err := runShowRemote(context.Background(), rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch usage report")
}

// TestRunShow_RemoteMode drives runShow's cobra RunE entry point end to end
// via env-var-resolved remote mode (KEYORIX_SERVER/KEYORIX_TOKEN), verifying
// it dispatches to runShowRemote rather than the embedded-storage path.
func TestRunShow_RemoteMode(t *testing.T) {
	resetFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/admin/usage?days=15", r.URL.RequestURI())
		body, err := json.Marshal(map[string]interface{}{
			"data": storage.UsageReport{WindowDays: 15, GeneratedAt: time.Now()},
		})
		require.NoError(t, err)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origServer, hadServer := os.LookupEnv("KEYORIX_SERVER")
	origToken, hadToken := os.LookupEnv("KEYORIX_TOKEN")
	t.Cleanup(func() {
		if hadServer {
			_ = os.Setenv("KEYORIX_SERVER", origServer)
		} else {
			_ = os.Unsetenv("KEYORIX_SERVER")
		}
		if hadToken {
			_ = os.Setenv("KEYORIX_TOKEN", origToken)
		} else {
			_ = os.Unsetenv("KEYORIX_TOKEN")
		}
	})
	require.NoError(t, os.Setenv("KEYORIX_SERVER", srv.URL))
	require.NoError(t, os.Setenv("KEYORIX_TOKEN", "tok"))

	flagDays = 15
	flagProjectID = 0
	flagFormat = "table"

	out, err := captureStdout(t, func() error { return runShow(nil, nil) })
	require.NoError(t, err)
	assert.Contains(t, out, "last 15 days")
}

// TestRunShow_LocalModeStorageInitFailure drives runShow's embedded/local-mode
// branch (no remote config resolved) through common.InitializeStorage's own
// config.Load failure. HOME is redirected to an empty temp dir so this does
// not depend on (or get derailed by) a real ~/.keyorix/cli.yaml that might be
// present on the machine running the test — see the "Local ~/.keyorix/cli.yaml
// breaks CLI tests" pitfall: without this, a real connect config on the
// developer's machine could route this at a live remote server instead of
// exercising the local branch this test targets.
func TestRunShow_LocalModeStorageInitFailure(t *testing.T) {
	resetFlags(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")

	flagDays = 30
	flagProjectID = 0
	flagFormat = "table"

	err := runShow(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestPrintReport_JSONFormat(t *testing.T) {
	resetFlags(t)
	flagFormat = "json"
	report := &storage.UsageReport{
		WindowDays:  9,
		GeneratedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		Projects: []storage.ProjectUsageStat{
			{ProjectID: 3, ProjectName: "gamma", SecretCount: 1, ReadsInWindow: 2, UniqueReaders: 1},
		},
	}
	out, err := captureStdout(t, func() error { return printReport(report) })
	require.NoError(t, err)

	var decoded storage.UsageReport
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, 9, decoded.WindowDays)
	require.Len(t, decoded.Projects, 1)
	assert.Equal(t, "gamma", decoded.Projects[0].ProjectName)
}

func TestPrintReport_EmptyProjectsShowsNoData(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"
	report := &storage.UsageReport{WindowDays: 30, GeneratedAt: time.Now()}
	out, err := captureStdout(t, func() error { return printReport(report) })
	require.NoError(t, err)
	assert.Contains(t, out, "(no data)")
}

// TestPrintReport_SortsByNameThenProjectID exercises both branches of the
// sort.Slice comparator: names differ (primary key), and names are equal so
// it must fall back to comparing ProjectID.
func TestPrintReport_SortsByNameThenProjectID(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"
	report := &storage.UsageReport{
		WindowDays:  30,
		GeneratedAt: time.Now(),
		Projects: []storage.ProjectUsageStat{
			// SecretCount differs between the two same-named projects so
			// their printed rows are distinguishable, letting the test
			// confirm the ProjectID tie-break actually reordered them
			// (rather than just preserving input order coincidentally).
			{ProjectID: 20, ProjectName: "dup", SecretCount: 99},
			{ProjectID: 2, ProjectName: "zeta", SecretCount: 1},
			{ProjectID: 10, ProjectName: "dup", SecretCount: 1},
			{ProjectID: 1, ProjectName: "alpha", SecretCount: 1},
		},
	}
	out, err := captureStdout(t, func() error { return printReport(report) })
	require.NoError(t, err)

	var dataLines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "alpha") || strings.HasPrefix(line, "dup") || strings.HasPrefix(line, "zeta") {
			dataLines = append(dataLines, line)
		}
	}
	require.Len(t, dataLines, 4)
	// Primary key (name) orders alpha < dup < dup < zeta; secondary key
	// (ProjectID) breaks the "dup"/"dup" tie so ID 10 (SecretCount 1)
	// precedes ID 20 (SecretCount 99).
	assert.True(t, strings.HasPrefix(dataLines[0], "alpha"))
	// tabwriter renders tabs as column-aligned spaces, not literal '\t', so
	// match on the distinguishing SecretCount field with flexible spacing.
	dupRow10 := regexp.MustCompile(`^dup\s+1\s+0\s+0$`)
	dupRow20 := regexp.MustCompile(`^dup\s+99\s+0\s+0$`)
	assert.Truef(t, dupRow10.MatchString(dataLines[1]), "want ID-10 row (count 1) first, got %q", dataLines[1])
	assert.Truef(t, dupRow20.MatchString(dataLines[2]), "want ID-20 row (count 99) second, got %q", dataLines[2])
	assert.True(t, strings.HasPrefix(dataLines[3], "zeta"))
}

// TestPrintReport_EmptyProjectNameFallsBackToProjectID covers the
// SanitizeForTerminal-emptied name branch, where printReport substitutes a
// "(project N)" placeholder rather than printing a blank cell.
func TestPrintReport_EmptyProjectNameFallsBackToProjectID(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"
	report := &storage.UsageReport{
		WindowDays:  30,
		GeneratedAt: time.Now(),
		Projects:    []storage.ProjectUsageStat{{ProjectID: 7, ProjectName: "\x1b"}},
	}
	out, err := captureStdout(t, func() error { return printReport(report) })
	require.NoError(t, err)
	assert.Contains(t, out, "(project 7)")
}

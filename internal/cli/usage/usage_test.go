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
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

// setupEmbeddedUsageMode points config.Load("") at a temp-dir keyorix.yaml
// (local/embedded SQLite storage) and clears remote-mode signals, mirroring
// internal/cli/rbac's setupEmbeddedMode helper. HOME is also redirected so
// common.NewRemoteClient() can't pick up a real ~/.keyorix/cli.yaml on the
// machine running the test (see TestRunShow_LocalModeStorageInitFailure's
// comment for the same pitfall).
func setupEmbeddedUsageMode(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	yaml := "storage:\n  type: local\n  database:\n    path: " + dir + "/secrets.db\n"
	require.NoError(t, os.WriteFile(dir+"/keyorix.yaml", []byte(yaml), 0600))
}

// TestRunShow_LocalModeSuccess_NoProjectFilter drives runShow's embedded-mode
// success path (InitializeStorage -> core.NewKeyorixCore -> GetUsageReport ->
// printReport) with flagProjectID left at zero, covering the "all projects"
// branch (the projectID pointer stays nil) plus the final printReport call.
func TestRunShow_LocalModeSuccess_NoProjectFilter(t *testing.T) {
	resetFlags(t)
	setupEmbeddedUsageMode(t)

	flagDays = 30
	flagProjectID = 0
	flagFormat = "table"

	out, err := captureStdout(t, func() error { return runShow(nil, nil) })
	require.NoError(t, err)
	assert.Contains(t, out, "last 30 days")
	assert.Contains(t, out, "(no data)")
}

// TestRunShow_LocalModeSuccess_WithProjectFilter covers the flagProjectID != 0
// branch inside runShow (the `id := flagProjectID; projectID = &id` block),
// which TestRunShow_LocalModeSuccess_NoProjectFilter's zero-value flag can't
// reach. The filtered project need not exist in storage — GetProjectUsageStats
// simply returns no matching rows, which is enough to exercise the branch.
func TestRunShow_LocalModeSuccess_WithProjectFilter(t *testing.T) {
	resetFlags(t)
	setupEmbeddedUsageMode(t)

	flagDays = 7
	flagProjectID = 99
	flagFormat = "json"

	out, err := captureStdout(t, func() error { return runShow(nil, nil) })
	require.NoError(t, err)

	var decoded storage.UsageReport
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, 7, decoded.WindowDays)
}

// TestRunShow_LocalModeGetUsageReportError covers runShow's
// "failed to generate usage report" wrap -- the one embedded-mode branch not
// reachable via a plain InitializeStorage success/failure. GetUsageReport's
// only error source is the underlying GetProjectUsageStats query
// (internal/storage/store/local_usage.go), which is a raw GORM Scan into a
// `ProjectID uint` field. audit_events.project_id has no NOT NULL/CHECK
// constraint at the schema level (see models.AuditEvent), so a row inserted
// via a raw connection with project_id = -1 passes SQLite's dynamic typing
// on INSERT but fails database/sql's uint conversion on Scan
// ("converting driver.Value type int64 (\"-1\") to a uint: invalid syntax"),
// producing a genuine backend error without any storage/interface changes.
func TestRunShow_LocalModeGetUsageReportError(t *testing.T) {
	resetFlags(t)
	setupEmbeddedUsageMode(t)

	_, err := common.InitializeStorage()
	require.NoError(t, err)

	rawDB, err := gorm.Open(sqlite.Open("secrets.db"))
	require.NoError(t, err)
	res := rawDB.Exec("INSERT INTO audit_events (event_type, project_id, event_time, success) VALUES (?, ?, ?, ?)",
		"secret.read", -1, time.Now().UTC(), true)
	require.NoError(t, res.Error)

	flagDays = 30
	flagProjectID = 0
	flagFormat = "table"

	err = runShow(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate usage report")
}

// TestPrintReport_NoDataWriteError forces the "(no data)" Fprintln call to
// fail by closing os.Stdout before printReport runs. This is the one
// tabwriter-buffered write error branch that's actually reachable: per
// text/tabwriter's Write implementation, a line with no tab characters (a
// single cell) triggers an immediate internal flush to the underlying
// writer, unlike the header/row lines below which contain tabs and stay
// buffered until an explicit Flush() (see the header/row write-error
// branches' doc comment on why those can't be covered the same way).
func TestPrintReport_NoDataWriteError(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, w.Close())
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	report := &storage.UsageReport{WindowDays: 30, GeneratedAt: time.Now()}
	err = printReport(report)
	require.Error(t, err)
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

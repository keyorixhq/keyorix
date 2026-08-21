package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFlags restores the package-level flag vars to their zero values so
// tests that mutate them (mirroring what cobra flag parsing would do) don't
// leak state into other tests.
func resetFlags(t *testing.T) {
	t.Helper()
	origFrom, origTo, origProjectID, origFormat := flagFrom, flagTo, flagProjectID, flagFormat
	t.Cleanup(func() {
		flagFrom, flagTo, flagProjectID, flagFormat = origFrom, origTo, origProjectID, origFormat
	})
}

func TestNewBillingCmd(t *testing.T) {
	cmd := NewBillingCmd()
	assert.Equal(t, "billing", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	sub, _, err := cmd.Find([]string{"report"})
	require.NoError(t, err)
	assert.Equal(t, "report", sub.Name())
}

func TestNewReportCmd_Flags(t *testing.T) {
	cmd := newReportCmd()
	assert.Equal(t, "report", cmd.Use)
	assert.NotNil(t, cmd.RunE)

	fromFlag := cmd.Flags().Lookup("from")
	require.NotNil(t, fromFlag)
	toFlag := cmd.Flags().Lookup("to")
	require.NotNil(t, toFlag)
	projectFlag := cmd.Flags().Lookup("project-id")
	require.NotNil(t, projectFlag)
	assert.Equal(t, "", projectFlag.DefValue)
	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "table", formatFlag.DefValue)

	// "from" and "to" are required — Cobra records this via an annotation.
	assert.Contains(t, fromFlag.Annotations, cobraRequiredAnnotation)
	assert.Contains(t, toFlag.Annotations, cobraRequiredAnnotation)
}

// cobraRequiredAnnotation mirrors cobra's internal BashCompOneRequiredFlag
// annotation key used by MarkFlagRequired, so the test above doesn't need to
// import cobra just for this one constant string.
const cobraRequiredAnnotation = "cobra_annotation_bash_completion_one_required_flag"

func TestRunReport_InvalidFrom(t *testing.T) {
	resetFlags(t)
	flagFrom = "not-a-date"
	flagTo = "2026-02-01T00:00:00Z"

	err := runReport(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --from value")
}

func TestRunReport_InvalidTo(t *testing.T) {
	resetFlags(t)
	flagFrom = "2026-01-01T00:00:00Z"
	flagTo = "also-not-a-date"

	err := runReport(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --to value")
}

func TestParseProjectIDs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint
		wantErr bool
	}{
		{name: "empty returns nil", input: "", want: nil},
		{name: "single id", input: "42", want: []uint{42}},
		{name: "multiple ids", input: "1,2,3", want: []uint{1, 2, 3}},
		{name: "trims whitespace", input: " 1 , 2 ", want: []uint{1, 2}},
		{name: "skips empty segments", input: "1,,2", want: []uint{1, 2}},
		{name: "invalid id errors", input: "1,abc", wantErr: true},
		{name: "negative id errors", input: "-1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProjectIDs(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func sampleReport() *storage.BillingReport {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	gen := time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC)
	return &storage.BillingReport{
		From:        from,
		To:          to,
		GeneratedAt: gen,
		Projects: []storage.BillingProjectStat{
			{ProjectID: 2, ProjectName: "zeta", SecretCount: 1, SecretReads: 2, SecretWrites: 3, SecretRotations: 1, UniqueUsers: 1, MachineReads: 0},
			{ProjectID: 1, ProjectName: "alpha", SecretCount: 5, SecretReads: 10, SecretWrites: 2, SecretRotations: 0, UniqueUsers: 3, MachineReads: 4},
			{ProjectID: 3, ProjectName: "", SecretCount: 0, SecretReads: 0, SecretWrites: 0, SecretRotations: 0, UniqueUsers: 0, MachineReads: 0},
		},
		Totals: storage.BillingTotals{
			Projects: 3, SecretCount: 6, SecretReads: 12, SecretWrites: 5, SecretRotations: 1, UniqueUsers: 4, MachineReads: 4,
		},
	}
}

func TestPrintBillingReport_TableSortsAndFormats(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"

	out, err := captureStdout(t, func() error { return printBillingReport(sampleReport()) })
	require.NoError(t, err)

	// "alpha" (project 1) must be printed before "zeta" (project 2) — stable
	// sort by ProjectName.
	alphaIdx := indexOf(t, out, "alpha")
	zetaIdx := indexOf(t, out, "zeta")
	assert.Less(t, alphaIdx, zetaIdx, "expected alpha row before zeta row, got:\n%s", out)

	// Blank ProjectName falls back to "(project <id>)".
	assert.Contains(t, out, "(project 3)")

	// Header and totals line are present.
	assert.Contains(t, out, "PROJECT")
	assert.Contains(t, out, "SECRETS")
	assert.Contains(t, out, "Totals (3 project(s))")
	assert.Contains(t, out, "2026-01-01")
	assert.Contains(t, out, "2026-02-01")
}

func TestPrintBillingReport_TableSortsByProjectIDOnNameTie(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"

	report := &storage.BillingReport{
		From: time.Now(), To: time.Now(), GeneratedAt: time.Now(),
		Projects: []storage.BillingProjectStat{
			{ProjectID: 9, ProjectName: "same", SecretCount: 1},
			{ProjectID: 2, ProjectName: "same", SecretCount: 2},
		},
		Totals: storage.BillingTotals{Projects: 2},
	}
	out, err := captureStdout(t, func() error { return printBillingReport(report) })
	require.NoError(t, err)

	// Both rows share ProjectName "same"; the tie-break on ProjectID must put
	// project 2 (SECRETS=2) before project 9 (SECRETS=1). Match the whole
	// "same"-prefixed row (tabwriter pads with spaces, not literal tabs) to
	// pull out each row's SECRETS column in printed order.
	rowPattern := regexp.MustCompile(`(?m)^same\s+(\d+)`)
	matches := rowPattern.FindAllStringSubmatch(out, -1)
	require.Len(t, matches, 2, "expected exactly 2 'same' rows, got:\n%s", out)
	assert.Equal(t, "2", matches[0][1], "expected project 2's row (SECRETS=2) first, got:\n%s", out)
	assert.Equal(t, "1", matches[1][1], "expected project 9's row (SECRETS=1) second, got:\n%s", out)
}

// TestPrintBillingReport_Table_FlushWriteError forces the tabwriter's
// underlying os.Stdout write to fail (by closing the read end of a pipe
// before flushing) so printBillingReport's w.Flush() error branch — which
// none of the happy-path table tests exercise, since tabwriter defers all
// actual writes until Flush — propagates the write error instead of
// silently succeeding.
func TestPrintBillingReport_Table_FlushWriteError(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"

	orig := os.Stdout
	r, w, perr := os.Pipe()
	require.NoError(t, perr)
	require.NoError(t, r.Close()) // closed read end -> write to w fails with EPIPE
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	err := printBillingReport(sampleReport())
	_ = w.Close()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pipe")
}

func TestPrintBillingReport_TableNoData(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"

	report := &storage.BillingReport{
		From: time.Now(), To: time.Now(), GeneratedAt: time.Now(),
	}
	out, err := captureStdout(t, func() error { return printBillingReport(report) })
	require.NoError(t, err)
	assert.Contains(t, out, "(no data)")
	assert.Contains(t, out, "Totals (0 project(s))")
}

func TestPrintBillingReport_JSON(t *testing.T) {
	resetFlags(t)
	flagFormat = "json"

	report := sampleReport()
	out, err := captureStdout(t, func() error { return printBillingReport(report) })
	require.NoError(t, err)

	var decoded storage.BillingReport
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, report.Totals, decoded.Totals)
	require.Len(t, decoded.Projects, 3)
}

func indexOf(t *testing.T, haystack, needle string) int {
	t.Helper()
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	t.Fatalf("expected %q to contain %q", haystack, needle)
	return -1
}

func TestRunReportRemote_Success(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"
	flagProjectID = "1,2"

	var gotPath string
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		env := map[string]interface{}{"data": sampleReport()}
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "test-token")
	require.True(t, ok)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	out, err := captureStdout(t, func() error {
		return runReportRemote(context.Background(), rc, from, to)
	})
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/admin/billing/report", gotPath)
	assert.Contains(t, gotQuery, "from=2026-01-01T00%3A00%3A00Z")
	assert.Contains(t, gotQuery, "to=2026-02-01T00%3A00%3A00Z")
	assert.Contains(t, gotQuery, "project_id=1%2C2")
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "Totals (3 project(s))")
}

func TestRunReportRemote_NoProjectIDFilter(t *testing.T) {
	resetFlags(t)
	flagFormat = "json"
	flagProjectID = ""

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		env := map[string]interface{}{"data": sampleReport()}
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "test-token")
	require.True(t, ok)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	_, err := captureStdout(t, func() error {
		return runReportRemote(context.Background(), rc, from, to)
	})
	require.NoError(t, err)
	assert.NotContains(t, gotQuery, "project_id")
}

func TestRunReportRemote_ServerError(t *testing.T) {
	resetFlags(t)
	flagFormat = "table"
	flagProjectID = ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc, ok := common.NewRemoteClientWithCredentials(srv.URL, "test-token")
	require.True(t, ok)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	_, err := captureStdout(t, func() error {
		return runReportRemote(context.Background(), rc, from, to)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch billing report")
}

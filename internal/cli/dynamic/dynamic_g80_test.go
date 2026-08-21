package dynamic

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// G80: exact-output-format regression coverage
//
// The existing suite mostly asserts individual substrings (assert.Contains),
// which verifies a value made it into the output but not that it landed in
// the right column/position, kept its exact punctuation, or that adjacent
// fields didn't collide. These tests assert full-string equality against the
// production format strings applied to known inputs, so a field swap (e.g.
// ProjectID/EnvironmentID), a dropped separator, or a padding-width change
// would fail loudly instead of silently passing a Contains check.
// ---------------------------------------------------------------------------

// TestPrintConfig_G80_ExactOutput verifies every line and field position of
// printConfig's output, not just that individual values appear somewhere in
// it. This would catch e.g. ProjectID and EnvironmentID being swapped.
func TestPrintConfig_G80_ExactOutput(t *testing.T) {
	cfg := configView{
		ID:                7,
		Name:              "demo-db",
		ProjectID:         3,
		EnvironmentID:     2,
		BackendType:       "postgres",
		DefaultTTLSeconds: 60,
		MaxTTLSeconds:     120,
		Classification:    "restricted",
	}
	out := captureStdout(t, func() {
		printConfig(cfg)
	})

	want := fmt.Sprintf("ID:             %d\n", cfg.ID) +
		fmt.Sprintf("Name:           %s\n", cfg.Name) +
		fmt.Sprintf("Project ID:     %d\n", cfg.ProjectID) +
		fmt.Sprintf("Environment ID: %d\n", cfg.EnvironmentID) +
		fmt.Sprintf("Backend:        %s\n", cfg.BackendType) +
		fmt.Sprintf("Default TTL:    %ds\n", cfg.DefaultTTLSeconds) +
		fmt.Sprintf("Max TTL:        %ds\n", cfg.MaxTTLSeconds) +
		fmt.Sprintf("Classification: %s\n", cfg.Classification)

	assert.Equal(t, want, out)
}

// TestList_G80_ExactOutputFormat verifies the header line and a data row are
// rendered with the exact column widths and separators the format strings
// specify, using fresh field values distinct from other tests so a
// misattributed column can't accidentally still read as correct.
func TestList_G80_ExactOutputFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":42,"name":"app-db","backend_type":"postgres","default_ttl_seconds":3600,"max_ttl_seconds":7200}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagProjectID, flagEnvID = 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})

	want := fmt.Sprintf("%-5s %-24s %-10s %-8s %-8s\n", "ID", "NAME", "BACKEND", "TTL", "MAXTTL") +
		fmt.Sprintf("%-5d %-24s %-10s %-8d %-8d\n", 42, "app-db", "postgres", 3600, 7200)

	assert.Equal(t, want, out)
}

// TestList_G80_LongNameNotTruncated verifies that a config name longer than
// the %-24s padding width is printed in full, not cut off. Left-padding
// verbs in Go never truncate a wider value, but that's a non-obvious
// behavior worth pinning: a naive re-implementation using a fixed-width
// buffer could silently start truncating names.
func TestList_G80_LongNameNotTruncated(t *testing.T) {
	longName := "this-config-name-is-longer-than-24-characters-wide"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":[{"id":1,"name":%q,"backend_type":"mysql","default_ttl_seconds":30,"max_ttl_seconds":60}]}`, longName)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagProjectID, flagEnvID = 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})
	assert.Contains(t, out, longName, "a name wider than the padding column must not be truncated")
}

// TestLeases_G80_ExactOutputFormat mirrors TestList_G80_ExactOutputFormat for
// the leases table.
func TestLeases_G80_ExactOutputFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"lease_id":"lease-1","role_name":"readwrite","status":"active","issued_at":"2026-07-01T10:00:00Z","expires_at":"2026-07-01T11:00:00Z"}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		require.NoError(t, leasesCmd.RunE(leasesCmd, []string{"5"}))
	})

	want := fmt.Sprintf("%-34s %-16s %-14s %s\n", "LEASE", "ROLE", "STATUS", "EXPIRES") +
		fmt.Sprintf("%-34s %-16s %-14s %s\n", "lease-1", "readwrite", "active", "2026-07-01T11:00:00Z")

	assert.Equal(t, want, out)
}

// TestGetConfig_G80_NegativeConfigID documents that strconv.Atoi accepts a
// leading "-" and get-config forwards it verbatim into the request path
// (there is no positive-ID validation). If someone later adds bounds
// checking, this pins the current, intentional behavior so the change is
// visible in a test diff rather than discovered in production.
func TestGetConfig_G80_NegativeConfigID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"x","backend_type":"postgres"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, getConfigCmd.RunE(getConfigCmd, []string{"-5"}))
	assert.Equal(t, "/api/v1/dynamic-secrets/configs/-5", gotPath)
}

// TestClassify_G80_ExactSuccessMessage verifies the full success line,
// including the %q-quoted level and the checkmark prefix, rather than just
// checking that the level and ID appear somewhere in the output.
func TestClassify_G80_ExactSuccessMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":9,"name":"db","classification":"top-secret"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagLevel = "top-secret"
	t.Cleanup(func() { flagLevel = "" })

	out := captureStdout(t, func() {
		require.NoError(t, classifyCmd.RunE(classifyCmd, []string{"9"}))
	})
	want := fmt.Sprintf("✅ Classification set to %q for config %d.\n", "top-secret", 9)
	assert.Equal(t, want, out)
}

// TestRevoke_G80_ExactOutputFormat verifies the full "Lease <id> <status>."
// success line, including the trailing period, rather than a substring
// match that would also pass if the punctuation were dropped or duplicated.
func TestRevoke_G80_ExactOutputFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-42","status":"revoked"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		require.NoError(t, revokeCmd.RunE(revokeCmd, []string{"lease-42"}))
	})
	assert.Equal(t, "Lease lease-42 revoked.\n", out)
}

// TestSortedKeys_G80_UnicodeAndNumericKeys verifies sortedKeys uses plain
// byte-wise string ordering (not locale-aware collation), which matters
// because issueCmd relies on this order to print cloud-IAM fields
// deterministically regardless of the host's locale.
func TestSortedKeys_G80_UnicodeAndNumericKeys(t *testing.T) {
	m := map[string]string{
		"Zebra": "1",
		"apple": "2",
		"10":    "3",
		"2":     "4",
	}
	got := sortedKeys(m)
	// Byte-wise ordering: digits < uppercase < lowercase, and "10" < "2"
	// lexicographically even though 10 > 2 numerically.
	want := []string{"10", "2", "Zebra", "apple"}
	require.Equal(t, want, got)
	assert.True(t, sort.StringsAreSorted(got))
}

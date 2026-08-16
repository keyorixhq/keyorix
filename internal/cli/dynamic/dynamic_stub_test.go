package dynamic

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListAgainstMockServer verifies that `list` hits the correct path and prints
// the returned configs.
func TestListAgainstMockServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"app-db","backend_type":"postgres","default_ttl_seconds":3600,"max_ttl_seconds":7200}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagProjectID, flagEnvID = 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})
	assert.Equal(t, "/api/v1/dynamic-secrets/configs", gotPath)
	assert.Contains(t, out, "app-db")
	assert.Contains(t, out, "postgres")
}

// TestListWithProjectFilter verifies project_id is appended when flagProjectID > 0.
func TestListWithProjectFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagProjectID, flagEnvID = 7, 0

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})
	assert.Contains(t, gotQuery, "project_id=7")
	assert.Contains(t, out, "No dynamic-secret configs found.")
}

// TestListWithEnvFilter verifies environment_id is appended when flagEnvID > 0.
func TestListWithEnvFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagProjectID, flagEnvID = 0, 3

	require.NoError(t, listCmd.RunE(listCmd, nil))
	assert.Contains(t, gotQuery, "environment_id=3")
}

// TestListWithBothFilters verifies both filters are appended.
func TestListWithBothFilters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagProjectID, flagEnvID = 2, 5

	require.NoError(t, listCmd.RunE(listCmd, nil))
	assert.Contains(t, gotQuery, "project_id=2")
	assert.Contains(t, gotQuery, "environment_id=5")
}

// TestLeasesAgainstMockServer verifies that `leases` hits the correct path.
func TestLeasesAgainstMockServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":[{"lease_id":"lease-1","role_name":"readwrite","status":"active","issued_at":"2026-07-01T10:00:00Z","expires_at":"2026-07-01T11:00:00Z"}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, leasesCmd.RunE(leasesCmd, []string{"7"}))
	})
	assert.Equal(t, "/api/v1/dynamic-secrets/configs/7/leases", gotPath)
	assert.Contains(t, out, "lease-1")
}

// TestLeasesEmpty verifies the "No leases" branch.
func TestLeasesEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, leasesCmd.RunE(leasesCmd, []string{"7"}))
	})
	assert.Contains(t, out, "No leases")
}

// TestLeasesInvalidID verifies bad config ID is rejected before any network call.
func TestLeasesInvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "t")

	err := leasesCmd.RunE(leasesCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config id")
}

// TestRenewAgainstMockServer verifies that `renew` hits the correct path.
func TestRenewAgainstMockServer(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-abc","expires_at":"2026-07-01T12:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagTTL = 3600

	out := captureStdout(t, func() {
		require.NoError(t, renewCmd.RunE(renewCmd, []string{"lease-abc"}))
	})
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/leases/lease-abc/renew", gotPath)
	assert.Contains(t, out, "lease-abc renewed")
}

// TestRevokeAgainstMockServer verifies that `revoke` hits the correct path.
func TestRevokeAgainstMockServer(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-abc","status":"revoked"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, revokeCmd.RunE(revokeCmd, []string{"lease-abc"}))
	})
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/leases/lease-abc/revoke", gotPath)
	assert.Contains(t, out, "revoked")
}

// TestRevokeAllDeclinePrompt verifies that declining the prompt does not hit the server.
func TestRevokeAllDeclinePrompt(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagYes = false
	t.Cleanup(func() { flagYes = false })

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("no\n"))
	require.NoError(t, revokeAllCmd.RunE(cmd, []string{"7"}))
	assert.Equal(t, 0, calls, "declining the prompt must not call the server")
}

// TestRevokeAllBadConfigID verifies bad config ID is rejected before any prompt.
func TestRevokeAllBadConfigID(t *testing.T) {
	flagYes = true
	t.Cleanup(func() { flagYes = false })
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "t")

	err := revokeAllCmd.RunE(revokeAllCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config id")
}

// TestIssueWithCloudFields verifies that cloud IAM fields are printed.
func TestIssueWithCloudFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-sts","fields":{"AccessKeyId":"AKIA123","SecretAccessKey":"sec","SessionToken":"tok"},"expires_at":"2026-07-01T11:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagTTL = 0

	out := captureStdout(t, func() {
		require.NoError(t, issueCmd.RunE(issueCmd, []string{"3"}))
	})
	// Fields are printed in sorted key order.
	assert.Contains(t, out, "AccessKeyId")
	assert.Contains(t, out, "SecretAccessKey")
	assert.Contains(t, out, "SessionToken")
}

// TestGetConfigInvalidID verifies bad config ID is rejected.
func TestGetConfigInvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "t")

	err := getConfigCmd.RunE(getConfigCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config id")
}

// TestClassifyInvalidID verifies bad config ID is rejected.
func TestClassifyInvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "t")
	flagLevel = "restricted"

	err := classifyCmd.RunE(classifyCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config id")
}

// ── G70: lease-id must be path-escaped before interpolation ─────────────────
//
// Regression coverage for G70 member 2 (internal/cli/dynamic/dynamic.go:260):
// renew/revoke used to interpolate the caller-supplied lease-id straight into
// the request path, so a lease-id containing "/" could add extra path
// segments and target a different resource than intended. We assert on
// r.RequestURI (the exact bytes sent on the wire) because r.URL.Path decodes
// "%2F" back to "/", which would hide the bug.

// TestRenewAgainstMockServer_LeaseIDWithSlash proves that a lease-id
// containing "/" is sent as a single, correctly-escaped path segment and
// cannot redirect the request to a different resource.
func TestRenewAgainstMockServer_LeaseIDWithSlash(t *testing.T) {
	maliciousLeaseID := "abc/../../other-config/leases/xyz"

	var gotRequestURI, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"data":{"lease_id":"abc","expires_at":"2026-07-01T12:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagTTL = 3600

	require.NoError(t, renewCmd.RunE(renewCmd, []string{maliciousLeaseID}))

	assert.Equal(t, http.MethodPost, gotMethod)
	wantEscaped := "/api/v1/dynamic-secrets/leases/" + url.PathEscape(maliciousLeaseID) + "/renew"
	assert.Equal(t, wantEscaped, gotRequestURI,
		"the raw request-target must contain the escaped lease-id as one segment, not literal '/'s")
	// The literal "/" from the lease-id must never appear unescaped in the
	// request line — it must show up as "%2F" so the server sees one segment.
	assert.NotContains(t, gotRequestURI, "leases/abc/../..",
		"unescaped slashes would let the lease-id smuggle extra path segments")
}

// TestRevokeAgainstMockServer_LeaseIDWithSlash mirrors the renew case for revoke.
func TestRevokeAgainstMockServer_LeaseIDWithSlash(t *testing.T) {
	maliciousLeaseID := "abc/../../revoke-all"

	var gotRequestURI, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{"data":{"lease_id":"abc","status":"revoked"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	require.NoError(t, revokeCmd.RunE(revokeCmd, []string{maliciousLeaseID}))

	assert.Equal(t, http.MethodPost, gotMethod)
	wantEscaped := "/api/v1/dynamic-secrets/leases/" + url.PathEscape(maliciousLeaseID) + "/revoke"
	assert.Equal(t, wantEscaped, gotRequestURI,
		"the raw request-target must contain the escaped lease-id as one segment, not literal '/'s")
	assert.NotContains(t, gotRequestURI, "leases/abc/../..",
		"unescaped slashes would let the lease-id smuggle extra path segments")
}

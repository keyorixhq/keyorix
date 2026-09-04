// quota_rune_test.go — exercises quotaReportCmd.RunE directly.
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quotaRuneStub(t *testing.T, body string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/quota-report" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestQuotaReportCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := quotaReportCmd.RunE(quotaReportCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestQuotaReportCmd_Success_Empty(t *testing.T) {
	done := quotaRuneStub(t, `{"data":{"secrets":[]}}`)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := quotaReportCmd.RunE(quotaReportCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No secrets with a read quota")
}

func TestQuotaReportCmd_Success_WithRows(t *testing.T) {
	done := quotaRuneStub(t, `{"data":{"secrets":[{"secret_id":1,"secret_name":"db-pw","read_count":90,"max_reads":100,"usage_pct":90,"status":"warning"}]}}`)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := quotaReportCmd.RunE(quotaReportCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "db-pw")
	assert.Contains(t, out, "warning")
}

func TestQuotaReportCmd_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := quotaReportCmd.RunE(quotaReportCmd, nil)
	require.Error(t, err)
}

package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quotaStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/quota-report" {
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"secret_id":1,"secret_name":"api-key","read_count":8,"max_reads":10,"usage_pct":80,"status":"warning"},{"secret_id":2,"secret_name":"burn-token","read_count":5,"max_reads":5,"usage_pct":100,"status":"exhausted"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestFetchQuotaReport(t *testing.T) {
	rc, done := quotaStub(t)
	defer done()
	rows, err := fetchQuotaReport(context.Background(), rc)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, uint(1), rows[0].SecretID)
	assert.Equal(t, "api-key", rows[0].SecretName)
	assert.Equal(t, 80, rows[0].UsagePct)
	assert.Equal(t, "warning", rows[0].Status)
	assert.Equal(t, "exhausted", rows[1].Status)
}

func TestFetchQuotaReport_Error(t *testing.T) {
	rc, done := quotaStub(t)
	defer done()
	// Unmount and kill the server to get a connection error.
	done()
	_, err := fetchQuotaReport(context.Background(), rc)
	require.Error(t, err)
}

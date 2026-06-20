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

func nameConformanceStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/4/secrets/name-conformance" {
			_, _ = w.Write([]byte(`{"data":{"policy_enabled":true,"pattern":"^[A-Z][A-Z0-9_]*$","max_length":0,"total_secrets":3,"violations":[{"id":8,"name":"db-pass","type":"password","environment_id":2,"reason":"secret name does not match the required pattern \"^[A-Z][A-Z0-9_]*$\""}]}}`))
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

func TestFetchNameConformance(t *testing.T) {
	rc, done := nameConformanceStub(t)
	defer done()
	rep, err := fetchNameConformance(context.Background(), rc, 4)
	require.NoError(t, err)
	assert.True(t, rep.PolicyEnabled)
	assert.Equal(t, 3, rep.TotalSecrets)
	require.Len(t, rep.Violations, 1)
	assert.Equal(t, "db-pass", rep.Violations[0].Name)
	assert.Contains(t, rep.Violations[0].Reason, "pattern")
}

func TestFetchNameConformance_NotFound(t *testing.T) {
	rc, done := nameConformanceStub(t)
	defer done()
	_, err := fetchNameConformance(context.Background(), rc, 999)
	require.Error(t, err)
}

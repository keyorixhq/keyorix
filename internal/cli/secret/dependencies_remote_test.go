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

func depsStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/7/dependencies":
			_, _ = w.Write([]byte(`{"data":{"secret_id":7,"depends_on":[{"id":10,"secret_id":2,"secret_name":"db-password","note":"derives from"}],"dependents":[{"id":11,"secret_id":3,"secret_name":"edge-cert"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/7/impact":
			_, _ = w.Write([]byte(`{"data":{"secret_id":7,"secret_name":"app-token","affected":[{"secret_id":3,"secret_name":"edge-cert","depth":1},{"secret_id":4,"secret_name":"gateway","depth":2}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/7/dependencies":
			_, _ = w.Write([]byte(`{"data":{"id":12,"secret_id":2,"secret_name":"db-password"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/7/dependencies/12":
			_, _ = w.Write([]byte(`{"data":{"removed":true}}`))
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

func TestFetchDependencies(t *testing.T) {
	rc, done := depsStub(t)
	defer done()
	v, err := fetchDependencies(context.Background(), rc, 7)
	require.NoError(t, err)
	require.Len(t, v.DependsOn, 1)
	assert.Equal(t, uint(10), v.DependsOn[0].ID)
	assert.Equal(t, "db-password", v.DependsOn[0].SecretName)
	assert.Equal(t, "derives from", v.DependsOn[0].Note)
	require.Len(t, v.Dependents, 1)
	assert.Equal(t, "edge-cert", v.Dependents[0].SecretName)
}

func TestFetchImpact(t *testing.T) {
	rc, done := depsStub(t)
	defer done()
	v, err := fetchImpact(context.Background(), rc, 7)
	require.NoError(t, err)
	assert.Equal(t, "app-token", v.SecretName)
	require.Len(t, v.Affected, 2)
	assert.Equal(t, "edge-cert", v.Affected[0].SecretName)
	assert.Equal(t, 1, v.Affected[0].Depth)
	assert.Equal(t, 2, v.Affected[1].Depth)
}

func TestDepsAddAndRemove(t *testing.T) {
	rc, done := depsStub(t)
	defer done()
	var out depEdgeView
	require.NoError(t, rc.Post(context.Background(), "/api/v1/secrets/7/dependencies", map[string]interface{}{"depends_on_id": 2}, &out))
	assert.Equal(t, uint(12), out.ID)
	require.NoError(t, rc.Delete(context.Background(), "/api/v1/secrets/7/dependencies/12"))
}

func TestParseSecretArg(t *testing.T) {
	id, err := parseSecretArg(" 42 ")
	require.NoError(t, err)
	assert.Equal(t, uint(42), id)
	_, err = parseSecretArg("0")
	assert.Error(t, err)
	_, err = parseSecretArg("abc")
	assert.Error(t, err)
}

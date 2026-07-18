// rotation_s27_test.go — sprint-27 coverage: error paths for fetchRotationOrder,
// fetchRotationPlan, and fetchDeploymentRotationPlan (the uncovered 25% branch
// in each function when c.Get returns an error).
package rotation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchRotationOrder_S27_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	v, err := fetchRotationOrder(context.Background(), rc, 42)
	assert.Error(t, err)
	assert.Nil(t, v)
}

func TestFetchRotationPlan_S27_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	plan, err := fetchRotationPlan(context.Background(), rc, 7)
	assert.Error(t, err)
	assert.Nil(t, plan)
}

func TestFetchDeploymentRotationPlan_S27_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	plan, err := fetchDeploymentRotationPlan(context.Background(), rc)
	assert.Error(t, err)
	assert.Nil(t, plan)
}

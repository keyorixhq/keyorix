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

func TestFetchRotationOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/1/rotation-order" {
			_, _ = w.Write([]byte(`{"data":{"project_id":1,"order":[{"secret_id":4,"secret_name":"root-ca"},{"secret_id":2,"secret_name":"intermediate"},{"secret_id":1,"secret_name":"service-cert"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	v, err := fetchRotationOrder(context.Background(), rc, 1)
	require.NoError(t, err)
	require.Len(t, v.Order, 3)
	assert.Equal(t, "root-ca", v.Order[0].SecretName)
	assert.Equal(t, "service-cert", v.Order[2].SecretName)
}

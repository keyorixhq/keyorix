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

// keyorixRenderStub serves the list + value endpoints the resolver uses.
func keyorixRenderStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/secrets" && r.URL.Query().Get("environment") == "prod":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":7,"Name":"db-password"},{"ID":9,"Name":"api-key"}]}}`))
		case r.URL.Path == "/api/v1/secrets/7":
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"}}`))
		case r.URL.Path == "/api/v1/secrets/9":
			_, _ = w.Write([]byte(`{"data":{"value":"k3y"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newRenderClient(t *testing.T, srv *httptest.Server) *common.RemoteClient {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc
}

func TestRenderWith(t *testing.T) {
	srv := keyorixRenderStub(t)
	defer srv.Close()
	rc := newRenderClient(t, srv)

	out, err := renderWith(context.Background(), rc,
		"DB_PASSWORD=${secret:prod/db-password}\nAPI_KEY=${secret:prod/api-key}\n")
	require.NoError(t, err)
	assert.Equal(t, "DB_PASSWORD=s3cr3t\nAPI_KEY=k3y\n", out)
}

func TestRenderWith_LiteralAndEscape(t *testing.T) {
	srv := keyorixRenderStub(t)
	defer srv.Close()
	rc := newRenderClient(t, srv)

	out, err := renderWith(context.Background(), rc, "lit=$${secret:prod/db-password} val=${secret:prod/db-password}")
	require.NoError(t, err)
	assert.Equal(t, "lit=${secret:prod/db-password} val=s3cr3t", out)
}

func TestRenderWith_MissingRefFails(t *testing.T) {
	srv := keyorixRenderStub(t)
	defer srv.Close()
	rc := newRenderClient(t, srv)

	_, err := renderWith(context.Background(), rc, "x=${secret:prod/nope}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRenderWith_BadRef(t *testing.T) {
	srv := keyorixRenderStub(t)
	defer srv.Close()
	rc := newRenderClient(t, srv)

	_, err := renderWith(context.Background(), rc, "${secret:noslash}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reference")
}

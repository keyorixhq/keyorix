package secret

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func descStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/42":
			// Raw model: PascalCase Description.
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db","Description":"prod DB; dba@"}}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/secrets/42/description":
			b, _ := io.ReadAll(r.Body)
			var got map[string]string
			_ = json.Unmarshal(b, &got)
			// Echo back the updated secret (non-nil data, like the real handler).
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db","Description":"` + got["description"] + `"},"message":"Description updated"}`))
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

func TestGetSecretDescription(t *testing.T) {
	rc, done := descStub(t)
	defer done()
	d, err := getSecretDescription(context.Background(), rc, 42)
	require.NoError(t, err)
	assert.Equal(t, "prod DB; dba@", d)
}

func TestSetSecretDescription(t *testing.T) {
	rc, done := descStub(t)
	defer done()
	require.NoError(t, setSecretDescription(context.Background(), rc, 42, "new note"))
}

func TestGetSecretDescription_NotFound(t *testing.T) {
	rc, done := descStub(t)
	defer done()
	_, err := getSecretDescription(context.Background(), rc, 999)
	require.Error(t, err)
}

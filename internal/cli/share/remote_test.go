package share

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/require"
)

func TestShareReadRemote(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets/7/shares", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		_, _ = w.Write([]byte(`{"data":{"shares":[
			{"ID":1,"SecretID":7,"OwnerID":1,"RecipientID":5,"IsGroup":false,"Permission":"read","CreatedAt":"2026-06-08T10:00:00Z"}
		]}}`))
	})
	mux.HandleFunc("/api/v1/shared-secrets", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GET", r.Method)
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":7,"Name":"db-pass","Type":"password","ProjectID":1,"EnvironmentID":1,"CreatedBy":"admin","CreatedAt":"2026-06-08T10:00:00Z"}
		]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc, 7))
	require.NoError(t, runSharedSecretsRemote(rc))
}

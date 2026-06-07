package user

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCreateRemote should POST the password-mode payload to /api/v1/users and
// print the created user, rather than touching a local SQLite file.
func TestRunCreateRemote(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/api/v1/users", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":7,"username":"bob","email":"bob@test.com"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	createUsername, createEmail, createPassword, createDisplayName = "bob", "bob@test.com", "s3cret-pass", ""
	require.NoError(t, runCreateRemote(rc))

	assert.Equal(t, "bob", gotBody["username"])
	assert.Equal(t, "bob@test.com", gotBody["email"])
	assert.Equal(t, "s3cret-pass", gotBody["password"])
	assert.Equal(t, "bob", gotBody["display_name"], "display_name defaults to username when empty")
}

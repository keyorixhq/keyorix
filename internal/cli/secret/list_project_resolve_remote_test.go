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

// TestRunListRemote_ResolvesProjectScope is the regression for the double-{"data":…}
// envelope bug in `secret list --project <name>` (remote mode): rc.Get already strips
// the envelope, so the project lookup must decode {"projects":[…]} directly. With the
// old nested Data wrapper the list decoded empty, resolution failed, and the command
// errored "project not found" before ever reaching the secrets endpoint. Here the name
// must resolve to id=1 and scope the secrets query with project_id=1.
func TestRunListRemote_ResolvesProjectScope(t *testing.T) {
	var secretsQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/secrets":
			secretsQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0}}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")

	listProjectName, listLimit, listOffset, listEnv, listFormat = "web", 50, 0, 0, "table"
	t.Cleanup(func() { listProjectName, listLimit, listOffset, listEnv, listFormat = "", 0, 0, 0, "" })

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	assert.Contains(t, secretsQuery, "project_id=1",
		"the --project name must resolve to its ID and scope the secrets query")
}

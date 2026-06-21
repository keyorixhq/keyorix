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

func bulkRenameStub(t *testing.T, capture *map[string]interface{}) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/5/secrets/bulk-rename" {
			b, _ := io.ReadAll(r.Body)
			if capture != nil {
				_ = json.Unmarshal(b, capture)
			}
			_, _ = w.Write([]byte(`{"data":{"dry_run":true,"renamed":1,"skipped":0,"outcomes":[{"id":12,"old_name":"db-pw","new_name":"DB_PW","status":"would_rename"}]}}`))
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

func TestPostBulkRename(t *testing.T) {
	var got map[string]interface{}
	rc, done := bulkRenameStub(t, &got)
	defer done()

	rep, err := postBulkRename(context.Background(), rc, 5, []bulkRenameEntry{{ID: 12, NewName: "DB_PW"}}, true)
	require.NoError(t, err)
	assert.True(t, rep.DryRun)
	assert.Equal(t, 1, rep.Renamed)
	require.Len(t, rep.Outcomes, 1)
	assert.Equal(t, "would_rename", rep.Outcomes[0].Status)

	// The dry_run flag and renames were sent in the body.
	assert.Equal(t, true, got["dry_run"])
	renames, ok := got["renames"].([]interface{})
	require.True(t, ok)
	assert.Len(t, renames, 1)
}

func TestPostBulkRename_NotFound(t *testing.T) {
	rc, done := bulkRenameStub(t, nil)
	defer done()
	_, err := postBulkRename(context.Background(), rc, 999, []bulkRenameEntry{{ID: 1, NewName: "X"}}, false)
	require.Error(t, err)
}

func TestParseRenamePairs(t *testing.T) {
	t.Run("parses id=name pairs and splits on the first =", func(t *testing.T) {
		got, err := parseRenamePairs([]string{"12=DB_PASSWORD", "15=NAME=WITH=EQUALS"})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, uint(12), got[0].ID)
		assert.Equal(t, "DB_PASSWORD", got[0].NewName)
		assert.Equal(t, "NAME=WITH=EQUALS", got[1].NewName)
	})

	t.Run("rejects malformed pairs", func(t *testing.T) {
		for _, bad := range []string{"noequals", "abc=NAME", "0=NAME", "12="} {
			_, err := parseRenamePairs([]string{bad})
			require.Error(t, err, "expected %q to be rejected", bad)
		}
	})
}

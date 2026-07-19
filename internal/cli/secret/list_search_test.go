// list_search_test.go — CLI tests for --search flag on secret list.
//
// Covers:
//   - runListRemote sends ?search=<encoded> when --search is given
//   - runListRemote does NOT send search param when --search is empty
package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunListRemote_SearchFlag_AddedToQuery verifies that --search foo appends
// &search=foo to the secrets request URL.
func TestRunListRemote_SearchFlag_AddedToQuery(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":50,"total_pages":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")

	origSearch := listSearch
	origLimit := listLimit
	origOffset := listOffset
	origEnv := listEnv
	origFormat := listFormat
	origProject := listProjectName
	origFolder := listFolderID
	t.Cleanup(func() {
		listSearch = origSearch
		listLimit = origLimit
		listOffset = origOffset
		listEnv = origEnv
		listFormat = origFormat
		listProjectName = origProject
		listFolderID = origFolder
	})

	listSearch = "foo"
	listLimit = 50
	listOffset = 0
	listEnv = 0
	listFormat = "table"
	listProjectName = ""
	listFolderID = 0

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	assert.True(t, strings.Contains(gotQuery, "search=foo"),
		"expected search=foo in query, got: %s", gotQuery)
}

// TestRunListRemote_SearchFlag_OmittedWhenEmpty verifies that an empty --search
// does not add a search parameter to the request.
func TestRunListRemote_SearchFlag_OmittedWhenEmpty(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":50,"total_pages":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")

	origSearch := listSearch
	origLimit := listLimit
	origOffset := listOffset
	origEnv := listEnv
	origFormat := listFormat
	origProject := listProjectName
	origFolder := listFolderID
	t.Cleanup(func() {
		listSearch = origSearch
		listLimit = origLimit
		listOffset = origOffset
		listEnv = origEnv
		listFormat = origFormat
		listProjectName = origProject
		listFolderID = origFolder
	})

	listSearch = ""
	listLimit = 50
	listOffset = 0
	listEnv = 0
	listFormat = "table"
	listProjectName = ""
	listFolderID = 0

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	assert.False(t, strings.Contains(gotQuery, "search"),
		"search param must not appear when --search is empty, got: %s", gotQuery)
}

// TestRunListRemote_SearchFlag_URLEncoded verifies that special characters in
// the search term are properly URL-encoded.
func TestRunListRemote_SearchFlag_URLEncoded(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":50,"total_pages":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")

	origSearch := listSearch
	origLimit := listLimit
	origOffset := listOffset
	origEnv := listEnv
	origFormat := listFormat
	origProject := listProjectName
	origFolder := listFolderID
	t.Cleanup(func() {
		listSearch = origSearch
		listLimit = origLimit
		listOffset = origOffset
		listEnv = origEnv
		listFormat = origFormat
		listProjectName = origProject
		listFolderID = origFolder
	})

	listSearch = "my secret"
	listLimit = 50
	listOffset = 0
	listEnv = 0
	listFormat = "table"
	listProjectName = ""
	listFolderID = 0

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(context.Background(), rc))
	// "my secret" must be URL-encoded as "my+secret" or "my%20secret"
	hasEncoded := strings.Contains(gotQuery, "search=my+secret") ||
		strings.Contains(gotQuery, "search=my%20secret")
	assert.True(t, hasEncoded,
		"space in search term must be URL-encoded, got: %s", gotQuery)
}

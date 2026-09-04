// tags_rune_test.go — exercises tagsCmd.RunE directly
// (tags_remote_test.go only tests getSecretTags/setSecretTags/splitTags).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tagsRuneStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func resetTagsFlags(t *testing.T) {
	t.Helper()
	origID, origSet := tagsID, tagsSet
	t.Cleanup(func() {
		tagsID = origID
		tagsSet = origSet
		tagsCmd.Flags().Lookup("set").Changed = false
	})
}

func TestTagsCmd_MissingID(t *testing.T) {
	resetTagsFlags(t)
	tagsID = 0
	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestTagsCmd_NoServer(t *testing.T) {
	resetTagsFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	tagsID = 7
	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestTagsCmd_List_Empty(t *testing.T) {
	resetTagsFlags(t)
	done := tagsRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"tags":[]}}`))
	})
	defer done()
	tagsID = 7

	out := captureStdoutForFolder(t, func() {
		err := tagsCmd.RunE(tagsCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "(no tags)")
}

func TestTagsCmd_List_WithTags(t *testing.T) {
	resetTagsFlags(t)
	done := tagsRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"tags":["prod","tier1"]}}`))
	})
	defer done()
	tagsID = 7

	out := captureStdoutForFolder(t, func() {
		err := tagsCmd.RunE(tagsCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "prod, tier1")
}

func TestTagsCmd_List_FetchError(t *testing.T) {
	resetTagsFlags(t)
	done := tagsRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	tagsID = 7

	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
}

func TestTagsCmd_Set_Success(t *testing.T) {
	resetTagsFlags(t)
	done := tagsRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"tags":["new"]}}`))
	})
	defer done()
	tagsID = 7
	tagsSet = "new"
	require.NoError(t, tagsCmd.Flags().Set("set", "new"))

	out := captureStdoutForFolder(t, func() {
		err := tagsCmd.RunE(tagsCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "new")
}

func TestTagsCmd_Set_Error(t *testing.T) {
	resetTagsFlags(t)
	done := tagsRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	tagsID = 7
	require.NoError(t, tagsCmd.Flags().Set("set", "new"))

	err := tagsCmd.RunE(tagsCmd, nil)
	require.Error(t, err)
}

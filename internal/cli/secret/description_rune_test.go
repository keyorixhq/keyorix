// description_rune_test.go — exercises descriptionCmd.RunE directly
// (description_remote_test.go only tests getSecretDescription/setSecretDescription).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func descriptionRuneStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func resetDescriptionFlags(t *testing.T) {
	t.Helper()
	origID, origSet := descID, descSet
	t.Cleanup(func() {
		descID = origID
		descSet = origSet
		descriptionCmd.Flags().Lookup("set").Changed = false
	})
}

func TestDescriptionCmd_MissingID(t *testing.T) {
	resetDescriptionFlags(t)
	descID = 0
	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestDescriptionCmd_NoServer(t *testing.T) {
	resetDescriptionFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	descID = 7
	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDescriptionCmd_Show_Empty(t *testing.T) {
	resetDescriptionFlags(t)
	done := descriptionRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"Description":""}}`))
	})
	defer done()
	descID = 7

	out := captureStdoutForFolder(t, func() {
		err := descriptionCmd.RunE(descriptionCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "(no description)")
}

func TestDescriptionCmd_Show_WithValue(t *testing.T) {
	resetDescriptionFlags(t)
	done := descriptionRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"Description":"prod DB"}}`))
	})
	defer done()
	descID = 7

	out := captureStdoutForFolder(t, func() {
		err := descriptionCmd.RunE(descriptionCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "prod DB")
}

func TestDescriptionCmd_Show_FetchError(t *testing.T) {
	resetDescriptionFlags(t)
	done := descriptionRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	descID = 7

	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
}

func TestDescriptionCmd_Set_Success(t *testing.T) {
	resetDescriptionFlags(t)
	patched := false
	done := descriptionRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			patched = true
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"Description":"new note"}}`))
	})
	defer done()
	descID = 7
	require.NoError(t, descriptionCmd.Flags().Set("set", "new note"))

	out := captureStdoutForFolder(t, func() {
		err := descriptionCmd.RunE(descriptionCmd, nil)
		require.NoError(t, err)
	})
	assert.True(t, patched)
	assert.Contains(t, out, "new note")
}

func TestDescriptionCmd_Set_PatchError(t *testing.T) {
	resetDescriptionFlags(t)
	done := descriptionRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	descID = 7
	require.NoError(t, descriptionCmd.Flags().Set("set", "new note"))

	err := descriptionCmd.RunE(descriptionCmd, nil)
	require.Error(t, err)
}

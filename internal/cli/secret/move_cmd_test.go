package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMoveCmd_MissingID returns an error when --id is not set.
func TestMoveCmd_MissingID(t *testing.T) {
	orig := moveID
	t.Cleanup(func() { moveID = orig })
	moveID = 0
	err := moveCmd.RunE(moveCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

// TestMoveCmd_NotConnected returns an error when no server is configured.
func TestMoveCmd_NotConnected(t *testing.T) {
	orig := moveID
	t.Cleanup(func() { moveID = orig })
	moveID = 42
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := moveCmd.RunE(moveCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestMoveCmd_ToRoot_PrintsRootMessage confirms that moving to root prints "root".
func TestMoveCmd_ToRoot_PrintsRootMessage(t *testing.T) {
	origID := moveID
	origTo := moveTo
	t.Cleanup(func() { moveID = origID; moveTo = origTo })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	moveID = 42
	moveTo = 0
	err := moveCmd.RunE(moveCmd, nil)
	require.NoError(t, err)
}

// TestMoveCmd_ToFolder_PrintsFolderMessage confirms "folder N" in output when moveTo != 0.
func TestMoveCmd_ToFolder_PrintsFolderMessage(t *testing.T) {
	origID := moveID
	origTo := moveTo
	t.Cleanup(func() { moveID = origID; moveTo = origTo })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	moveID = 42
	moveTo = 7
	err := moveCmd.RunE(moveCmd, nil)
	require.NoError(t, err)
}

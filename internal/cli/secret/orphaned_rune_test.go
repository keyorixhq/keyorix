// orphaned_rune_test.go — exercises orphanedCmd.RunE directly
// (orphaned_remote_test.go only tests fetchOrphaned).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetOrphanedFlags(t *testing.T) {
	t.Helper()
	orig := orphanedProject
	t.Cleanup(func() { orphanedProject = orig })
}

func TestOrphanedCmd_MissingProject(t *testing.T) {
	resetOrphanedFlags(t)
	orphanedProject = 0
	err := orphanedCmd.RunE(orphanedCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestOrphanedCmd_NoServer(t *testing.T) {
	resetOrphanedFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	orphanedProject = 4
	err := orphanedCmd.RunE(orphanedCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestOrphanedCmd_Success_Empty(t *testing.T) {
	resetOrphanedFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"orphaned":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	orphanedProject = 4

	out := captureStdoutForFolder(t, func() {
		err := orphanedCmd.RunE(orphanedCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No orphaned secrets")
}

func TestOrphanedCmd_Success_WithRows(t *testing.T) {
	resetOrphanedFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"orphaned":[{"id":1,"name":"stray","type":"generic","classification":"internal","owner_id":99}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	orphanedProject = 4

	out := captureStdoutForFolder(t, func() {
		err := orphanedCmd.RunE(orphanedCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "stray")
}

func TestOrphanedCmd_FetchError(t *testing.T) {
	resetOrphanedFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	orphanedProject = 4

	err := orphanedCmd.RunE(orphanedCmd, nil)
	require.Error(t, err)
}

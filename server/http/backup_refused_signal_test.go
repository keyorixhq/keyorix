package http

// backup_refused_signal_test.go — #4105 over the real router: while a
// key-rotation staging file is in the key directory, `admin backup` is refused
// before it opens storage (exit 4, no audit event), so GET /api/v1/system/info
// reports security.backup_refused to an administrator; the signal clears once
// the file is gone, and reading it never touches a staging file.

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/server/http/handlers"
)

type backupRefusedEnv struct {
	Data struct {
		Security struct {
			BackupRefused *handlers.BackupRefusedStatus `json:"backup_refused"`
		} `json:"security"`
	} `json:"data"`
}

// newBackupRefusedServer serves the router with a key directory "keys/" under a
// fresh working directory, as boot and `admin backup` resolve it (base ".").
func newBackupRefusedServer(t *testing.T) (*shareDemo, *httptest.Server) {
	t.Helper()
	d := newShareDemo(t)
	t.Chdir(t.TempDir())
	require.NoError(t, os.Mkdir("keys", 0o700))
	for _, f := range []string{"keys/dek.key", "keys/kek.salt"} {
		require.NoError(t, os.WriteFile(f, []byte("active-key-material"), 0o600))
	}
	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}},
		Storage: config.StorageConfig{Encryption: config.EncryptionConfig{
			Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt",
		}},
	}
	router, err := NewRouter(cfg, d.c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return d, srv
}

func backupRefused(t *testing.T, srv *httptest.Server, tok string) (*handlers.BackupRefusedStatus, string) {
	t.Helper()
	code, raw := doMachineRequest(t, srv, tok, http.MethodGet, "/api/v1/system/info", nil)
	require.Equal(t, http.StatusOK, code, raw)
	var env backupRefusedEnv
	require.NoError(t, json.Unmarshal([]byte(raw), &env), raw)
	return env.Data.Security.BackupRefused, raw
}

func plantStaging(t *testing.T, path string) []byte {
	t.Helper()
	data := make([]byte, 48)
	_, err := rand.Read(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return data
}

func TestSystemInfo_BackupRefused_StaleSaltPending_SignalsUntilRemoved(t *testing.T) {
	d, srv := newBackupRefusedServer(t)

	st, raw := backupRefused(t, srv, d.adminTok)
	require.Nil(t, st, "control: no staging file, no signal: %s", raw)

	saltPending := filepath.Join("keys", "kek.salt.pending")
	plantStaging(t, saltPending)

	for range 2 {
		st, raw = backupRefused(t, srv, d.adminTok)
		require.NotNil(t, st, "an administrator must see backup_refused: %s", raw)
		require.Equal(t, keyfiles.BackupRefusedReasonStagingFile, st.Reason)
		require.Equal(t, []string{saltPending}, st.Files)
		require.True(t, st.StagingSaltOnly)
		require.Contains(t, st.Remedy, "move the staging file out of the key directory")
		require.Contains(t, st.Remedy, "admin validate --posture")
	}

	// It names key-file paths: system.write only, like recovery_key.
	_, aliceRaw := backupRefused(t, srv, d.aliceTok)
	require.NotContains(t, aliceRaw, "backup_refused", "a caller without system.write must not see it")
	require.NotContains(t, aliceRaw, "kek.salt.pending")

	require.FileExists(t, saltPending, "reading the signal never moves or deletes the file")
	require.NoError(t, os.Remove(saltPending))
	st, raw = backupRefused(t, srv, d.adminTok)
	require.Nil(t, st, "the signal clears once the file is gone: %s", raw)
}

// A DEK's staging file can be the only copy of the new DEK: the signal reports
// it, never suggests removing it, and leaves its bytes exactly as they were.
func TestSystemInfo_BackupRefused_DEKPending_ReportedAndNeverTouched(t *testing.T) {
	d, srv := newBackupRefusedServer(t)
	dekPending := filepath.Join("keys", "dek.key.pending")
	saltPending := filepath.Join("keys", "kek.salt.pending")
	want := map[string][]byte{dekPending: plantStaging(t, dekPending), saltPending: plantStaging(t, saltPending)}
	before, err := os.Stat(dekPending)
	require.NoError(t, err)

	for range 3 {
		st, raw := backupRefused(t, srv, d.adminTok)
		require.NotNil(t, st, raw)
		require.Equal(t, keyfiles.BackupRefusedReasonStagingFile, st.Reason)
		require.ElementsMatch(t, []string{saltPending, dekPending}, st.Files)
		require.False(t, st.StagingSaltOnly, "with a DEK staging file present the salt advice does not apply")
		require.Contains(t, st.Remedy, "Never delete a DEK's .pending file by hand")
		require.NotContains(t, st.Remedy, "move the staging file")
	}

	for path, data := range want {
		got, rerr := os.ReadFile(path)
		require.NoError(t, rerr, "%s must survive", path)
		require.Equal(t, data, got, "%s must be byte-identical", path)
	}
	after, err := os.Stat(dekPending)
	require.NoError(t, err)
	require.Equal(t, before.Mode(), after.Mode())
	require.Equal(t, before.ModTime(), after.ModTime())
}

// A check that cannot tell is reported as refused (the backup refuses too),
// without the error's text.
func TestSystemInfo_BackupRefused_CheckFailure_FailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the stat cannot be made to fail")
	}
	d, srv := newBackupRefusedServer(t)
	require.NoError(t, os.Chmod("keys", 0o000))
	t.Cleanup(func() { _ = os.Chmod("keys", 0o700) })

	st, raw := backupRefused(t, srv, d.adminTok)
	require.NotNil(t, st, "an unreadable key directory must not read as \"backups fine\": %s", raw)
	require.Equal(t, "staging-file-check-failed", st.Reason)
	require.Empty(t, st.Files)
	require.NotContains(t, raw, "permission denied", "the error text stays in the server log")
}

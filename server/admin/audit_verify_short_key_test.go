package admin

import (
	"crypto/fips140"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// TestVerifyAudit_ShortCheckpointKey_WarnsOnStderrAndStillVerifies drives the
// real command in default mode against a chain really signed with a 9-byte
// key: the operator is warned on stderr, the --json output stays parseable, and
// the key still authenticates the checkpoint.
func TestVerifyAudit_ShortCheckpointKey_WarnsOnStderrAndStillVerifies(t *testing.T) {
	skipUnderFIPS140Only(t, "a checkpoint key under 14 bytes cannot key HMAC in that mode; TestVerifyAudit_UnderFIPS140Only_ShortCheckpointKeyRefusedNoWarning covers it")
	resetVerifyAuditAndExportFlags(t)
	origKey := offlineAnchorTestKey
	offlineAnchorTestKey = []byte("short-key")
	t.Cleanup(func() { offlineAnchorTestKey = origKey })

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)
	configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "")
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
	verifyAuditJSON = true

	var out string
	var runErr error
	stderr := captureStderr(t, func() {
		out, runErr = captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	})

	require.NoError(t, runErr, "a short key must still verify in default mode")
	require.Contains(t, stderr, "WARNING: the checkpoint key is 9 bytes, shorter than MinKEKLen (14 bytes")
	require.NotContains(t, stderr, "short-key", "the warning must never contain the key")
	require.NotContains(t, stderr, hex.EncodeToString(offlineAnchorTestKey), "the warning must never contain the key")

	var res auditverify.Result
	require.NoError(t, json.Unmarshal([]byte(out), &res), "stdout must stay pure JSON: %s", out)
	require.Equal(t, auditverify.VerdictValid, res.Verdict)
	require.True(t, res.Checkpoint.Authenticated, "the short key must have authenticated the checkpoint")
}

// A full-length key prints no warning.
func TestVerifyAudit_FullLengthCheckpointKey_NoWarning(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)
	configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "")
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)

	var runErr error
	stderr := captureStderr(t, func() {
		_, runErr = captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	})
	require.NoError(t, runErr)
	require.NotContains(t, stderr, "WARNING")
}

// Under the real GODEBUG=fips140=only the refusal stays as shipped: exit 3,
// ErrCheckpointKeyTooShort, and no warning. Skips in default CI.
func TestVerifyAudit_UnderFIPS140Only_ShortCheckpointKeyRefusedNoWarning(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; the seam tests in internal/auditverify drive this in default mode")
	}
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)
	configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "")
	verifyAuditKeyFile = filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(verifyAuditKeyFile, []byte(hex.EncodeToString([]byte("short-key"))), 0600))

	var runErr error
	stderr := captureStderr(t, func() {
		_, runErr = captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	})

	var ece *exitCodeError
	require.ErrorAs(t, runErr, &ece)
	require.Equal(t, 3, ece.code)
	require.True(t, errors.Is(runErr, auditverify.ErrCheckpointKeyTooShort), "got %v", runErr)
	require.NotContains(t, stderr, "WARNING")
}

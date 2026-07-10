package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// writeSigningKey generates an ed25519 key and writes it as a PKCS#8 PEM file,
// the format `license issue` expects.
func writeSigningKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sign.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

func TestGraceOf(t *testing.T) {
	assert.Equal(t, 14*24*time.Hour, graceOf(0))
	assert.Equal(t, 14*24*time.Hour, graceOf(-3))
	assert.Equal(t, 24*time.Hour, graceOf(24))
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	require.NoError(t, os.WriteFile(p, []byte("  the-token \n"), 0o600))
	got, err := readToken(p)
	require.NoError(t, err)
	assert.Equal(t, "the-token", got)

	_, err = readToken(filepath.Join(dir, "does-not-exist"))
	require.Error(t, err)
}

func TestPrintStatus(t *testing.T) {
	t.Run("granting", func(t *testing.T) {
		out := captureStdout(t, func() {
			printStatus(ilicense.Status{
				State: ilicense.StateActive, Licensee: "acme", Plan: "enterprise",
				Features: []string{"airgap_updates"}, NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			})
		})
		assert.Contains(t, out, "state:    active")
		assert.Contains(t, out, "licensee: acme")
		assert.Contains(t, out, "plan:     enterprise")
		assert.Contains(t, out, "features: airgap_updates")
		assert.Contains(t, out, "expires:  2030-01-01T00:00:00Z")
	})

	t.Run("baseline shows no commercial features", func(t *testing.T) {
		out := captureStdout(t, func() {
			printStatus(ilicense.Status{State: ilicense.StateNone, Reason: "no license installed"})
		})
		assert.Contains(t, out, "state:    none")
		assert.Contains(t, out, "community baseline")
		assert.Contains(t, out, "note:     no license installed")
	})
}

func TestIssue_HappyPath(t *testing.T) {
	issueLicensee = "acme"
	issuePlan = "enterprise-airgap"
	issueFeatures = "airgap_updates, extra"
	issueNotAfter = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	issueKeyID = "test-key"
	issueSignKey = writeSigningKey(t)
	t.Cleanup(func() {
		issueLicensee, issuePlan, issueFeatures, issueNotAfter, issueKeyID, issueSignKey = "", "", "", "", "", ""
	})

	out := captureStdout(t, func() { require.NoError(t, issueCmd.RunE(nil, nil)) })
	assert.NotEmpty(t, strings.TrimSpace(out), "issue must print a token")
}

func TestIssue_ErrorPaths(t *testing.T) {
	t.Run("bad not-after", func(t *testing.T) {
		issueNotAfter = "not-a-date"
		issueSignKey = writeSigningKey(t)
		t.Cleanup(func() { issueNotAfter, issueSignKey = "", "" })
		err := issueCmd.RunE(nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--not-after must be RFC3339")
	})

	t.Run("missing signing key file", func(t *testing.T) {
		issueNotAfter = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		issueSignKey = filepath.Join(t.TempDir(), "nope.pem")
		t.Cleanup(func() { issueNotAfter, issueSignKey = "", "" })
		err := issueCmd.RunE(nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read signing key")
	})
}

func TestInstall_RequiresDest(t *testing.T) {
	installDest = ""
	err := installCmd.RunE(nil, []string{"whatever"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--dest is required")
}

func TestInstall_RefusesInvalidToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "bad.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("this-is-not-a-valid-token"), 0o600))

	installDest = filepath.Join(dir, "installed.token")
	installDeployment = ""
	installGraceHours = 0
	t.Cleanup(func() { installDest, installDeployment, installGraceHours = "", "", 0 })

	err := installCmd.RunE(nil, []string{tokenFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to install an invalid license")
	_, statErr := os.Stat(installDest)
	assert.True(t, os.IsNotExist(statErr), "an invalid token must not be written")
}

func TestInstall_EmptyTokenBaselineWritesFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "empty.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(""), 0o600))

	installDest = filepath.Join(dir, "installed.token")
	t.Cleanup(func() { installDest = "" })

	out := captureStdout(t, func() { require.NoError(t, installCmd.RunE(nil, []string{tokenFile})) })
	assert.Contains(t, out, "Installed license")
	_, err := os.Stat(installDest)
	require.NoError(t, err, "a baseline (empty) token still installs")
}

func TestStatus_Baseline(t *testing.T) {
	statusFile = ""
	statusDeployment = ""
	statusGraceHours = 0
	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "state:    none")
	assert.Contains(t, out, "community baseline")
}

func TestStatus_GarbageTokenFileIsFailSafe(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "garbage.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("garbage"), 0o600))
	statusFile = tokenFile
	t.Cleanup(func() { statusFile = "" })

	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "state:    invalid", "a garbage token degrades to invalid, never errors the tool")
}

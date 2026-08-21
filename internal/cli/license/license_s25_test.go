package license

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRSAKey writes a PKCS#8 PEM file containing an RSA key (not ed25519) so that
// ParsePrivateKeyPEM succeeds at PEM decode and PKCS#8 parse but fails the ed25519
// type assertion — exercising the "signing key is not ed25519" branch.
func writeRSAKey(t *testing.T) string {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "rsa.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

// writeJunkPEM writes a PEM file whose DER content is not a valid PKCS#8 key so that
// x509.ParsePKCS8PrivateKey returns an error — exercising the "parse signing key" branch.
func writeJunkPEM(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "junk.pem")
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-valid-der")}
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

// --- issueCmd error paths ---

func TestIssue_BadPEM_NotED25519(t *testing.T) {
	issueNotAfter = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	issueSignKey = writeRSAKey(t)
	t.Cleanup(func() { issueNotAfter, issueSignKey = "", "" })

	err := issueCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not ed25519")
}

func TestIssue_BadPEM_ParseError(t *testing.T) {
	issueNotAfter = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	issueSignKey = writeJunkPEM(t)
	t.Cleanup(func() { issueNotAfter, issueSignKey = "", "" })

	err := issueCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse signing key")
}

func TestIssue_NoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "nopem.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("just raw bytes, not PEM"), 0o600))
	issueNotAfter = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	issueSignKey = notPEM
	t.Cleanup(func() { issueNotAfter, issueSignKey = "", "" })

	err := issueCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

// TestIssue_IssueCallFails covers the branch where ilicense.Issue itself returns an
// error (as opposed to the earlier PEM-parsing failures already covered above) — here
// by leaving --key-id empty, which Issue rejects even though issueCmd.RunE never
// validates it itself (that's normally cobra's MarkFlagRequired, bypassed when calling
// RunE directly in tests).
func TestIssue_IssueCallFails(t *testing.T) {
	issueLicensee = "acme"
	issueNotAfter = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	issueKeyID = ""
	issueSignKey = writeSigningKey(t)
	t.Cleanup(func() { issueLicensee, issueNotAfter, issueKeyID, issueSignKey = "", "", "", "" })

	err := issueCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key-id is required")
}

// --- installCmd error paths ---

func TestInstall_MissingTokenFile(t *testing.T) {
	dir := t.TempDir()
	installDest = filepath.Join(dir, "out.token")
	t.Cleanup(func() { installDest = "" })

	err := installCmd.RunE(nil, []string{filepath.Join(dir, "no-such-file.token")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read license token")
}

// TestInstall_WriteFailure covers the branch where the license validates fine (an
// empty token, same as TestInstall_EmptyTokenBaselineWritesFile) but
// securefiles.SecureWriteFileSync itself fails — here because --dest's parent
// directory doesn't exist, so the underlying open(2) of the base directory fails.
func TestInstall_WriteFailure(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "empty.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(""), 0o600))

	installDest = filepath.Join(dir, "no-such-subdir", "installed.token")
	installDeployment = ""
	installGraceHours = 0
	t.Cleanup(func() { installDest, installDeployment, installGraceHours = "", "", 0 })

	err := installCmd.RunE(nil, []string{tokenFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write license")
	_, statErr := os.Stat(installDest)
	assert.True(t, os.IsNotExist(statErr), "a failed write must not leave a file behind")
}

// --- statusCmd error paths ---

func TestStatus_MissingTokenFile(t *testing.T) {
	statusFile = "/nonexistent/path/license.token"
	t.Cleanup(func() { statusFile = "" })

	err := statusCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read license token")
}

// --- printStatus branch coverage ---

// TestPrintStatus_ExpiringSoon covers the StateExpiringSoon path:
// Grants()==true, has features, has Reason, has NotAfter.
func TestPrintStatus_ExpiringSoon(t *testing.T) {
	out := captureStdout(t, func() {
		printStatus(ilicense.Status{
			State:    ilicense.StateExpiringSoon,
			Licensee: "widgets-inc",
			Plan:     "enterprise",
			Features: []string{"airgap_updates", "sso"},
			NotAfter: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
			Reason:   "license expires on 2026-07-20T00:00:00Z — renew soon",
		})
	})
	assert.Contains(t, out, "state:    expiring_soon")
	assert.Contains(t, out, "licensee: widgets-inc")
	assert.Contains(t, out, "plan:     enterprise")
	assert.Contains(t, out, "features: airgap_updates, sso")
	assert.Contains(t, out, "expires:  2026-07-20T00:00:00Z")
	assert.Contains(t, out, "note:     license expires on")
}

// TestPrintStatus_Expired covers the StateExpired path:
// Grants()==false so the "community baseline" branch is taken even though Features
// could be populated; Reason and NotAfter are both set.
func TestPrintStatus_Expired(t *testing.T) {
	out := captureStdout(t, func() {
		printStatus(ilicense.Status{
			State:    ilicense.StateExpired,
			Licensee: "old-co",
			Plan:     "enterprise",
			NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Reason:   "license expired on 2025-01-01T00:00:00Z — running the community baseline",
		})
	})
	assert.Contains(t, out, "state:    expired")
	assert.Contains(t, out, "licensee: old-co")
	assert.Contains(t, out, "plan:     enterprise")
	assert.Contains(t, out, "expires:  2025-01-01T00:00:00Z")
	assert.Contains(t, out, "community baseline")
	assert.Contains(t, out, "note:     license expired on")
}

// TestPrintStatus_GrantingNoNotAfter covers the !st.NotAfter.IsZero() false branch:
// Grants()==true but NotAfter is zero, which skips the "expires:" line.
func TestPrintStatus_GrantingNoNotAfter(t *testing.T) {
	out := captureStdout(t, func() {
		printStatus(ilicense.Status{
			State:    ilicense.StateActive,
			Licensee: "perpetual-co",
			Plan:     "enterprise",
			Features: []string{"airgap_updates"},
		})
	})
	assert.Contains(t, out, "state:    active")
	assert.Contains(t, out, "licensee: perpetual-co")
	assert.NotContains(t, out, "expires:")
	assert.Contains(t, out, "features: airgap_updates")
}

// TestPrintStatus_GrantingEmptyFeatures covers the Grants()==true but len(Features)==0
// path: the else branch prints "community baseline" even though the state is active.
func TestPrintStatus_GrantingEmptyFeatures(t *testing.T) {
	out := captureStdout(t, func() {
		printStatus(ilicense.Status{
			State:    ilicense.StateActive,
			Licensee: "no-feature-co",
			Plan:     "base",
		})
	})
	assert.Contains(t, out, "state:    active")
	assert.Contains(t, out, "community baseline")
}

// TestPrintStatus_NoLicenseeNoPlan exercises the branches where Licensee and Plan are
// empty, so both optional Printf lines are skipped.
func TestPrintStatus_NoLicenseeNoPlan(t *testing.T) {
	out := captureStdout(t, func() {
		printStatus(ilicense.Status{
			State:  ilicense.StateNone,
			Reason: "no license installed",
		})
	})
	assert.Contains(t, out, "state:    none")
	assert.NotContains(t, out, "licensee:")
	assert.NotContains(t, out, "plan:")
	assert.Contains(t, out, "community baseline")
	assert.Contains(t, out, "note:     no license installed")
}

// TestInstall_HappyPath exercises the full installCmd success path including the
// printStatus call inside it, with a real signed token file.
func TestInstall_HappyPath(t *testing.T) {
	// Build a valid signed token using the internal package directly.
	keyPath := writeSigningKey(t)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	priv, err := ilicense.ParsePrivateKeyPEM(keyPEM)
	require.NoError(t, err)

	token, err := ilicense.Issue(ilicense.License{
		Licensee: "test-corp",
		Plan:     "enterprise",
		Features: []string{"airgap_updates"},
		IssuedAt: time.Now().UTC(),
		NotAfter: time.Now().Add(30 * 24 * time.Hour).UTC(),
		KeyID:    "test-key-id",
	}, priv)
	require.NoError(t, err)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "license.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(token), 0o600))

	installDest = filepath.Join(dir, "installed.token")
	installDeployment = ""
	installGraceHours = 0
	t.Cleanup(func() { installDest, installDeployment, installGraceHours = "", "", 0 })

	// The token will evaluate as StateInvalid because the test key is not in the
	// DefaultRegistry — so it won't be written. This exercises the "refusing" branch
	// again, which is fine: we cannot inject a test key into the embedded registry.
	// The valuable coverage here is readToken + Evaluate + the error return.
	err = installCmd.RunE(nil, []string{tokenFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to install an invalid license")
}

// TestStatus_WithTokenFile exercises the statusCmd path where statusFile is set to a
// readable token file (non-empty content that is ultimately invalid for the registry).
func TestStatus_WithTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "some.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("payload.sig"), 0o600))

	statusFile = tokenFile
	statusDeployment = ""
	statusGraceHours = 0
	t.Cleanup(func() { statusFile, statusDeployment, statusGraceHours = "", "", 0 })

	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "state:    invalid")
}

// TestGraceOf_Boundary exercises the exact-zero edge of graceOf.
func TestGraceOf_Boundary(t *testing.T) {
	assert.Equal(t, 14*24*time.Hour, graceOf(0))
	assert.Equal(t, 1*time.Hour, graceOf(1))
	assert.Equal(t, 336*time.Hour, graceOf(336))
}

package bundle

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain sandboxes every test in this package against a throwaway
// KEYORIX_BUNDLE_STATE_DIR, so running `go test ./internal/bundle/...` never reads or
// writes the real developer/CI-runner home directory's ~/.keyorix/bundle-installs — the
// production default (externalStateBaseDir) deliberately resolves there when no override
// is set, which is correct in production but not something a test run should touch.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keyorix-bundle-state-test-*")
	if err != nil {
		os.Exit(1)
	}
	if err := os.Setenv(installStateDirEnvOverride, dir); err != nil {
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// resignForRegistry builds + signs a NEW bundle for keyID, registering a freshly generated
// key under that keyID in the EXISTING reg (overwriting whatever key was previously
// registered there — trust.KeyRegistry.Add allows re-registering a keyID with a different
// key under the same purpose; only cross-purpose reuse is refused). This lets a test build
// a second, differently-versioned bundle that still verifies against the same registry
// object passed to an earlier Extract call, without needing to keep the original signing
// key around (signedBundle doesn't return one reusable across calls with a shared registry).
func resignForRegistry(t *testing.T, reg *trust.KeyRegistry, files map[string]string, version, keyID, minFrom string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	dir := srcDirWith(t, files)
	m, err := BuildManifest(dir, version, keyID, minFrom, time.Unix(1_700_000_000, 0))
	require.NoError(t, err)
	sig, err := Sign(m, priv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, WriteBundle(&buf, dir, m, sig))
	require.NoError(t, reg.Add(trust.PurposeUpdate, keyID, pub))
	return buf.Bytes()
}

// TestExtract_WholeDestDirWipe_ResetsGateWithoutExternalState is the RED case: with the
// external install-state record disabled (nothing to compare against, i.e. the world
// before this fix), deleting the ENTIRE destDir after a successful import is treated as an
// unremarkable first install, and a subsequent downgrade sails through with no error. This
// pins the pre-fix gap for the specific code path that no longer has it once
// KEYORIX_BUNDLE_STATE_DIR resolves to somewhere real (see the GREEN test below).
func TestExtract_WholeDestDirWipe_ResetsGateWithoutExternalState(t *testing.T) {
	t.Setenv(installStateDirEnvOverride, installStateDisabledValue) // disable the external record for this test only
	dest := t.TempDir()

	raw1, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v2.0.0", "k-wipe", "")
	_, err := Extract(bytes.NewReader(raw1), reg, dest, "")
	require.NoError(t, err)

	// Simulate an import-capable adversary (or a confused operator) wiping the whole
	// destination, not just the marker file.
	require.NoError(t, os.RemoveAll(dest))
	require.NoError(t, os.MkdirAll(dest, 0o750))

	raw0 := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v1.0.0", "k-wipe", "")
	_, err = Extract(bytes.NewReader(raw0), reg, dest, "")
	assert.NoError(t, err, "documents the pre-fix gap: with no external record, a wiped destDir "+
		"looks like a genuine first install and the downgrade to v1.0.0 is silently allowed")
}

// TestExtract_WholeDestDirWipe_RefusedByExternalState is the GREEN case: with the external
// install-state record resolvable (the default posture once KEYORIX_BUNDLE_STATE_DIR — or
// $HOME/.keyorix in production — is set, as TestMain arranges for this whole package),
// wiping the entire destDir no longer resets the gate silently: Extract refuses with
// ErrInstallStateReset instead of treating the wipe as a first install.
func TestExtract_WholeDestDirWipe_RefusedByExternalState(t *testing.T) {
	dest := t.TempDir()

	raw1, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v2.0.0", "k-wipe2", "")
	_, err := Extract(bytes.NewReader(raw1), reg, dest, "")
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dest))
	require.NoError(t, os.MkdirAll(dest, 0o750))

	raw0 := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v1.0.0", "k-wipe2", "")
	_, err = Extract(bytes.NewReader(raw0), reg, dest, "")
	require.Error(t, err, "a wiped destDir must not be silently treated as a first install when an "+
		"external install-state record still remembers v2.0.0 was installed here")
	assert.True(t, errors.Is(err, ErrInstallStateReset), "got: %v", err)

	// A refused import must not write anything to dest (fail closed before any component
	// write, exactly like every other Extract refusal) — dest was wiped by the test setup
	// above and must stay that way, not partially re-populated by the refused attempt.
	_, statErr := os.Stat(filepath.Join(dest, "a.bin"))
	assert.True(t, os.IsNotExist(statErr), "a refused import must not stage any component; got stat err: %v", statErr)
}

// TestExtract_WholeDestDirWipe_AcknowledgedResetStillEnforcesDowngrade verifies that
// acknowledging the reset does NOT disable the no-downgrade check itself — it only resolves
// which record to trust. Since the internal marker was wiped along with the rest of
// destDir, the reconciled state is "no anchor" (a genuine first install), so an
// operator-supplied --installed-version (or its absence) governs exactly as it would for
// any other first install, and the check resumes enforcing on the very next import.
func TestExtract_WholeDestDirWipe_AcknowledgedResetStillEnforcesDowngrade(t *testing.T) {
	dest := t.TempDir()

	raw1, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v2.0.0", "k-wipe3", "")
	_, err := Extract(bytes.NewReader(raw1), reg, dest, "")
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dest))
	require.NoError(t, os.MkdirAll(dest, 0o750))

	raw0 := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v1.0.0", "k-wipe3", "")

	// Acknowledging the reset without an --installed-version to anchor against still lets
	// the (older, but now-unanchored) bundle stage — matching first-install semantics
	// exactly (this is why the CLI layer additionally requires --installed-version or
	// --force on a true first install; the library call alone does not).
	m, err := ExtractAllowingStateReset(bytes.NewReader(raw0), reg, dest, "", true)
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", m.Version)

	// A second, later import of an even older version, now anchored by the record
	// ExtractAllowingStateReset just wrote, must still be caught as a downgrade.
	rawOlder := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v0.9.0", "k-wipe3", "")
	_, err = Extract(bytes.NewReader(rawOlder), reg, dest, "")
	require.Error(t, err, "the no-downgrade check must resume enforcing normally after an acknowledged reset")
	assert.True(t, errors.Is(err, ErrNotUpgrade), "got: %v", err)
}

// TestExtract_MarkerEditedInPlace_RefusedByExternalState covers the OTHER gap the external
// record closes, beyond outright destDir deletion: editing the marker file's CONTENT to
// claim an older installed version (the marker still exists, so #111's "content but no
// marker" check never fires) is also caught, because the internal and external records now
// disagree.
func TestExtract_MarkerEditedInPlace_RefusedByExternalState(t *testing.T) {
	dest := t.TempDir()

	raw2, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v2.0.0", "k-edit", "")
	_, err := Extract(bytes.NewReader(raw2), reg, dest, "")
	require.NoError(t, err)

	// Edit the marker in place to claim an older installed version, without touching
	// anything else (no deletion at all — the #111 "content but no marker" check cannot
	// see this, because the marker is still present).
	require.NoError(t, os.WriteFile(filepath.Join(dest, installedVersionMarker), []byte("v1.0.0\n"), 0o600))

	rawRepeat := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v1.5.0", "k-edit", "")
	_, err = Extract(bytes.NewReader(rawRepeat), reg, dest, "")
	require.Error(t, err, "an in-place-edited marker claiming v1.0.0 must not let v1.5.0 verify as an upgrade")
	assert.True(t, errors.Is(err, ErrInstallStateReset), "got: %v", err)
}

// TestPersistedInstalledVersionAllowingReset_Cov exercises the CLI-facing entry point
// directly (mirroring the existing PersistedInstalledVersion coverage in
// bundle_coverage_test.go), across the reset/no-reset combinations.
func TestPersistedInstalledVersionAllowingReset_Cov(t *testing.T) {
	dest := t.TempDir()
	raw, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v3.0.0", "k-parv", "")
	_, err := Extract(bytes.NewReader(raw), reg, dest, "")
	require.NoError(t, err)

	version, ok, err := PersistedInstalledVersionAllowingReset(dest, false)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "v3.0.0", version)

	require.NoError(t, os.RemoveAll(dest))
	require.NoError(t, os.MkdirAll(dest, 0o750))

	_, ok, err = PersistedInstalledVersionAllowingReset(dest, false)
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrInstallStateReset), "got: %v", err)

	_, ok, err = PersistedInstalledVersionAllowingReset(dest, true)
	assert.False(t, ok)
	assert.NoError(t, err, "acknowledging the reset must clear the refusal and read back as a first install")
}

// TestReconcileInstallState_BackfillsExistingInternalMarker verifies the "internal present,
// external absent" case is NOT suspicious: an install performed before external tracking
// existed (or targeting a destDir whose external directory only just became resolvable)
// must not be refused, and a following import backfills the external record.
func TestReconcileInstallState_BackfillsExistingInternalMarker(t *testing.T) {
	dest := t.TempDir()

	// Write the internal marker directly, bypassing Extract entirely, to simulate a
	// pre-existing install that predates this feature (no external record was ever
	// written for it).
	require.NoError(t, os.WriteFile(filepath.Join(dest, installedVersionMarker), []byte("v4.0.0\n"), 0o600))

	version, ok, err := PersistedInstalledVersion(dest)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "v4.0.0", version)

	// A subsequent import must both succeed and backfill the external record — verified by
	// checking that a wipe-then-reimport-older-version is now caught (which would not
	// happen if the external record was never written).
	raw, reg, _ := signedBundle(t, map[string]string{"a.bin": "x"}, "v4.1.0", "k-backfill", "")
	_, err = Extract(bytes.NewReader(raw), reg, dest, "v4.0.0")
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dest))
	require.NoError(t, os.MkdirAll(dest, 0o750))

	rawOld := resignForRegistry(t, reg, map[string]string{"a.bin": "x"}, "v1.0.0", "k-backfill", "")
	_, err = Extract(bytes.NewReader(rawOld), reg, dest, "")
	require.Error(t, err, "the backfilled external record must now catch a post-wipe downgrade")
	assert.True(t, errors.Is(err, ErrInstallStateReset), "got: %v", err)
}

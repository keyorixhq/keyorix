// absolute_key_paths_test.go — regression tests for the absolute dek_path /
// salt_path boot failure fixed in normalizeKeyPaths.
//
// Before the fix, server/main.go set baseDir="" whenever DEKPath was absolute,
// intending "self-contained path, no base-dir restriction". No internal/
// securefiles primitive implements that convention, so first-boot key
// generation failed on every start with
//
//	failed to write wrapped DEK: access denied: file %q is outside of ""
//
// meaning no deployment configuring an absolute key path could ever boot. It
// went unnoticed because nothing in the test suite used an absolute key path;
// the DAST workflow (/tmp/keyorix-dast.dek) was the only caller that did, and
// it is push-triggered on main rather than a PR-blocking check.
package encryption

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The case that was broken: absolute paths in a shared directory must boot.
func TestNewKeyManager_AbsolutePaths_FirstBootSucceeds(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager("", filepath.Join(dir, "keyorix.dek"), filepath.Join(dir, "keyorix.salt"))

	require.NoError(t, km.configErr, "absolute key paths in one directory must be accepted")
	require.NoError(t, km.Initialize("correct horse battery staple"),
		"first-boot key generation must succeed with absolute key paths")

	assert.Equal(t, dir, km.baseDir, "base dir should become the keys' directory")
	assert.Equal(t, "keyorix.dek", km.dekPath, "dek path should be reduced to its base name")
	assert.Equal(t, "keyorix.salt", km.saltPath, "salt path should be reduced to its base name")
	assert.FileExists(t, filepath.Join(dir, "keyorix.dek"))
	assert.FileExists(t, filepath.Join(dir, "keyorix.salt"))
}

// Guards the trap in the obvious fix. Splitting a RELATIVE path into Dir/Base
// would convert a traversal rejection into an accepted escape: "../../etc/x" is
// refused today because safeRelComponents rejects the ".." component, but as
// (base="../../etc", name="x") both containment checks pass. Only absolute
// paths may be rewritten — this test fails if that ever changes.
func TestNewKeyManager_RelativePaths_LeftUnchangedAndStillContained(t *testing.T) {
	km := NewKeyManager(t.TempDir(), "../../etc/evil.dek", "../../etc/evil.salt")
	require.NoError(t, km.configErr, "relative paths are not a construction-time error")

	assert.Equal(t, "../../etc/evil.dek", km.dekPath, "a relative path must not be rewritten")
	assert.Equal(t, "../../etc/evil.salt", km.saltPath, "a relative path must not be rewritten")

	err := km.Initialize("correct horse battery staple")
	require.Error(t, err, "a relative key path escaping the base dir must still be refused")
	assert.Contains(t, err.Error(), "access denied")
}

// An ordinary relative configuration keeps working exactly as before.
func TestNewKeyManager_RelativePaths_UnderBaseDirStillBoot(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.configErr)
	require.NoError(t, km.Initialize("correct horse battery staple"))
	assert.Equal(t, dir, km.baseDir)
	assert.FileExists(t, filepath.Join(dir, "dek.key"))
}

// baseDir is the join root for the DEK lock, the server lock and the .pending
// rotation siblings as well as the two key files, so two absolute paths in
// different directories have no single correct base. Refused loudly rather than
// guessed at.
func TestNewKeyManager_AbsolutePathsInDifferentDirs_Refused(t *testing.T) {
	km := NewKeyManager("", filepath.Join(t.TempDir(), "a.dek"), filepath.Join(t.TempDir(), "b.salt"))

	require.Error(t, km.configErr)
	assert.Contains(t, km.configErr.Error(), "same directory")
	assert.Error(t, km.Initialize("correct horse battery staple"),
		"Initialize must surface the construction error rather than proceed")
}

func TestNewKeyManager_MixedAbsoluteAndRelative_Refused(t *testing.T) {
	for _, tc := range []struct{ name, dek, salt string }{
		{"abs dek, rel salt", filepath.Join(t.TempDir(), "a.dek"), "kek.salt"},
		{"rel dek, abs salt", "dek.key", filepath.Join(t.TempDir(), "b.salt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km := NewKeyManager(t.TempDir(), tc.dek, tc.salt)
			require.Error(t, km.configErr)
			assert.Contains(t, km.configErr.Error(), "both be absolute or both be relative")
		})
	}
}

// An unset path means "not configured" (keyfiles.Registry skips empty entries),
// so it must not be mistaken for the relative half of a mixed pair.
func TestNewKeyManager_EmptyPath_NotTreatedAsMixed(t *testing.T) {
	km := NewKeyManager(t.TempDir(), filepath.Join(t.TempDir(), "a.dek"), "")
	assert.NoError(t, km.configErr)
}

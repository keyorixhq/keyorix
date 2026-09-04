package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// readYAMLMap re-reads path and decodes it into a generic map for assertions on
// individual keys, independent of the Config struct's own field set (SaveFields
// operates on arbitrary YAML key paths, not just ones Config happens to declare).
func readYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, yaml.Unmarshal(data, &m))
	return m
}

// ---------------------------------------------------------------------------
// IsNotExist
// ---------------------------------------------------------------------------

// TestIsNotExist_TrueForWrappedFsErrNotExist confirms the documented contract:
// unlike os.IsNotExist, IsNotExist must see through fmt.Errorf's %w wrapping.
func TestIsNotExist_TrueForWrappedFsErrNotExist(t *testing.T) {
	err := fmt.Errorf("failed to read config file %q: %w", "x.yaml", fs.ErrNotExist)
	assert.True(t, IsNotExist(err))
}

// TestIsNotExist_TrueForRealMissingFileOpen exercises the actual stdlib error
// shape (a *fs.PathError from os.Open on a missing path), not just a hand-built
// fs.ErrNotExist wrap.
func TestIsNotExist_TrueForRealMissingFileOpen(t *testing.T) {
	dir := t.TempDir()
	_, err := os.Open(filepath.Join(dir, "does-not-exist.yaml"))
	require.Error(t, err)
	assert.True(t, IsNotExist(err))
}

// TestIsNotExist_TrueThroughLoadWrapping mirrors the real production call chain:
// Load wraps securefiles' not-found error in its own "failed to read config file"
// message. IsNotExist exists specifically because that wrapping breaks
// os.IsNotExist; confirm it survives the actual wrap Load performs, not just a
// synthetic one.
func TestIsNotExist_TrueThroughLoadWrapping(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
	assert.True(t, IsNotExist(err), "Load's wrapped not-exist error must satisfy IsNotExist")
}

// TestIsNotExist_FalseForParseError is the read-side counterpart of #1644: a
// config file that EXISTS but fails to parse must never be mistaken for one that
// doesn't exist. A caller that gets this wrong falls back to save-the-defaults
// and silently destroys the file's real content.
func TestIsNotExist_FalseForParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("a: [1, 2\n"), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.False(t, IsNotExist(err), "a parse/decode failure must NOT be mistaken for not-exist")
}

// TestIsNotExist_FalseForNil confirms the zero-value / no-error case.
func TestIsNotExist_FalseForNil(t *testing.T) {
	assert.False(t, IsNotExist(nil))
}

// ---------------------------------------------------------------------------
// SaveFields
// ---------------------------------------------------------------------------

// TestSaveFields_CreatesNewFile validates the fresh-install path: when the
// target file doesn't exist yet, SaveFields creates one containing only the
// given fields.
func TestSaveFields_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")

	require.NoError(t, SaveFields(path, map[string]any{
		"environment": "prod",
	}))

	m := readYAMLMap(t, path)
	assert.Equal(t, map[string]any{"environment": "prod"}, m)
}

// TestSaveFields_PreservesOtherKeys is the core #1644 regression test: writing
// one named field via SaveFields must leave every other pre-existing top-level
// key's value completely untouched -- this is exactly the property Save (full
// struct remarshal) violated.
func TestSaveFields_PreservesOtherKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")

	original := "" +
		"environment: dev\n" +
		"security:\n" +
		"  require_transport_tls: true\n" +
		"  other_flag: false\n" +
		"storage:\n" +
		"  type: local\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))

	require.NoError(t, SaveFields(path, map[string]any{
		"environment": "prod",
	}))

	m := readYAMLMap(t, path)
	assert.Equal(t, "prod", m["environment"], "the named field must be updated")

	security, ok := m["security"].(map[string]any)
	require.True(t, ok, "security mapping must survive untouched")
	assert.Equal(t, true, security["require_transport_tls"], "unrelated security setting must not be reverted -- this is the exact #1644 failure mode")
	assert.Equal(t, false, security["other_flag"])

	storage, ok := m["storage"].(map[string]any)
	require.True(t, ok, "storage mapping must survive untouched")
	assert.Equal(t, "local", storage["type"])
}

// TestSaveFields_InvalidYAMLLeavesFileUnchanged asserts the "a parse failure is
// not licence to replace the file" invariant the SaveFields doc comment states
// explicitly: against a file that exists but contains invalid YAML, SaveFields
// must return an error AND leave the on-disk bytes byte-for-byte unchanged.
func TestSaveFields_InvalidYAMLLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")

	invalid := "a: [1, 2\n" // unterminated flow sequence -- invalid YAML
	require.NoError(t, os.WriteFile(path, []byte(invalid), 0o600))

	before, err := os.ReadFile(path)
	require.NoError(t, err)

	err = SaveFields(path, map[string]any{"environment": "prod"})
	require.Error(t, err)

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "SaveFields must not modify the file on a parse failure")
}

// TestSaveFields_NestedDotPathOnFreshFile validates that a multi-segment dot
// path (e.g. "storage.remote.base_url") creates the necessary intermediate
// mapping nodes when starting from nothing.
func TestSaveFields_NestedDotPathOnFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")

	require.NoError(t, SaveFields(path, map[string]any{
		"storage.remote.base_url": "https://example.com",
	}))

	m := readYAMLMap(t, path)
	storage, ok := m["storage"].(map[string]any)
	require.True(t, ok)
	remote, ok := storage["remote"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://example.com", remote["base_url"])
}

// TestSaveFields_NestedDotPathPreservesSiblings validates that setting a nested
// field on a mapping that already has OTHER keys at every level doesn't clobber
// any of those siblings -- the multi-level analogue of
// TestSaveFields_PreservesOtherKeys.
func TestSaveFields_NestedDotPathPreservesSiblings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")

	original := "" +
		"storage:\n" +
		"  type: remote\n" +
		"  remote:\n" +
		"    api_key: secret-value\n" +
		"    timeout: 30\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))

	require.NoError(t, SaveFields(path, map[string]any{
		"storage.remote.base_url": "https://example.com",
	}))

	m := readYAMLMap(t, path)
	storage, ok := m["storage"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "remote", storage["type"], "sibling of the intermediate mapping must survive")

	remote, ok := storage["remote"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "secret-value", remote["api_key"], "sibling of the leaf key must survive")
	assert.Equal(t, 30, remote["timeout"], "sibling of the leaf key must survive")
	assert.Equal(t, "https://example.com", remote["base_url"], "the newly-set leaf key must be present")
}

// TestSaveFields_DefaultsPathWhenEmpty mirrors Save's own empty-path handling:
// SaveFields("", fields) must write to appRootDir/keyorix.yaml rather than
// erroring.
func TestSaveFields_DefaultsPathWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, SaveFields("", map[string]any{"environment": "default-path-test"}))

	m := readYAMLMap(t, filepath.Join(dir, "keyorix.yaml"))
	assert.Equal(t, "default-path-test", m["environment"])
}

// TestSaveFields_ReadErrorOtherThanNotExist exercises the "default" branch of
// SaveFields' read-error switch: a read failure that is NOT fs.ErrNotExist
// (here, the securefiles traversal guard rejecting a path that escapes
// appRootDir) must be surfaced as a real error, not silently treated as
// "file doesn't exist yet."
func TestSaveFields_ReadErrorOtherThanNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	err := SaveFields("../escape.yaml", map[string]any{"environment": "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")

	_, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "escape.yaml"))
	assert.True(t, os.IsNotExist(statErr), "SaveFields must not write outside its base directory")
}

// TestSaveFields_RootNotAMapping validates that an existing file whose YAML
// content parses but is not a mapping at its root (e.g. a bare list) is
// rejected with a clear error rather than panicking or silently discarding
// the file's structure.
func TestSaveFields_RootNotAMapping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")
	original := "- one\n- two\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))

	err := SaveFields(path, map[string]any{"environment": "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain a YAML mapping")

	after, rerr := os.ReadFile(path)
	require.NoError(t, rerr)
	assert.Equal(t, original, string(after), "file must be left untouched when the root isn't a mapping")
}

// TestSaveFields_WriteErrorPropagates exercises the write-side error branch:
// when the underlying secure write fails (here, the target directory has no
// write permission), SaveFields must propagate that error rather than
// reporting success.
func TestSaveFields_WriteErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permissions")
	}

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	require.NoError(t, os.Chmod(sub, 0o500)) // read+execute only, no write
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	path := filepath.Join(sub, "keyorix.yaml")
	err := SaveFields(path, map[string]any{"environment": "prod"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write config file")
}

// TestSaveFields_HonorsAbsolutePath mirrors TestSaveHonorsAbsolutePath: an
// absolute path must be written exactly there, rooted at its own directory,
// not mis-joined against appRootDir.
func TestSaveFields_HonorsAbsolutePath(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	elsewhere := t.TempDir()
	absPath := filepath.Join(elsewhere, "keyorix.yaml")

	require.NoError(t, SaveFields(absPath, map[string]any{"environment": "prod-abs-path-test"}))

	m := readYAMLMap(t, absPath)
	assert.Equal(t, "prod-abs-path-test", m["environment"])

	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	assert.Empty(t, entries, "cwd must remain untouched when SaveFields is given an absolute path")
}

// ---------------------------------------------------------------------------
// yamlSetField (unexported, tested directly from within the package)
// ---------------------------------------------------------------------------

// parseMappingRoot parses a small YAML document and returns its root mapping
// node, for driving yamlSetField directly without going through SaveFields'
// file I/O.
func parseMappingRoot(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &doc))
	require.Equal(t, yaml.DocumentNode, doc.Kind)
	require.NotEmpty(t, doc.Content)
	root := doc.Content[0]
	require.Equal(t, yaml.MappingNode, root.Kind)
	return root
}

// decodeNode marshals a yaml.Node back out and decodes it into a generic map,
// so assertions can be made on values rather than node internals.
func decodeNode(t *testing.T, node *yaml.Node) map[string]any {
	t.Helper()
	out, err := yaml.Marshal(node)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, yaml.Unmarshal(out, &m))
	return m
}

// TestYamlSetField_OverwritesExistingScalar validates the simple single-segment
// case: an existing key's value is replaced.
func TestYamlSetField_OverwritesExistingScalar(t *testing.T) {
	root := parseMappingRoot(t, "environment: dev\nother: unchanged\n")

	require.NoError(t, yamlSetField(root, []string{"environment"}, "prod"))

	m := decodeNode(t, root)
	assert.Equal(t, "prod", m["environment"])
	assert.Equal(t, "unchanged", m["other"], "sibling key must be untouched")
}

// TestYamlSetField_AddsNewKey validates that a key not previously present is
// appended rather than requiring pre-existence.
func TestYamlSetField_AddsNewKey(t *testing.T) {
	root := parseMappingRoot(t, "existing: value\n")

	require.NoError(t, yamlSetField(root, []string{"brand_new"}, "hello"))

	m := decodeNode(t, root)
	assert.Equal(t, "value", m["existing"])
	assert.Equal(t, "hello", m["brand_new"])
}

// TestYamlSetField_OverwritesNonMappingIntermediate exercises the documented
// edge case: "overwrites (rather than merges into) any existing non-mapping
// node found along an intermediate segment." Path a.b.c where a.b currently
// holds a scalar (not a mapping) must have that scalar replaced by a mapping
// so c can be set underneath it -- not error out, and not silently no-op.
func TestYamlSetField_OverwritesNonMappingIntermediate(t *testing.T) {
	root := parseMappingRoot(t, "a:\n  b: i-am-a-scalar\n  sibling: keep-me\n")

	require.NoError(t, yamlSetField(root, []string{"a", "b", "c"}, "value"))

	m := decodeNode(t, root)
	a, ok := m["a"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "keep-me", a["sibling"], "sibling of the overwritten intermediate must survive")

	b, ok := a["b"].(map[string]any)
	require.True(t, ok, "b must have been converted from scalar to mapping")
	assert.Equal(t, "value", b["c"])
}

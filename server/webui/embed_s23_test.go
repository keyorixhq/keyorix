package webui_test

import (
	"io"
	"io/fs"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/webui"
)

// TestFS_canReadFileContent verifies that FS() returns an FS whose files are
// actually readable (not just openable).
func TestFS_canReadFileContent(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	file, err := f.Open("index.html")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	content, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.NotEmpty(t, content, "index.html should have non-empty content")
}

// TestFS_statIndexHTML verifies that fs.Stat works on the embedded index.html.
func TestFS_statIndexHTML(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	info, err := fs.Stat(f, "index.html")
	require.NoError(t, err)
	assert.Equal(t, "index.html", info.Name())
	assert.False(t, info.IsDir(), "index.html should not be a directory")
	assert.Greater(t, info.Size(), int64(0), "index.html should have non-zero size")
}

// TestFS_readDirRoot verifies that the root of FS() is traversable via ReadDir.
func TestFS_readDirRoot(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	entries, err := fs.ReadDir(f, ".")
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "root of embedded FS should contain at least index.html")

	found := false
	for _, e := range entries {
		if e.Name() == "index.html" {
			found = true
			break
		}
	}
	assert.True(t, found, "index.html must appear in root ReadDir listing")
}

// TestFS_openNonExistent verifies that opening a non-existent path returns an error.
func TestFS_openNonExistent(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	_, err := f.Open("does-not-exist-xyz.html")
	assert.Error(t, err, "opening a missing path should return an error")
}

// TestFS_noDist prefix verifies that FS() strips the dist/ prefix correctly —
// a file must not be reachable via a dist/-prefixed path.
func TestFS_noDistPrefix(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	_, err := f.Open("dist/index.html")
	assert.Error(t, err, "dist/index.html must not exist — dist/ prefix should be stripped")
}

// TestHTTPFS_openRootSlash verifies that HTTPFS() serves "/" without error.
func TestHTTPFS_openRootSlash(t *testing.T) {
	hfs := webui.HTTPFS()
	require.NotNil(t, hfs)

	f, err := hfs.Open("/")
	require.NoError(t, err)
	require.NotNil(t, f)
	t.Cleanup(func() { _ = f.Close() })
}

// TestHTTPFS_stat verifies that HTTPFS() returns Stat information on index.html.
func TestHTTPFS_stat(t *testing.T) {
	hfs := webui.HTTPFS()
	require.NotNil(t, hfs)

	f, err := hfs.Open("/index.html")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	hf, ok := f.(http.File)
	require.True(t, ok, "HTTPFS().Open should return an http.File")

	info, err := hf.Stat()
	require.NoError(t, err)
	assert.Equal(t, "index.html", info.Name())
	assert.False(t, info.IsDir())
	assert.Greater(t, info.Size(), int64(0))
}

// TestHTTPFS_openMissing verifies that HTTPFS() returns an error for missing files.
func TestHTTPFS_openMissing(t *testing.T) {
	hfs := webui.HTTPFS()
	require.NotNil(t, hfs)

	_, err := hfs.Open("/nonexistent-file.js")
	assert.Error(t, err, "HTTPFS().Open on a missing path should error")
}

// TestHTTPFS_readContent verifies that HTTPFS() allows reading file content.
func TestHTTPFS_readContent(t *testing.T) {
	hfs := webui.HTTPFS()
	require.NotNil(t, hfs)

	f, err := hfs.Open("/index.html")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	content, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.NotEmpty(t, content, "HTTPFS() index.html should have readable non-empty content")
}

// TestHasRealBuild_isStable verifies that HasRealBuild() returns the same value
// across repeated calls (it must be deterministic for a given binary).
func TestHasRealBuild_isStable(t *testing.T) {
	first := webui.HasRealBuild()
	second := webui.HasRealBuild()
	assert.Equal(t, first, second, "HasRealBuild() must return the same value on repeated calls")
}

// TestHasRealBuild_noAssetsInPlaceholderBuild verifies that the committed
// placeholder dist/index.html does NOT include an assets/ directory.
// Real Vite builds embed assets/; the stub does not.
func TestHasRealBuild_noAssetsInPlaceholderBuild(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	_, assetsErr := fs.Stat(f, "assets")
	hasAssets := assetsErr == nil

	// HasRealBuild() must agree with the filesystem state.
	assert.Equal(t, hasAssets, webui.HasRealBuild(),
		"HasRealBuild() should agree with whether assets/ is present in FS()")
}

// TestFS_readFile uses fs.ReadFile helper to confirm round-trip file access.
func TestFS_readFile(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	data, err := fs.ReadFile(f, "index.html")
	require.NoError(t, err)
	assert.NotEmpty(t, data, "fs.ReadFile on index.html should return content")
}

// TestFS_walkDir verifies that fs.WalkDir traverses the embedded FS without error.
func TestFS_walkDir(t *testing.T) {
	f := webui.FS()
	require.NotNil(t, f)

	var paths []string
	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	})
	require.NoError(t, err)
	assert.Contains(t, paths, "index.html", "WalkDir should visit index.html")
}

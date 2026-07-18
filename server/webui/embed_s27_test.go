// Package webui — sprint-27 white-box tests.
//
// The FS() function has a defensive fallback branch ("return distFS") that
// executes when fsSub(distFS, "dist") returns an error. The fsSub variable
// allows tests to inject a failing implementation to exercise this branch.
package webui

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFS_S27_FallbackToDistFS exercises the defensive error branch in FS():
// when fsSub returns an error, FS() must return distFS directly (non-nil).
func TestFS_S27_FallbackToDistFS(t *testing.T) {
	// Inject a failing fsSub to simulate an unexpected fs.Sub error.
	orig := fsSub
	t.Cleanup(func() { fsSub = orig })
	fsSub = func(fsys fs.FS, dir string) (fs.FS, error) {
		return nil, errors.New("injected sub failure")
	}

	got := FS()
	// The fallback must return distFS, which is always non-nil.
	require.NotNil(t, got, "FS() must return non-nil even when fsSub errors")

	// The fallback returns distFS, which still exposes the "dist/" prefix.
	_, err := got.Open("dist/index.html")
	assert.NoError(t, err, "fallback distFS must be openable via dist/-prefixed path")
}

// TestFS_S27_ReturnValueIsNotDistFS confirms that the happy-path branch
// (err == nil) returns the sub-FS, NOT distFS itself. The returned FS must
// not expose the "dist/" prefix.
func TestFS_S27_ReturnValueIsNotDistFS(t *testing.T) {
	got := FS()
	require.NotNil(t, got)

	// If FS() incorrectly returned distFS (the fallback), opening "dist/index.html"
	// would succeed. The happy path should strip the prefix.
	_, err := got.Open("dist/index.html")
	assert.Error(t, err, "FS() must return the sub-FS (prefix stripped), not distFS")
}

// TestFS_S27_SubAssignmentAndFsSubContract verifies that fs.Sub with the
// embedded FS and a valid path always succeeds (confirming the fallback branch
// is unreachable), and that the returned sub-FS is functional.
func TestFS_S27_SubAssignmentAndFsSubContract(t *testing.T) {
	sub, err := fs.Sub(distFS, "dist")
	require.NoError(t, err, "fs.Sub(distFS, \"dist\") must never error — it is always a valid path")
	require.NotNil(t, sub)

	// The sub-FS must have index.html at its root.
	info, err := fs.Stat(sub, "index.html")
	require.NoError(t, err)
	assert.False(t, info.IsDir())
	assert.Greater(t, info.Size(), int64(0))
}

// TestFS_S27_DirectoryIsRoot verifies that FS() returns an FS whose root "."
// is a directory, not a file, and that it contains index.html.
func TestFS_S27_DirectoryIsRoot(t *testing.T) {
	f := FS()
	require.NotNil(t, f)

	info, err := fs.Stat(f, ".")
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "root '.' of FS() should be a directory")
}

// TestHTTPFS_S27_RootDirectoryIsReadable verifies that HTTPFS() root can be
// opened and its Readdir method returns at least one entry.
func TestHTTPFS_S27_RootDirectoryIsReadable(t *testing.T) {
	hfs := HTTPFS()
	require.NotNil(t, hfs)

	f, err := hfs.Open("/")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	hf, ok := f.(http.File)
	require.True(t, ok)

	entries, err := hf.Readdir(-1)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "root directory of HTTPFS() should have at least one entry")

	found := false
	for _, e := range entries {
		if e.Name() == "index.html" {
			found = true
			break
		}
	}
	assert.True(t, found, "index.html must appear in HTTPFS() root Readdir listing")
}

// TestHTTPFS_S27_SeekableFile verifies that files returned by HTTPFS() are
// seekable (implement io.Seeker), which is required for HTTP range requests.
func TestHTTPFS_S27_SeekableFile(t *testing.T) {
	hfs := HTTPFS()
	require.NotNil(t, hfs)

	f, err := hfs.Open("/index.html")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	seeker, ok := f.(io.Seeker)
	require.True(t, ok, "HTTPFS() files must implement io.Seeker for HTTP range support")

	// Read some content, then seek back to the start.
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	require.NoError(t, err)
	assert.Greater(t, n, 0)

	_, err = seeker.Seek(0, io.SeekStart)
	require.NoError(t, err, "Seek to start should not error")

	// Re-read from the start — must match the first read.
	buf2 := make([]byte, 4)
	n2, err := f.Read(buf2)
	require.NoError(t, err)
	assert.Equal(t, n, n2)
	assert.Equal(t, buf[:n], buf2[:n2], "content after seek must match initial read")
}

// TestHTTPFS_S27_StatIsConsistentWithFSFS verifies that HTTPFS() and FS()
// report the same size and name for index.html.
func TestHTTPFS_S27_StatIsConsistentWithFSFS(t *testing.T) {
	// Stat via fs.FS
	fsys := FS()
	fsInfo, err := fs.Stat(fsys, "index.html")
	require.NoError(t, err)

	// Stat via http.FileSystem
	hfs := HTTPFS()
	hf, err := hfs.Open("/index.html")
	require.NoError(t, err)
	t.Cleanup(func() { _ = hf.Close() })

	hfFile, ok := hf.(http.File)
	require.True(t, ok)
	httpInfo, err := hfFile.Stat()
	require.NoError(t, err)

	assert.Equal(t, fsInfo.Name(), httpInfo.Name(), "name must match between FS() and HTTPFS()")
	assert.Equal(t, fsInfo.Size(), httpInfo.Size(), "size must match between FS() and HTTPFS()")
	assert.Equal(t, fsInfo.IsDir(), httpInfo.IsDir(), "IsDir must match between FS() and HTTPFS()")
}

// TestHasRealBuild_S27_FalseOnPlaceholder documents that the committed placeholder
// dist/index.html does not contain an assets/ directory, so HasRealBuild()
// returns false in a normal development checkout.
func TestHasRealBuild_S27_FalseOnPlaceholder(t *testing.T) {
	// This test is intentionally weak — it documents the expected state of the
	// placeholder build without asserting a specific boolean value, because a
	// developer who ran `make build-ui` locally would have a real build.
	result := HasRealBuild()

	// Whatever the result, it must agree with the FS() assets presence.
	fsys := FS()
	_, assetsErr := fs.Stat(fsys, "assets")
	expected := assetsErr == nil

	assert.Equal(t, expected, result,
		"HasRealBuild() must agree with whether 'assets/' exists in FS()")
}

// TestFS_S27_OpenRootDot verifies that FS().Open(".") returns a directory
// entry without error (some FS implementations don't support ".").
func TestFS_S27_OpenRootDot(t *testing.T) {
	f := FS()
	require.NotNil(t, f)

	root, err := f.Open(".")
	require.NoError(t, err, "FS().Open(\".\") must succeed")
	t.Cleanup(func() { _ = root.Close() })
}

// TestFS_S27_MultipleCallsReturnEquivalentFS verifies that FS() is idempotent —
// calling it twice returns FSes that are functionally equivalent.
func TestFS_S27_MultipleCallsReturnEquivalentFS(t *testing.T) {
	fs1 := FS()
	fs2 := FS()
	require.NotNil(t, fs1)
	require.NotNil(t, fs2)

	info1, err := fs.Stat(fs1, "index.html")
	require.NoError(t, err)

	info2, err := fs.Stat(fs2, "index.html")
	require.NoError(t, err)

	assert.Equal(t, info1.Size(), info2.Size(), "repeated FS() calls must return equivalent FSes")
	assert.Equal(t, info1.Name(), info2.Name())
}

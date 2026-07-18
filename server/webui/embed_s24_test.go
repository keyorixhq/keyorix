package webui

// Internal (white-box) tests for the webui package.
// These tests access unexported package variables to exercise scenarios that
// are unreachable through the public API under normal operation.

import (
	"embed"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFS_withEmptyDistFS verifies that FS() returns a non-nil, usable fs.FS
// even when the underlying distFS contains no files. In this scenario,
// fs.Sub(distFS, "dist") succeeds (returning an empty sub-FS) and FS() returns
// the empty sub-FS rather than panicking or returning nil.
func TestFS_withEmptyDistFS(t *testing.T) {
	// Save and restore the real embedded FS around this test.
	realFS := distFS
	t.Cleanup(func() { distFS = realFS })

	// Replace distFS with a zero-value embed.FS (contains no embedded files).
	// fs.Sub on an empty embed.FS with path "dist" still succeeds (the path is
	// syntactically valid), returning an empty sub-FS.
	distFS = embed.FS{}

	got := FS()
	// FS() must never return nil regardless of distFS contents.
	require.NotNil(t, got, "FS() must never return nil")

	// The returned FS is an empty sub-FS: opening any file should fail.
	_, err := got.Open("index.html")
	assert.Error(t, err, "empty distFS should yield an FS that cannot open index.html")
}

// TestFS_withEmptyDistFS_readDir verifies that fs.ReadDir on the result of
// FS() when distFS is empty returns an error or an empty listing — in either
// case, FS() itself must still return a non-nil result without panicking.
func TestFS_withEmptyDistFS_readDir(t *testing.T) {
	realFS := distFS
	t.Cleanup(func() { distFS = realFS })

	distFS = embed.FS{}

	got := FS()
	require.NotNil(t, got)

	// fs.ReadDir on an empty sub-FS may error (the "dist" subdir doesn't exist
	// in the zero-value FS). Either outcome (empty list or error) is acceptable;
	// the invariant is that FS() itself did not panic and returned non-nil.
	entries, err := fs.ReadDir(got, ".")
	if err == nil {
		assert.Empty(t, entries, "empty distFS should have no directory entries")
	}
	// If err != nil that's also acceptable — the empty FS has no "." to list.
}

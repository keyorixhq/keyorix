package egressguard

// #4370: the inventory scan must depend on the committed source, not on what
// else happens to sit in the work tree. Session scratch space (tmp/, .scratch/,
// the redproof exports, a private GOPATH) is skipped by name at the repository
// root, and a half-written or foreign .go file in there must neither add a site
// nor fail the walk with a parse error. These tests pin that, and pin the other
// direction: a file outside the skip list, in any directory that merely shares a
// skipped name below the root, is still scanned.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTree(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}

func TestEgressScanTree_IgnoresStrayFilesInTheDocumentedSkipList(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "go.mod", "module example.test/m\n")
	writeTree(t, root, "srv/ok.go", "package srv\n")

	const unparseable = "package x\nfunc (" // a file another process is still writing
	for _, dir := range []string{
		"tmp", ".scratch", ".claude", "web", ".git", "node_modules", "vendor", "testdata",
		".redproof-4242", ".gopath", ".gopath-session", "srv/testdata", "srv/node_modules",
	} {
		writeTree(t, root, dir+"/stray.go", fixtureHTTP)
		writeTree(t, root, dir+"/partial.go", unparseable)
	}

	sites, err := scanTree(root)
	require.NoError(t, err, "a stray file in a skipped directory must not fail the walk")
	assert.Empty(t, sites, "a stray file in a skipped directory must not be a site")
}

func TestEgressScanTree_StillScansTheRealTreeAndSameNamedDirsBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "go.mod", "module example.test/m\n")
	// tmp/, web/ and .scratch/ are skipped at the root only: internal/.../web is Go.
	writeTree(t, root, "internal/api/web/client.go", fixtureHTTP)
	writeTree(t, root, "internal/api/tmp/client.go", fixtureHTTP)
	writeTree(t, root, "srv/real.go", fixtureHTTP)

	sites, err := scanTree(root)
	require.NoError(t, err)
	files := map[string]bool{}
	for _, s := range sites {
		files[s.File] = true
	}
	assert.Equal(t, map[string]bool{
		"internal/api/web/client.go": true,
		"internal/api/tmp/client.go": true,
		"srv/real.go":                true,
	}, files)

	// A parse error outside the skip list is reported, not swallowed.
	writeTree(t, root, "srv/broken.go", "package srv\nfunc (")
	_, err = scanTree(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "srv/broken.go")
}

package webui_test

import (
	"io/fs"
	"testing"

	"github.com/keyorixhq/keyorix/server/webui"
)

func TestFS_returnsReadableFS(t *testing.T) {
	f := webui.FS()
	if f == nil {
		t.Fatal("FS() returned nil")
	}
	// The committed dist/index.html placeholder must always be readable.
	file, err := f.Open("index.html")
	if err != nil {
		t.Fatalf("FS().Open(index.html): %v", err)
	}
	if err := file.Close(); err != nil {
		t.Errorf("file.Close(): %v", err)
	}
}

func TestFS_returnsSubFS(t *testing.T) {
	f := webui.FS()
	// fs.Sub strips the "dist/" prefix, so "dist/index.html" must NOT exist.
	if _, err := f.Open("dist/index.html"); err == nil {
		t.Error("FS() did not strip the dist/ prefix — got a sub-FS that still has dist/ in path")
	}
}

func TestHTTPFS_implementsHTTPFileSystem(t *testing.T) {
	hfs := webui.HTTPFS()
	if hfs == nil {
		t.Fatal("HTTPFS() returned nil")
	}
	f, err := hfs.Open("/index.html")
	if err != nil {
		t.Fatalf("HTTPFS().Open(/index.html): %v", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("f.Close(): %v", err)
	}
}

func TestHasRealBuild_matchesAssetsPresence(t *testing.T) {
	// HasRealBuild uses fs.Stat(FS(), "assets") internally. This test verifies
	// the two agree — so the function correctly reflects whether a real Vite
	// build was embedded regardless of local build state (locally-built assets
	// are gitignored; only index.html is committed).
	f := webui.FS()
	_, assetsErr := fs.Stat(f, "assets")
	want := assetsErr == nil
	if got := webui.HasRealBuild(); got != want {
		t.Errorf("HasRealBuild() = %v but assets/ presence = %v — they must agree", got, want)
	}
}

func TestHasRealBuild_distIndexAlwaysPresent(t *testing.T) {
	// The committed placeholder index.html must always be present so the
	// server binary is valid even without a UI build.
	f := webui.FS()
	_, err := fs.Stat(f, "index.html")
	if err != nil {
		t.Fatalf("placeholder index.html missing from embedded dist: %v", err)
	}
}

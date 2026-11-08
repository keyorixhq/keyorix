package wvec

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// TestDirIsTheRepoVectorDirUnderTrimpath: without WYCHEPROOF_DIR the vectors
// live in internal/wycheproof/testdata/vectors (where fetch.sh puts them by
// default). Dir must find that directory however the test binary was built;
// under -trimpath a runtime.Caller file name is module-relative and is not a
// usable path, so this fails there if Dir derives the path from it.
func TestDirIsTheRepoVectorDirUnderTrimpath(t *testing.T) {
	t.Setenv("WYCHEPROOF_DIR", "")
	want := filepath.Join(srcpath.RepoRoot(), "internal", "wycheproof", "testdata", "vectors")
	if got := Dir(); got != want {
		t.Fatalf("Dir() = %q, want %q", got, want)
	}
}

func TestDirHonoursOverride(t *testing.T) {
	t.Setenv("WYCHEPROOF_DIR", "/some/where")
	if got := Dir(); got != "/some/where" {
		t.Fatalf("Dir() = %q, want the WYCHEPROOF_DIR value", got)
	}
}

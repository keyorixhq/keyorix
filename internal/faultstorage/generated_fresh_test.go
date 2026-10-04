package faultstorage

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// staleMsg is the fix-it instruction printed when the committed generated file
// drifts from the generator's output. Kept in one place so the README and the
// failure say the same thing.
const staleMsg = "faulty_storage_generated.go is stale — run `go generate ./internal/faultstorage/` " +
	"(on a merge conflict: take main's version of the file, then regenerate)"

// TestFaultyStorageGenerated_IsFresh asserts the committed
// faulty_storage_generated.go is byte-for-byte what ./gen produces from the
// current storage.Storage interface source.
//
// What this covers that `go build` does not: the build already fails when the
// interface gains or loses a method the wrapper doesn't implement (the wrapper
// does not embed storage.Storage — see gen/main.go's doc). It does NOT fail when
// the generated file was hand-edited in a way that still compiles (a wrapper
// body changed, a fault check removed from one method), nor when a merge
// resolution combined two PRs' generated files into something that compiles but
// is not what the generator emits. This test catches both.
//
// What it does not cover: the hand-written WithTransaction wrapper in
// faultstorage.go (not generated), and changes to the generator's own output
// across Go toolchain versions (go/format) — those show up here as a diff, which
// is the intended signal: regenerate with the pinned toolchain.
//
// It runs the real generator via `go run ./gen -o <tmp>` rather than in-process,
// because the generator is a main package and so cannot be imported.
func TestFaultyStorageGenerated_IsFresh(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}

	committed, err := os.ReadFile("faulty_storage_generated.go")
	if err != nil {
		t.Fatalf("reading committed generated file: %v", err)
	}

	out := filepath.Join(t.TempDir(), "faulty_storage_generated.go")
	cmd := exec.Command(goBin, "run", "./gen", "-o", out)
	cmd.Dir = "." // the package directory; gen locates the module root via go.mod
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running the generator failed: %v\n%s\n%s", err, b, staleMsg)
	}
	fresh, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading generator output: %v", err)
	}

	if !bytes.Equal(committed, fresh) {
		t.Fatalf("%s\nfirst difference: %s", staleMsg, firstDiff(committed, fresh))
	}
}

// firstDiff reports the first differing line between committed and fresh, so
// the failure points at the method that drifted instead of only saying "differs".
func firstDiff(committed, fresh []byte) string {
	a := bytes.Split(committed, []byte("\n"))
	b := bytes.Split(fresh, []byte("\n"))
	for i := 0; i < len(a) || i < len(b); i++ {
		var la, lb []byte
		if i < len(a) {
			la = a[i]
		}
		if i < len(b) {
			lb = b[i]
		}
		if !bytes.Equal(la, lb) || i >= len(a) || i >= len(b) {
			return fmt.Sprintf("line %d\n  committed: %s\n  generated: %s", i+1, la, lb)
		}
	}
	return "(none found; lengths differ)"
}

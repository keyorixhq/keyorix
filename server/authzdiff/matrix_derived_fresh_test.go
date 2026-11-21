package authzdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMatrixIsCurrent: matrix.json and MATRIX.md are exactly what
// devtools/authzmatrix derives from the code as it is now. TestMatrixKeysAreCurrent
// checks only the key set, so the derived columns (core entry points, guard
// reach, core_refusal class) used to go stale unnoticed: a stale core_refusal of
// "none" made TestCoreRefusesSuspendedActor skip an operation whose core had since
// gained a typed refusal, and two such operations (RequestProjectAccess,
// GrantSecretACL) let a suspended account through core unnoticed. coreEnforced,
// and with it every core-leg guard, is derived from this file.
//
// On failure, regenerate and commit both files:
//
//	go run ./devtools/authzmatrix -md server/authzdiff/MATRIX.md -json server/authzdiff/matrix.json
//
// Not run with -short (it type-checks the module, about 15 s).
func TestMatrixIsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("derives the matrix from the whole module; skipped with -short")
	}
	dir := t.TempDir()
	files := map[string]string{
		"matrix.json": filepath.Join(dir, "matrix.json"),
		"MATRIX.md":   filepath.Join(dir, "MATRIX.md"),
	}
	cmd := exec.Command("go", "run", "./devtools/authzmatrix", "-md", files["MATRIX.md"], "-json", files["matrix.json"])
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("regenerating the matrix: %v\n%s", err, out)
	}
	for name, generated := range files {
		got, err := os.ReadFile(generated)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) == string(want) {
			continue
		}
		t.Errorf("%s is stale; regenerate it (see the test comment). First differing lines:\n%s", name, firstDiffLines(string(want), string(got), 6))
	}
}

// firstDiffLines lists up to max lines that differ between committed and
// generated, line by line (both files are line-stable across a regeneration).
func firstDiffLines(committed, generated string, max int) string {
	a, b := strings.Split(committed, "\n"), strings.Split(generated, "\n")
	var out []string
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			out = append(out, "  committed: "+x, "  generated: "+y)
			if len(out) >= 2*max {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFix_ResolvesAgainstPathNotCWD reproduces the exact scenario from
// HARDENING-BACKLOG #352: `findAndPlanFix` records plan.File relative to
// --path, but applyFix used to resolve that same relative path against the
// process's CWD instead. Running `keyorix secret fix --path <elsewhere>`
// from a directory that happens to contain a file at the same relative path
// as the real target must:
//   - actually fix the real target under --path, and
//   - leave the CWD-relative decoy file (which merely shares that relative
//     path) completely untouched.
func TestFix_ResolvesAgainstPathNotCWD(t *testing.T) {
	root := t.TempDir()

	projectDir := filepath.Join(root, "project")
	decoyDir := filepath.Join(root, "decoy")

	realFile := filepath.Join(projectDir, "sub", "config.py")
	decoyFile := filepath.Join(decoyDir, "sub", "config.py")

	if err := os.MkdirAll(filepath.Dir(realFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(decoyFile), 0o755); err != nil {
		t.Fatal(err)
	}

	realContent := "DB_PASSWORD = \"supersecretvalue123\"\n"
	decoyContent := "# unrelated file at the same relative path — must not be touched\nDB_PASSWORD = \"supersecretvalue123\"\n"

	if err := os.WriteFile(realFile, []byte(realContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoyFile, []byte(decoyContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Run from decoyDir with --path pointing at ../project, exactly as in
	// the empirically-reproduced finding (invoked from an unrelated `decoy/`
	// directory that happens to share a same-relative-path file).
	t.Chdir(decoyDir)

	origPath, origDryRun, origInteractive, origEnvFile := fixPath, fixDryRun, fixInteractive, fixEnvFile
	t.Cleanup(func() {
		fixPath, fixDryRun, fixInteractive, fixEnvFile = origPath, origDryRun, origInteractive, origEnvFile
	})

	fixPath = "../project"
	fixDryRun = false
	fixInteractive = false
	fixEnvFile = ".env"

	if err := runFix(fixCmd, []string{"DB_PASSWORD"}); err != nil {
		t.Fatalf("runFix returned error: %v", err)
	}

	// The decoy file (which would only be touched if resolution incorrectly
	// used the CWD instead of --path) must be completely untouched.
	gotDecoy, err := os.ReadFile(decoyFile)
	if err != nil {
		t.Fatalf("decoy file vanished: %v", err)
	}
	if string(gotDecoy) != decoyContent {
		t.Fatalf("decoy file (unrelated to --path) was modified; got %q, want unchanged %q", gotDecoy, decoyContent)
	}

	// The real target file under --path must actually have been fixed.
	gotReal, err := os.ReadFile(realFile)
	if err != nil {
		t.Fatalf("real target file vanished: %v", err)
	}
	if strings.Contains(string(gotReal), "supersecretvalue123") {
		t.Fatalf("real target file still contains the hardcoded secret (false remediation): %q", gotReal)
	}
	if !strings.Contains(string(gotReal), `os.getenv("DB_PASSWORD")`) {
		t.Fatalf("real target file was not fixed as expected: %q", gotReal)
	}
}

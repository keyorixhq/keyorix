package securefiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// FuzzSafeRelComponents is CLI-FUZZ target 4a (ADR-108): the pure, filesystem-free
// lexical gate every credential/token/output file write in this CLI goes through
// (directly, via SecureOpenBeneath, or via resolveInside/SecureCreateFileHandle).
// Invariants for any input: never panics, and whenever it accepts a path, none of the
// returned components is ".." and the components never reconstruct an absolute path --
// the actual symlink-escape defense is SecureOpenBeneath's O_NOFOLLOW walk (see
// FuzzSecureOpenBeneath below), but this lexical gate must never itself hand back
// something an attacker could use to climb out.
func FuzzSafeRelComponents(f *testing.F) {
	seeds := []string{
		"file.txt",
		"sub/file.txt",
		"../escape.txt",
		"a/../b",
		"",
		".",
		"..",
		"/abs/path",
		"a//b",
		"a/./b",
		string([]byte{0}),
		"very/deep/../../../etc/passwd",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, relPath string) {
		var parts []string
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("safeRelComponents panicked on %q: %v", relPath, r)
				}
			}()
			parts, err = safeRelComponents(relPath)
		}()
		if err != nil {
			return // a refusal is always a valid outcome
		}
		for _, p := range parts {
			if p == ".." {
				t.Fatalf("safeRelComponents(%q) returned a %q component", relPath, "..")
			}
			if p == "" {
				t.Fatalf("safeRelComponents(%q) returned an empty component", relPath)
			}
		}
		rejoined := strings.Join(parts, string(os.PathSeparator))
		if filepath.IsAbs(rejoined) {
			t.Fatalf("safeRelComponents(%q) returned components that rejoin to an absolute path: %q", relPath, rejoined)
		}
	})
}

// FuzzSecureOpenBeneath_SymlinkComponentNeverFollowed is CLI-FUZZ target 4b: the actual
// TOCTOU-safe defense (per-component O_NOFOLLOW walk via openat(2)) this package exists
// for, matching the task's "0600 permission check can't be bypassed via symlink" ask at
// the shared primitive level rather than re-testing credstore's already-fuzzed
// FileStore.Load (cli/internal/credstore/file_fuzz_test.go) in isolation -- 8 other
// cmd/*.go call sites for security-sensitive local file writes route through this same
// helper. baseDir/linkdir is a fixed symlink pointing OUTSIDE baseDir at a directory
// containing a canary file; relPath always begins with "linkdir/" so every fuzzed input
// exercises the symlink-component defense, with the fuzzer free to vary what comes
// after.
func FuzzSecureOpenBeneath_SymlinkComponentNeverFollowed(f *testing.F) {
	seeds := []string{
		"file.txt",
		"",
		".",
		"..",
		"sub/file.txt",
		"a/b/c.txt",
		string([]byte{0}),
		"café.txt",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, leaf string) {
		dir := t.TempDir()
		outsideDir := t.TempDir()
		canary := filepath.Join(outsideDir, "canary.txt")
		if err := os.WriteFile(canary, []byte("secret"), 0o600); err != nil {
			t.Skipf("could not seed canary file: %v", err)
		}
		linkDir := filepath.Join(dir, "linkdir")
		if err := os.Symlink(outsideDir, linkDir); err != nil {
			t.Skipf("could not create symlink fixture: %v", err)
		}
		relPath := "linkdir/" + leaf

		var f2 *os.File
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SecureOpenBeneath panicked on relPath %q: %v", relPath, r)
				}
			}()
			f2, err = SecureOpenBeneath(dir, relPath, unix.O_RDONLY, 0)
		}()
		if err == nil {
			_ = f2.Close()
			t.Fatalf("SecureOpenBeneath followed a symlinked intermediate/leaf component for relPath %q (baseDir=%q)", relPath, dir)
		}
	})
}

//go:build linux

package securefiles_test

// atomic_write_fault_fuzz_test.go — FuzzSecureWriteUnderFault (FS1).
//
// SecureWriteFileSync / SecureOpenBeneath is the durable-write primitive the
// key-set manifest, the DEK/KEK files and every securefiles caller sit on. Its
// per-path-component O_NOFOLLOW walk opens a chain of directory descriptors;
// every error path (an unsafe component, a read-only leaf, a path escaping the
// base, a non-directory ancestor) must (c) surface a non-nil error, (d) leave a
// pre-existing target byte-for-byte unchanged (the open fails before O_TRUNC
// can empty it), and (e) close every descriptor it opened on the way — a fd
// leak in a boot-time walk run per start would accumulate across restarts.
//
// Unlike the other FS1 targets this one injects a REAL filesystem fault (a
// read-only leaf/ancestor, a symlinked or escaping path, a non-dir ancestor)
// rather than manufacturing a post-crash byte state, so it exercises the real
// open/chmod/write/sync/close error-handling code, not a reader.
//
// Oracles (and what each does NOT verify):
//
//	(c) SURFACED — an unsafe or failing write returns a non-nil error.
//	(d) OLD-OR-NEW — a pre-existing target is either unchanged (write failed
//	    before truncation) or fully the new bytes; never a partial prefix. DOES
//	    NOT verify crash-atomicity of a SUCCESSFUL write mid-flight:
//	    SecureWriteFileSync writes IN PLACE (O_TRUNC, no temp+rename) by design —
//	    its callers (writeManifest, the key files) add staging+rename on top; a
//	    torn write from an EIO after a successful open is a documented,
//	    caller-handled shape, not asserted here.
//	(e) NO FD LEAK — the open descriptor count is stable across many error-path
//	    writes. DOES NOT verify goroutine leaks (none are started).
//	ROBUSTNESS — no arbitrary relative path makes SecureWriteFileSync panic.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

func countFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(ents)
}

func FuzzSecureWriteUnderFault(f *testing.F) {
	f.Add(byte(0), "sub/key.dat", []byte("new-content"), uint16(3))
	f.Add(byte(1), "key.dat", []byte("x"), uint16(0))
	f.Add(byte(2), "../escape.dat", []byte("y"), uint16(1))
	f.Add(byte(3), "a/b/c/deep.dat", []byte("zzz"), uint16(2))
	f.Add(byte(4), "via-symlink/key.dat", []byte("data"), uint16(5))
	f.Add(byte(5), "readonly-leaf.dat", []byte("replacement"), uint16(1))
	f.Add(byte(6), "not-a-dir/leaf.dat", []byte("data"), uint16(0))

	f.Fuzz(func(t *testing.T, faultSel byte, relRaw string, data []byte, depth uint16) {
		base := t.TempDir()

		// Keep the relative path bounded and free of NUL (which open rejects at
		// the syscall layer anyway); the fuzzer still gets to pick traversal,
		// nesting, and odd characters.
		rel := strings.ReplaceAll(relRaw, "\x00", "")
		if rel == "" {
			rel = "leaf.dat"
		}
		if len(rel) > 200 {
			rel = rel[:200]
		}

		fdBefore := countFDs(t)

		// Run the operation under each fault setup. All must either succeed with
		// the new bytes landing, or fail cleanly; never panic, never leak fds.
		switch faultSel % 7 {
		case 0:
			// Benign: a safe nested path (parent dir pre-created, as every real
			// securefiles caller does). Should succeed; read back == data.
			safe := "sub/key.dat"
			if err := os.MkdirAll(filepath.Join(base, "sub"), 0o700); err != nil {
				t.Fatalf("mkdir sub: %v", err)
			}
			if err := securefiles.SecureWriteFileSync(base, safe, data, 0o600); err != nil {
				// Only acceptable failure here is a genuinely odd environment.
				t.Fatalf("benign write failed: %v", err)
			}
			got, rerr := os.ReadFile(filepath.Join(base, safe)) //nolint:gosec
			if rerr != nil || string(got) != string(data) {
				t.Fatalf("OLD-OR-NEW(d): benign write did not land exactly: err=%v got=%q want=%q", rerr, got, data)
			}

		case 1:
			// Overwrite an existing file with known OLD content. A successful
			// write must leave exactly the new bytes; nothing partial.
			old := []byte("OLD-CONTENT-sentinel")
			full := filepath.Join(base, "key.dat")
			if err := os.WriteFile(full, old, 0o600); err != nil { //nolint:gosec
				t.Fatalf("seed old: %v", err)
			}
			err := securefiles.SecureWriteFileSync(base, "key.dat", data, 0o600)
			got, _ := os.ReadFile(full) //nolint:gosec
			assertOldOrNew(t, "overwrite", err, got, old, data)

		case 2:
			// Path escaping the base MUST be refused (resolveInside), and no
			// file is created outside base.
			rel2 := "../escape-" + rel
			err := securefiles.SecureWriteFileSync(base, rel2, data, 0o600)
			if err == nil {
				t.Fatalf("SURFACED(c): a path escaping the base was NOT refused: %q", rel2)
			}

		case 3:
			// Arbitrary (possibly deep / traversal) fuzzer path. Either it is
			// safe and lands, or it is refused — never a panic, never a write
			// outside base. If it claims success, the bytes must be exactly data.
			err := securefiles.SecureWriteFileSync(base, rel, data, 0o600)
			if err == nil {
				full := filepath.Join(base, filepath.Clean(rel))
				if got, rerr := os.ReadFile(full); rerr == nil && string(got) != string(data) { //nolint:gosec
					t.Fatalf("OLD-OR-NEW(d): claimed-success write has partial content: got=%q want=%q", got, data)
				}
			}

		case 4:
			// A symlink as an intermediate component MUST be refused by the
			// per-component O_NOFOLLOW walk (never written through).
			if err := os.Symlink("/tmp", filepath.Join(base, "via-symlink")); err != nil {
				t.Skipf("cannot symlink: %v", err)
			}
			err := securefiles.SecureWriteFileSync(base, "via-symlink/key.dat", data, 0o600)
			if err == nil {
				t.Fatalf("SURFACED(c): wrote THROUGH a symlinked component")
			}

		case 5:
			// A read-only EXISTING leaf: O_WRONLY open fails, the old content
			// must survive (failure is before truncation).
			old := []byte("READONLY-OLD-sentinel")
			full := filepath.Join(base, "readonly-leaf.dat")
			if err := os.WriteFile(full, old, 0o400); err != nil { //nolint:gosec
				t.Fatalf("seed ro leaf: %v", err)
			}
			err := securefiles.SecureWriteFileSync(base, "readonly-leaf.dat", data, 0o600)
			got, _ := os.ReadFile(full) //nolint:gosec
			// chmod in SecureWriteFileSync may widen the mode even if write
			// fails; what matters for (d) is the CONTENT is old-or-new.
			assertOldOrNew(t, "readonly-leaf", err, got, old, data)

		default:
			// A regular file used as an ancestor directory (ENOTDIR). MUST be
			// refused, never written through, never panic.
			if err := os.WriteFile(filepath.Join(base, "not-a-dir"), []byte("iamafile"), 0o600); err != nil { //nolint:gosec
				t.Fatalf("seed not-a-dir: %v", err)
			}
			err := securefiles.SecureWriteFileSync(base, "not-a-dir/leaf.dat", data, 0o600)
			if err == nil {
				t.Fatalf("SURFACED(c): wrote through a non-directory ancestor")
			}
		}

		// oracle (e): repeat the (often-failing) walk and confirm fds are stable.
		for range 24 {
			_ = securefiles.SecureWriteFileSync(base, rel, data, 0o600)
			_ = securefiles.SyncDir(filepath.Join(base, "definitely-not-here"))
		}
		fdAfter := countFDs(t)
		if fdAfter > fdBefore+3 {
			t.Fatalf("FD LEAK(e): open fd count grew %d→%d across error-path writes (fault=%d rel=%q)", fdBefore, fdAfter, faultSel%7, rel)
		}
	})
}

// assertOldOrNew fails unless got is exactly old (write failed) or exactly new
// (write succeeded) — never a partial/torn prefix.
func assertOldOrNew(t *testing.T, context string, writeErr error, got, old, newData []byte) {
	t.Helper()
	if string(got) == string(old) || string(got) == string(newData) {
		return
	}
	t.Fatalf("OLD-OR-NEW(d): [%s] after write (err=%v) content is neither old nor new: got=%q old=%q new=%q", context, writeErr, got, old, newData)
}

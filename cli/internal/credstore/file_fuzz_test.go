package credstore

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzCredstoreLoad fuzzes FileStore.Load against arbitrary file contents and
// arbitrary Unix permission bits on a real temp file, plus a symlink pointing
// at that same file. file.go's own doc comments document the two refusal
// gates this oracle re-derives independently:
//
//  1. Load never panics on any byte content or permission value.
//  2. Whenever perm&0o077 != 0 (any group or other bit set -- the EXACT
//     threshold file.go's Load enforces, matching this package's own doc
//     comment "permissions wider than 0600"), Load must refuse (return a
//     non-nil error), regardless of the file's actual content.
//  3. A symlink at the final path component must always be refused
//     (info.Mode()&os.ModeSymlink check in Load), independent of the
//     permissions on -- or content of -- the file it points to.
//  4. Whenever Load returns a non-nil error, the returned Credentials is
//     always the zero value: no token or server URL may leak through a
//     refused or failed read.
func FuzzCredstoreLoad(f *testing.F) {
	valid := []byte("server_url: https://example.test\ntoken: tok-abc\n")

	f.Add(valid, uint32(0o600))                             // valid file, narrow (correct) permissions
	f.Add(valid, uint32(0o644))                             // world-readable
	f.Add(valid, uint32(0o640))                             // group-readable
	f.Add(valid, uint32(0o666))                             // world-writable
	f.Add(valid, uint32(0o777))                             // fully open
	f.Add([]byte{}, uint32(0o600))                          // empty file, narrow permissions
	f.Add([]byte("not: [valid yaml"), uint32(0o600))        // garbage/malformed YAML, narrow permissions
	f.Add([]byte("\x00\x01\xff\xfe binary"), uint32(0o600)) // binary garbage, narrow permissions

	f.Fuzz(func(t *testing.T, data []byte, modeBits uint32) {
		dir := t.TempDir()
		realPath := filepath.Join(dir, "credentials.yaml")
		perm := os.FileMode(modeBits & 0o777)

		if err := os.WriteFile(realPath, data, 0o600); err != nil {
			t.Skipf("could not write fixture file: %v", err)
		}
		if err := os.Chmod(realPath, perm); err != nil {
			t.Skipf("could not chmod fixture file to %#o: %v", perm, err)
		}

		s := NewFileStore(realPath)
		creds, err := s.Load() // must never panic

		if err != nil && creds != (Credentials{}) {
			t.Fatalf("Load returned an error (%v) but a non-zero Credentials value: %+v (perm=%#o)", err, creds, perm)
		}
		if perm&0o077 != 0 && err == nil {
			t.Fatalf("Load succeeded on a file with permissions %#o (wider than 0600), want a refusal", perm)
		}

		// Symlink case: a link at the final path component pointing at the same
		// real file, whatever its permissions. Load must refuse through the
		// link even when the target's own permissions are narrow and its
		// content is valid.
		linkPath := filepath.Join(dir, "credentials-link.yaml")
		if err := os.Symlink(realPath, linkPath); err != nil {
			t.Skipf("could not create symlink fixture: %v", err)
		}
		linkStore := NewFileStore(linkPath)
		linkCreds, linkErr := linkStore.Load() // must never panic

		if linkErr == nil {
			t.Fatalf("Load succeeded through a symlink (target perm=%#o), want a refusal", perm)
		}
		if linkCreds != (Credentials{}) {
			t.Fatalf("Load through a symlink returned an error (%v) but a non-zero Credentials value: %+v", linkErr, linkCreds)
		}
	})
}

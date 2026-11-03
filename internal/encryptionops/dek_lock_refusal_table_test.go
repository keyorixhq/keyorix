package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption"
)

// MSG-ACCURACY-1 item 1 (#3742 audit): every key-writer lock refusal must say what is
// actually wrong. Only real lock contention may tell the operator to stop a server.
func TestOpenKeyWriter_LockRefusalMessageMatchesTheCause(t *testing.T) {
	const serverHint = "stop the running server"

	cases := []struct {
		name       string
		setup      func(t *testing.T, base string) (cleanup func())
		wantAll    []string
		wantAbsent []string
	}{
		{
			name: "ENOENT key directory",
			setup: func(t *testing.T, base string) func() {
				return func() {}
			},
			wantAll:    []string{"key directory " + "%BASE%/keys" + " does not exist", "keyorix-server admin init"},
			wantAbsent: []string{serverHint, "live server"},
		},
		{
			name: "EACCES key directory",
			setup: func(t *testing.T, base string) func() {
				if os.Geteuid() == 0 {
					t.Skip("root bypasses directory permissions")
				}
				dir := filepath.Join(base, "keys")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o000); err != nil {
					t.Fatal(err)
				}
				return func() { _ = os.Chmod(dir, 0o700) }
			},
			wantAll:    []string{"permission denied"},
			wantAbsent: []string{serverHint, "live server", "does not exist"},
		},
		{
			name: "lock contention",
			setup: func(t *testing.T, base string) func() {
				dir := filepath.Join(base, "keys")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				cfg := testConfig(true)
				cfg.Storage.Encryption.DEKPath = "keys/dek.key"
				cfg.Storage.Encryption.SaltPath = "keys/kek.salt"
				holder := encryption.NewService(&cfg.Storage.Encryption, base)
				if err := holder.AcquireExclusiveKeyLock(); err != nil {
					t.Fatalf("holder lock: %v", err)
				}
				return holder.Shutdown
			},
			wantAll:    []string{serverHint},
			wantAbsent: []string{"does not exist"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			cleanup := tc.setup(t, base)
			defer cleanup()

			cfg := testConfig(true)
			cfg.Storage.Encryption.DEKPath = "keys/dek.key"
			cfg.Storage.Encryption.SaltPath = "keys/kek.salt"

			_, _, err := openKeyWriter(cfg, base, "pw-for-the-test-0123456789", "rotate")
			if err == nil {
				t.Fatal("openKeyWriter must refuse")
			}
			msg := err.Error()
			for _, w := range tc.wantAll {
				w = strings.ReplaceAll(w, "%BASE%", base)
				if !strings.Contains(msg, w) {
					t.Errorf("error %q must contain %q", msg, w)
				}
			}
			for _, a := range tc.wantAbsent {
				if strings.Contains(msg, a) {
					t.Errorf("error %q must not contain %q", msg, a)
				}
			}
		})
	}
}

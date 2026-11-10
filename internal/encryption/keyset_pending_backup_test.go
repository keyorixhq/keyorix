//go:build !windows

package encryption

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// TestRotateKEKCrashPoints_PendingFilesBackupRefusesOn crashes the REAL
// rotate-kek at every checkpoint and records which staging files exist, the
// ones `admin backup` refuses on (#4058), before and after boot recovery. It
// is the evidence that rotate-kek has the DEK rotation's exposure, and that
// boot does not always clear it: a rotation abandoned before it changed the
// active keys leaves kek.salt.pending for good.
func TestRotateKEKCrashPoints_PendingFilesBackupRefusesOn(t *testing.T) {
	const salt, dek = "kek.salt.pending", "dek.key.pending"
	cases := []struct {
		label     string
		crashed   []string
		afterBoot []string
	}{
		{"kek:after-write-salt-pending", []string{salt}, []string{salt}},
		{"kek:after-write-dek-pending", []string{salt, dek}, []string{salt}},
		{"kek:after-stage-manifest", []string{salt, dek}, []string{salt}},
		{"kek:after-rename-dek", []string{salt}, nil},
		{"kek:after-rename-salt", nil, nil},
		{"kek:after-commit-manifest", nil, nil},
	}
	const oldPass, newPass = "old-passphrase-1", "new-passphrase-2"
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			dir := t.TempDir()
			enc := passwordEncConfig()
			seed := newPasswordService(t, dir, oldPass)
			runRotationWithCrash(seed.keyManager, oldPass, newPass, c.label)

			pendingNames := func() []string {
				found, err := keyfiles.PendingRotationFiles(enc, dir)
				if err != nil {
					t.Fatalf("PendingRotationFiles: %v", err)
				}
				var names []string
				for _, f := range found {
					names = append(names, filepath.Base(f.Path))
				}
				return names
			}
			if got := pendingNames(); !slices.Equal(got, c.crashed) {
				t.Fatalf("after a crash at %s: staging files %v, want %v", c.label, got, c.crashed)
			}
			specs, err := keyfiles.Registry(enc, dir)
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			if want := 2 + len(c.crashed); len(specs) != want {
				t.Fatalf("after a crash at %s: Registry lists %d files, want %d (what a backup would archive)", c.label, len(specs), want)
			}

			boot := NewService(enc, dir)
			if err := boot.AcquireExclusiveKeyLock(); err != nil {
				t.Fatalf("key lock: %v", err)
			}
			t.Cleanup(boot.Shutdown)
			if err := boot.ReconcileKeySet(); err != nil {
				t.Fatalf("ReconcileKeySet: %v", err)
			}
			if err := boot.RecoverInterruptedRotation(nil); err != nil {
				t.Fatalf("RecoverInterruptedRotation: %v", err)
			}
			if got := pendingNames(); !slices.Equal(got, c.afterBoot) {
				t.Fatalf("after a crash at %s and boot recovery: staging files %v, want %v", c.label, got, c.afterBoot)
			}
		})
	}
}

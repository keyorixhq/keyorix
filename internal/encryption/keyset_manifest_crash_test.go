//go:build !windows

package encryption

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestRotateKEKCrashPoints_BootClassifiesAndRecovers crashes the REAL
// rotate-kek (commitNewKEKFiles) at every durability checkpoint, through the
// nil-in-production rotationCheckpoint seam (a test-installed panic, the
// in-process half of the AT2 harness — never an environment variable a
// production binary would read), then boots the key directory the way the
// server does (Service.ReconcileKeySet under the key lock, then Initialize)
// and asserts, per crash point (#2900 criterion 3):
//
//   - the boot step succeeds — every state commitNewKEKFiles can leave is
//     classified from the manifest's hashes, without a passphrase;
//   - the passphrase that opens the set afterwards is the old one until the
//     DEK rename, and the new one from it on (boot finished the salt rename in
//     the hazard window instead of only refusing), and the DEK is the original
//     one byte for byte;
//   - the other passphrase no longer opens the set once the new one does;
//   - boot records an audit event exactly when it finished the rotation.
func TestRotateKEKCrashPoints_BootClassifiesAndRecovers(t *testing.T) {
	cases := []struct {
		label         string
		newPassActive bool
		finishedEvent bool
	}{
		{"kek:after-write-salt-pending", false, false},
		{"kek:after-write-dek-pending", false, false},
		{"kek:after-stage-manifest", false, false},
		{"kek:after-rename-dek", true, true}, // the hazard window: boot finishes it
		{"kek:after-rename-salt", true, false},
		{"kek:after-commit-manifest", true, false},
	}
	const oldPass, newPass = "old-passphrase-1", "new-passphrase-2"
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			dir := t.TempDir()
			seed := newPasswordService(t, dir, oldPass)
			dek0 := seed.keyManager.GetDEK()
			runRotationWithCrash(seed.keyManager, oldPass, newPass, c.label)

			boot := NewService(passwordEncConfig(), dir)
			var mu sync.Mutex
			var events []string
			boot.SetAuditSink(func(_ context.Context, e *models.AuditEvent) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, e.EventType)
				return nil
			})
			if err := boot.AcquireExclusiveKeyLock(); err != nil {
				t.Fatalf("key lock: %v", err)
			}
			t.Cleanup(boot.Shutdown)
			if err := boot.ReconcileKeySet(); err != nil {
				t.Fatalf("boot refused the state rotate-kek leaves at %s: %v", c.label, err)
			}

			want, other := oldPass, newPass
			if c.newPassActive {
				want, other = newPass, oldPass
			}
			if err := boot.Initialize(want); err != nil {
				t.Fatalf("after a crash at %s and boot, the expected passphrase must open the set: %v", c.label, err)
			}
			if !bytes.Equal(boot.keyManager.GetDEK(), dek0) {
				t.Fatalf("after a crash at %s the DEK changed", c.label)
			}
			probe := NewService(passwordEncConfig(), dir)
			if err := probe.Initialize(other); err == nil {
				t.Errorf("after a crash at %s the other passphrase still opens the set", c.label)
			}
			mu.Lock()
			gotFinished := len(events) == 1 && events[0] == EventKeySetRotationFinished
			mu.Unlock()
			if gotFinished != c.finishedEvent {
				t.Errorf("after a crash at %s: audit events %v, want finished-event=%v", c.label, events, c.finishedEvent)
			}
		})
	}
}

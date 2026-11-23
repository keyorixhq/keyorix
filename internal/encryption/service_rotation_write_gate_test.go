package encryption

import (
	"bytes"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestRotateDEKWithSweep_WriteDuringSweepOpensAfterRotation is the red/green
// test for #4654 (INV-ENCRYPTION-dek-sweep-holds-service-write-lock). It stalls
// the real Service.RotateDEKWithSweep at the sweep:after-sweep-commit seam (the
// rows are under the new DEK, the key manager has not published it, the
// Service has not swapped), starts a write and a read of a swept row on the
// same Service, then lets the rotation finish.
//
// Before the fix the write took s.mu.RLock, waited on km.mu in GetKeyVersion,
// and resumed after the key manager published the new version but before the
// Service swap: it sealed under the superseded DEK a value labelled with the new
// version, so the value never opened again (cipher: message authentication
// failed). The read failed closed on the swept row. With the fix both wait for
// the swap: the written value opens after the rotation and the read returns the
// right plaintext.
//
// Every Encrypt* entry point that pairs s.encryptionService with the key
// version (service.go) is driven, so a new one that bypasses the gate is
// caught by adding its row here.
func TestRotateDEKWithSweep_WriteDuringSweepOpensAfterRotation(t *testing.T) {
	type write struct {
		open func(*Service) ([]byte, error)
		err  error
	}
	const plaintext = "written-during-sweep"
	cases := []struct {
		name  string
		write func(*Service) write
	}{
		{"EncryptSecret", func(s *Service) write {
			ct, _, err := s.EncryptSecret([]byte(plaintext))
			return write{func(r *Service) ([]byte, error) { return r.DecryptSecret(ct) }, err}
		}},
		{"EncryptSecretWithAAD", func(s *Service) write {
			aad := SecretAAD(99, 1, 1)
			ct, _, err := s.EncryptSecretWithAAD([]byte(plaintext), aad)
			return write{func(r *Service) ([]byte, error) { return r.DecryptSecretWithAAD(ct, aad) }, err}
		}},
		{"EncryptLargeSecret", func(s *Service) write {
			chunks, _, err := s.EncryptLargeSecret([]byte(plaintext), 1)
			return write{func(r *Service) ([]byte, error) { return r.DecryptLargeSecret(chunks) }, err}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			svc, _ := newTestService(t, "write-gate-pass")
			t.Cleanup(svc.Shutdown)
			nodeID := seedSecretNode(t, db, 1)
			seedSecretVersion(t, db, svc, nodeID, 1, 1, "swept-before")

			reached, release := make(chan struct{}), make(chan struct{})
			prev := rotationCheckpoint
			rotationCheckpoint = func(label string) {
				if label == "sweep:after-sweep-commit" {
					close(reached)
					<-release
				}
			}
			rotErr := make(chan error, 1)
			go func() { _, err := svc.RotateDEKWithSweep("write-gate-pass", db); rotErr <- err }()
			released := false
			defer func() {
				if !released {
					close(release)
					if err := <-rotErr; err != nil {
						t.Logf("rotation after an early test exit: %v", err)
					}
				}
				rotationCheckpoint = prev
			}()
			<-reached

			var swept models.SecretVersion
			if err := db.Where("secret_node_id = ?", nodeID).First(&swept).Error; err != nil {
				t.Fatal(err)
			}
			type read struct {
				pt  []byte
				err error
			}
			rd := make(chan read, 1)
			go func() {
				pt, err := svc.DecryptSecretWithAAD(swept.EncryptedValue, SecretAAD(nodeID, 1, 1))
				rd <- read{pt, err}
			}()
			wr := make(chan write, 1)
			go func() { wr <- tc.write(svc) }()

			// Give both calls time to reach the lock they wait on (at the base
			// commit the write waits on km.mu, at HEAD both wait on s.mu).
			time.Sleep(300 * time.Millisecond)
			select {
			case w := <-wr:
				wr <- w
				t.Logf("write returned while the sweep was stalled (err=%v)", w.err)
			default:
			}

			close(release)
			released = true
			if err := <-rotErr; err != nil {
				t.Fatalf("rotation: %v", err)
			}

			r := <-rd
			if r.err != nil || string(r.pt) != "swept-before" {
				t.Errorf("read of a swept row started during the sweep: got %q, %v; want %q (it must wait for the Service swap, not fail)", r.pt, r.err, "swept-before")
			}
			w := <-wr
			if w.err != nil {
				t.Fatalf("write during the sweep: %v", w.err)
			}
			got, err := w.open(svc)
			if err != nil || !bytes.Equal(got, []byte(plaintext)) {
				t.Errorf("value written during the sweep does not open after the rotation (#4654: sealed under the superseded DEK): got %q, %v", got, err)
			}
		})
	}
}

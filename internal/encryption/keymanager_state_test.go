// keymanager_state_test.go — readers racing rotations over the published keyState
// (#4376, docs/design/2026-11-15-key-custody-availability.md §2.7 items 4 and 5).
package encryption

import (
	"bytes"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
)

// setTestDEK publishes dek as the current DEK, keeping the rest of the state.
func setTestDEK(km *KeyManager, dek []byte) {
	next := km.nextState()
	next.dek = dek
	km.state.Store(next)
}

// keyPairs records, per KEK-derived key, every (key ID → key) pair one
// generation of the key manager published.
type keyPairs map[string]map[string]string

// add records the pair and reports false if id was already recorded with a
// different key.
func (p keyPairs) add(kind, id string, key []byte) bool {
	if p[kind] == nil {
		p[kind] = map[string]string{}
	}
	k := hex.EncodeToString(key)
	if prev, ok := p[kind][id]; ok && prev != k {
		return false
	}
	p[kind][id] = k
	return true
}

func (p keyPairs) addCurrent(t *testing.T, km *KeyManager) {
	t.Helper()
	for kind, get := range map[string]func() ([]byte, string, bool){
		"evidence-signing": km.GetEvidenceSignKey,
		"audit-checkpoint": km.GetAuditCheckpointKey,
		"backup-manifest":  km.GetBackupManifestKey,
	} {
		key, id, ok := get()
		if !ok {
			t.Fatalf("%s key missing on an initialized key manager", kind)
		}
		if !p.add(kind, id, key) {
			t.Fatalf("%s key ID %q published with two different keys", kind, id)
		}
	}
}

// TestKeyState_ReadersRacingKEKRotationSeeWholeGenerations runs readers of every
// getter against a chain of KEK rotations (run it under -race). Every value a
// reader sees must be one whole generation: a key with the ID it was published
// with (never a new key under an old ID, or a wiped key), the unchanged DEK and
// key version. The pairs are checked against the generations the rotating
// goroutine recorded, after all goroutines are joined.
func TestKeyState_ReadersRacingKEKRotationSeeWholeGenerations(t *testing.T) {
	passes := []string{"race-p0", "race-p1", "race-p2", "race-p3"}
	km := NewKeyManager(t.TempDir(), "dek.key", "kek.salt")
	if err := km.Initialize(passes[0]); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dek0, version0 := km.GetDEK(), km.GetKeyVersion()
	published := keyPairs{}
	published.addCurrent(t, km)

	const readers = 4
	stop := make(chan struct{})
	seen := make([]keyPairs, readers)
	var bad []string
	var badMu sync.Mutex
	var wg sync.WaitGroup
	for r := range readers {
		seen[r] = keyPairs{}
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !bytes.Equal(km.GetDEK(), dek0) || km.GetKeyVersion() != version0 {
					badMu.Lock()
					bad = append(bad, "DEK or key version changed across a KEK rotation")
					badMu.Unlock()
				}
				for kind, get := range map[string]func() ([]byte, string, bool){
					"evidence-signing": km.GetEvidenceSignKey,
					"audit-checkpoint": km.GetAuditCheckpointKey,
					"backup-manifest":  km.GetBackupManifestKey,
				} {
					key, id, ok := get()
					if !ok {
						badMu.Lock()
						bad = append(bad, kind+" key missing mid-rotation")
						badMu.Unlock()
						continue
					}
					if !seen[r].add(kind, id, key) {
						badMu.Lock()
						bad = append(bad, kind+" key ID "+id+" read with two different keys")
						badMu.Unlock()
					}
				}
			}
		})
	}

	for i := range len(passes) - 1 {
		if err := km.RotateKEKPassphrase(passes[i], passes[i+1]); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("rotation %d: %v", i, err)
		}
		published.addCurrent(t, km)
	}
	close(stop)
	wg.Wait()

	if len(bad) > 0 {
		t.Fatalf("%d torn reads, first: %s", len(bad), bad[0])
	}
	reads := 0
	for r := range readers {
		for kind, pairs := range seen[r] {
			for id, key := range pairs {
				reads++
				want, ok := published[kind][id]
				if !ok {
					t.Fatalf("reader %d saw a %s key ID %q that no generation published", r, kind, id)
				}
				if key != want {
					t.Fatalf("reader %d saw %s key ID %q with a key that is not the one published under it "+
						"(a torn or wiped read): got %s…", r, kind, id, key[:8])
				}
			}
		}
	}
	if reads == 0 {
		t.Fatal("HARNESS: the readers recorded nothing")
	}
}

// TestKeyState_ConcurrentKEKRotationsSerialise is §2.7 item 5: two rotations
// from the same old passphrase race on one key manager; rotateMu (and the DEK
// flock) serialise them, so exactly one wins and the other fails closed on the
// old passphrase, which no longer unwraps the DEK under the new salt.
func TestKeyState_ConcurrentKEKRotationsSerialise(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("serial-old"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dek0 := km.GetDEK()

	newPasses := []string{"serial-a", "serial-b"}
	errs := make([]error, len(newPasses))
	var wg sync.WaitGroup
	for i, np := range newPasses {
		wg.Go(func() { errs[i] = km.RotateKEKPassphrase("serial-old", np) })
	}
	wg.Wait()

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil && winner < 0:
			winner = i
		case err == nil:
			t.Fatal("both concurrent KEK rotations from the same old passphrase succeeded")
		case !strings.Contains(err.Error(), "old passphrase is incorrect"):
			t.Fatalf("losing rotation failed with %v, want the old-passphrase refusal", err)
		}
	}
	if winner < 0 {
		t.Fatalf("no rotation succeeded: %v", errs)
	}
	reopened := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := reopened.Initialize(newPasses[winner]); err != nil {
		t.Fatalf("reopen under the winner's passphrase: %v", err)
	}
	if !bytes.Equal(reopened.GetDEK(), dek0) {
		t.Fatal("reopened DEK differs from the original")
	}
}

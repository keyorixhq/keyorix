// service_rotation_lock_scope_test.go — Service encrypt/decrypt during a KEK
// rotation or DEK re-wrap (#4625).
//
// KeyManager readers stopped waiting on a KEK rotation's or a DEK re-wrap's
// disk I/O in #4376 (keymanager_slow_disk_sync_test.go). The Service wrapper
// still held Service.mu for writing across the whole key-manager call, so every
// Service.EncryptSecret*/DecryptSecret*/key getter waited for the rotation's
// fsyncs anyway. These tests stall the rotation inside its directory fsync
// (blocking until the test releases it, no timing) and require every Service
// reader to return while it is stalled, with the pre-rotation keys, and the data
// written during the stall to open after the rotation and after a reopen.
package encryption

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// lockScopeWait bounds how long a test waits for something that must happen
// (the seam being reached, the probes returning). It only turns a hang into a
// failure; nothing here waits for time to pass.
const lockScopeWait = 10 * time.Second

// armBlockingSeamOnce installs a fileFaultHook that, on the FIRST call for
// seam, closes reached and blocks until release is closed, then lets the real
// durability call run. Restore after the rotation goroutine has returned (the
// hook is a package global, not for parallel tests).
func armBlockingSeamOnce(seam string) (reached, release chan struct{}, restore func()) {
	prev := fileFaultHook
	reached, release = make(chan struct{}), make(chan struct{})
	var fired bool
	fileFaultHook = func(s string) *fileFault {
		if s == seam && !fired {
			fired = true
			close(reached)
			<-release
		}
		return nil
	}
	return reached, release, func() { fileFaultHook = prev }
}

// serviceProbe is what one round of Service reads saw.
type serviceProbe struct {
	plain0     []byte // ct0 decrypted
	ct         []byte // a value encrypted during the stall (with aad)
	ackID      string // audit-checkpoint key ID
	eskID      string // evidence-signing key ID
	bmkID      string // backup-manifest key ID
	keyVersion string
}

// probeService runs every Service reader once and returns what it saw, or the
// first error.
func probeService(svc *Service, ct0, aad []byte, plain []byte) (serviceProbe, error) {
	var p serviceProbe
	if !svc.IsInitialized() {
		return p, fmt.Errorf("IsInitialized() = false during the rotation")
	}
	p.keyVersion = svc.GetKeyVersion()
	got, err := svc.DecryptSecretWithAAD(ct0, aad)
	if err != nil {
		return p, fmt.Errorf("DecryptSecretWithAAD(pre-rotation value): %w", err)
	}
	p.plain0 = got
	if p.ct, _, err = svc.EncryptSecretWithAAD(plain, aad); err != nil {
		return p, fmt.Errorf("EncryptSecretWithAAD: %w", err)
	}
	ctNoAAD, _, err := svc.EncryptSecret(plain)
	if err != nil {
		return p, fmt.Errorf("EncryptSecret: %w", err)
	}
	if got, err := svc.DecryptSecret(ctNoAAD); err != nil || !bytes.Equal(got, plain) {
		return p, fmt.Errorf("DecryptSecret round trip: %q, %v", got, err)
	}
	chunks, _, err := svc.EncryptLargeSecret(plain, 1)
	if err != nil {
		return p, fmt.Errorf("EncryptLargeSecret: %w", err)
	}
	if got, err := svc.DecryptLargeSecret(chunks); err != nil || !bytes.Equal(got, plain) {
		return p, fmt.Errorf("DecryptLargeSecret round trip: %q, %v", got, err)
	}
	var key []byte
	var ok bool
	if key, p.ackID, ok = svc.AuditCheckpointKey(); !ok {
		return p, fmt.Errorf("AuditCheckpointKey unavailable")
	}
	wipeBytes(key)
	if key, p.eskID, ok = svc.EvidenceSignKey(); !ok {
		return p, fmt.Errorf("EvidenceSignKey unavailable")
	}
	wipeBytes(key)
	if key, p.bmkID, ok = svc.BackupManifestKey(); !ok {
		return p, fmt.Errorf("BackupManifestKey unavailable")
	}
	wipeBytes(key)
	return p, nil
}

// keyIDs returns the three KEK-derived key IDs svc currently serves.
func keyIDs(t *testing.T, svc *Service) (ack, esk, bmk string) {
	t.Helper()
	var key []byte
	key, ack, _ = svc.AuditCheckpointKey()
	wipeBytes(key)
	key, esk, _ = svc.EvidenceSignKey()
	wipeBytes(key)
	key, bmk, _ = svc.BackupManifestKey()
	wipeBytes(key)
	return ack, esk, bmk
}

// runStalledRotation starts rotate on a goroutine, waits until it is stalled
// in seam, runs probeService on another goroutine while it stays stalled, and
// then releases it. Alongside the probe it runs background encrypt/decrypt
// loops for the race detector. It fails if a probe does not return while the
// rotation is stalled (the Service holds a lock its readers take across the
// rotation's I/O) and returns the probe and the rotation's error.
func runStalledRotation(t *testing.T, svc *Service, seam string, rotate func() error, ct0, aad, plain []byte) (serviceProbe, error) {
	t.Helper()
	reached, release, restore := armBlockingSeamOnce(seam)
	defer restore()
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFn()

	rotDone := make(chan error, 1)
	go func() { rotDone <- rotate() }()
	select {
	case <-reached:
	case err := <-rotDone:
		t.Fatalf("HARNESS: the rotation returned (err=%v) without reaching seam %s", err, seam)
	case <-time.After(lockScopeWait):
		t.Fatalf("HARNESS: the rotation never reached seam %s", seam)
	}

	// Background readers and writers for -race, from the stall until the end.
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bgErr := make(chan error, 4)
	for range 4 {
		bg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				ct, _, err := svc.EncryptSecretWithAAD(plain, aad)
				if err == nil {
					var got []byte
					got, err = svc.DecryptSecretWithAAD(ct, aad)
					if err == nil && !bytes.Equal(got, plain) {
						err = fmt.Errorf("round trip returned %q", got)
					}
				}
				if err != nil {
					bgErr <- err
					return
				}
			}
		})
	}

	type result struct {
		p   serviceProbe
		err error
	}
	probeDone := make(chan result, 1)
	go func() {
		p, err := probeService(svc, ct0, aad, plain)
		probeDone <- result{p, err}
	}()
	var res result
	select {
	case res = <-probeDone:
	case <-time.After(lockScopeWait):
		releaseFn()
		if err := <-rotDone; err != nil {
			t.Logf("rotation after release: %v", err)
		}
		<-probeDone
		close(stop)
		bg.Wait()
		t.Fatalf("Service readers did not return while the rotation was stalled in %s: "+
			"the Service holds a lock its encrypt/decrypt path takes across the key manager's rotation I/O (#4625)", seam)
	}
	select {
	case err := <-rotDone:
		t.Fatalf("HARNESS: the rotation returned (err=%v) before it was released — the probe did not overlap the stall", err)
	default:
	}

	releaseFn()
	var rotErr error
	select {
	case rotErr = <-rotDone:
	case <-time.After(lockScopeWait):
		t.Fatalf("DEADLOCK: the rotation did not return after its seam was released")
	}
	close(stop)
	bg.Wait()
	select {
	case err := <-bgErr:
		t.Fatalf("a concurrent Service encrypt/decrypt failed during the rotation: %v", err)
	default:
	}
	if res.err != nil {
		t.Fatalf("Service reader during the stalled rotation: %v", res.err)
	}
	return res.p, rotErr
}

// TestServiceKEKRotation_EncryptDecryptNotBlockedAcrossSync is the acceptance
// test for #4625 (KEK rotation): Service readers return while the rotation is
// stalled in its directory fsync, see the old KEK-derived keys until it
// returns and the new ones after, and every value written during the stall
// opens after the rotation and after a reopen under the new passphrase.
func TestServiceKEKRotation_EncryptDecryptNotBlockedAcrossSync(t *testing.T) {
	const oldPass, newPass = "svc-lock-old-pass", "svc-lock-new-pass"
	dir := t.TempDir()
	svc := newTestServiceAtDir(t, dir, oldPass)
	defer svc.Shutdown()

	aad := []byte("svc-lock-scope-aad")
	plain0, plain := []byte("written before the rotation"), []byte("written during the rotation")
	ct0, _, err := svc.EncryptSecretWithAAD(plain0, aad)
	if err != nil {
		t.Fatalf("EncryptSecretWithAAD before the rotation: %v", err)
	}
	oldACK, oldESK, oldBMK := keyIDs(t, svc)
	oldVersion := svc.GetKeyVersion()

	p, rotErr := runStalledRotation(t, svc, "kek:syncdir-dek",
		func() error { return svc.RotateKEKPassphrase(oldPass, newPass) }, ct0, aad, plain)
	if rotErr != nil {
		t.Fatalf("KEK rotation: %v", rotErr)
	}

	// No stale-new read: nothing is published before the files are durable.
	if p.ackID != oldACK || p.eskID != oldESK || p.bmkID != oldBMK {
		t.Fatalf("during the stalled rotation the Service served key IDs (%s, %s, %s), want the old (%s, %s, %s)",
			p.ackID, p.eskID, p.bmkID, oldACK, oldESK, oldBMK)
	}
	if !bytes.Equal(p.plain0, plain0) || p.keyVersion != oldVersion {
		t.Fatalf("during the rotation: decrypted %q (want %q), key version %q (want %q)", p.plain0, plain0, p.keyVersion, oldVersion)
	}
	// No stale-old read after the rotation returned.
	newACK, newESK, newBMK := keyIDs(t, svc)
	if newACK == oldACK || newESK == oldESK || newBMK == oldBMK {
		t.Fatalf("after the KEK rotation the Service still serves an old KEK-derived key ID: (%s, %s, %s)", newACK, newESK, newBMK)
	}

	// No lost update: the value written during the stall opens now and after a
	// reopen under the new passphrase, like the one written before.
	for name, c := range map[string][]byte{"before": ct0, "during": p.ct} {
		if _, err := svc.DecryptSecretWithAAD(c, aad); err != nil {
			t.Fatalf("value written %s the rotation does not decrypt after it: %v", name, err)
		}
	}
	svc.Shutdown()
	reopened := newTestServiceAtDir(t, dir, newPass)
	defer reopened.Shutdown()
	for name, c := range map[string][]byte{"before": ct0, "during": p.ct} {
		want := map[string][]byte{"before": plain0, "during": plain}[name]
		got, err := reopened.DecryptSecretWithAAD(c, aad)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("after a reopen under the new passphrase, the value written %s the rotation: %q, %v", name, got, err)
		}
	}
	if ack, _, _ := keyIDs(t, reopened); ack != newACK {
		t.Fatalf("reopened audit-checkpoint key ID %s, want the one the rotation published (%s)", ack, newACK)
	}
}

// TestServiceRewrap_EncryptDecryptNotBlockedAcrossSync is the acceptance test
// for #4625 (DEK re-wrap, migrate-provider): Service readers return while the
// re-wrap is stalled in its directory fsync, and every value written during the
// stall opens from a fresh key manager under the new provider.
func TestServiceRewrap_EncryptDecryptNotBlockedAcrossSync(t *testing.T) {
	const pass = "svc-lock-rewrap-pass"
	dir := t.TempDir()
	svc := newTestServiceAtDir(t, dir, pass)
	defer svc.Shutdown()

	newKEK := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEK)
	aad := []byte("svc-lock-scope-rewrap-aad")
	plain0, plain := []byte("written before the re-wrap"), []byte("written during the re-wrap")
	ct0, _, err := svc.EncryptSecretWithAAD(plain0, aad)
	if err != nil {
		t.Fatalf("EncryptSecretWithAAD before the re-wrap: %v", err)
	}
	oldACK, _, _ := keyIDs(t, svc)

	p, rotErr := runStalledRotation(t, svc, "rewrap:syncdir",
		func() error { return svc.RewrapDEKWithProvider(crypto.NewFileKeyProvider(newKEK)) }, ct0, aad, plain)
	if rotErr != nil {
		t.Fatalf("DEK re-wrap: %v", rotErr)
	}
	if !bytes.Equal(p.plain0, plain0) || p.ackID != oldACK {
		t.Fatalf("during the stalled re-wrap: decrypted %q (want %q), audit key ID %s (want %s)", p.plain0, plain0, p.ackID, oldACK)
	}
	svc.Shutdown()

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(newKEK))
	if err := km.Initialize(""); err != nil {
		t.Fatalf("reopen under the new provider: %v", err)
	}
	defer km.Wipe()
	es, err := NewEncryptionService(km.GetDEK())
	if err != nil {
		t.Fatalf("NewEncryptionService: %v", err)
	}
	defer es.WipeDEK()
	for name, c := range map[string][]byte{"before": ct0, "during": p.ct} {
		want := map[string][]byte{"before": plain0, "during": plain}[name]
		ed, err := DeserializeEncryptedData(c)
		if err != nil {
			t.Fatalf("deserialize the value written %s the re-wrap: %v", name, err)
		}
		got, err := es.DecryptWithAAD(ed, aad)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("under the new provider, the value written %s the re-wrap: %q, %v", name, got, err)
		}
	}
}

// TestServiceShutdownDuringKEKRotation_NoDeadlock: Shutdown arriving while a
// KEK rotation is stalled in its fsync waits for it (KeyManager.Wipe takes
// rotateMu) and both return; the rotation either completed before the wipe or
// the service is left uninitialized, never half-wiped mid-rotation.
func TestServiceShutdownDuringKEKRotation_NoDeadlock(t *testing.T) {
	const oldPass, newPass = "svc-lock-shutdown-old", "svc-lock-shutdown-new"
	dir := t.TempDir()
	svc := newTestServiceAtDir(t, dir, oldPass)

	reached, release, restore := armBlockingSeamOnce("kek:syncdir-dek")
	defer restore()
	rotDone := make(chan error, 1)
	go func() { rotDone <- svc.RotateKEKPassphrase(oldPass, newPass) }()
	select {
	case <-reached:
	case <-time.After(lockScopeWait):
		close(release)
		t.Fatal("HARNESS: the rotation never reached its directory fsync")
	}
	shutDone := make(chan struct{})
	go func() { svc.Shutdown(); close(shutDone) }()
	close(release)
	select {
	case <-shutDone:
	case <-time.After(lockScopeWait):
		t.Fatal("DEADLOCK: Shutdown did not return after the rotation was released")
	}
	select {
	case err := <-rotDone:
		if err != nil {
			t.Fatalf("KEK rotation that was already past its checks failed: %v", err)
		}
	case <-time.After(lockScopeWait):
		t.Fatal("DEADLOCK: the rotation did not return after Shutdown")
	}
	if svc.IsInitialized() {
		t.Fatal("service still initialized after Shutdown")
	}
	reopened := newTestServiceAtDir(t, dir, newPass)
	reopened.Shutdown()
}

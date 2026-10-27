package encryption

// sweep_verify_unit_test.go — unit tests of sweep_verify.go (DEK-ROTATE-SAFETY-1
// item 1). The end-to-end fault test is sweep_verify_test.go.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestRotateDEKWithSweep_PreCommitVerify_ErrorIsTyped: the refusal wraps
// ErrSweepVerification so callers can tell it from other sweep failures.
func TestRotateDEKWithSweep_PreCommitVerify_ErrorIsTyped(t *testing.T) {
	f := newVerifyFixture(t)
	installRewrapFault(t, f.db, "secret_versions", "encrypted_value", f.versionIDs[0], flipCiphertextByte)
	_, err := f.svc.RotateDEKWithSweep(f.passphrase, f.db)
	if !errors.Is(err, ErrSweepVerification) {
		t.Fatalf("want ErrSweepVerification, got %v", err)
	}
}

// TestRotateDEKWithSweep_PreCommitVerify_CleanRotationPasses is the positive
// control: with no fault the same fixture rotates and every row decrypts
// under the new DEK.
func TestRotateDEKWithSweep_PreCommitVerify_CleanRotationPasses(t *testing.T) {
	f := newVerifyFixture(t)
	oldDEK := captureCurrentDEK(t, f.svc)
	res, err := f.svc.RotateDEKWithSweep(f.passphrase, f.db)
	if err != nil {
		t.Fatalf("RotateDEKWithSweep: %v", err)
	}
	if res.SecretVersionsSwept != len(f.versionIDs) || res.MFASecretsSwept != 1 || res.NotificationChannelsSwept != 1 {
		t.Fatalf("unexpected sweep counts: %+v", res)
	}
	if bytes.Equal(captureCurrentDEK(t, f.svc), oldDEK) {
		t.Fatal("the DEK did not change")
	}
	opened, err := verifySweptRows(f.db, f.svc.encryptionService)
	if err != nil || opened != len(f.versionIDs)+2 {
		t.Fatalf("after a clean rotation every row must open under the new DEK: opened %d, err %v", opened, err)
	}
}

// TestRewrapCanary_RefusesBrokenNewDEK: a new DEK service that cannot open
// its own ciphertext (here: wiped) is refused before the sweep writes anything.
func TestRewrapCanary_RefusesBrokenNewDEK(t *testing.T) {
	f := newVerifyFixture(t)
	k, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := NewEncryptionService(k)
	if err != nil {
		t.Fatal(err)
	}
	broken.WipeDEK()
	err = rewrapCanary(f.db, f.svc.encryptionService, broken, "v-canary")
	if !errors.Is(err, ErrSweepVerification) || !strings.Contains(err.Error(), "canary secret_versions id=") {
		t.Fatalf("want a canary refusal naming the row, got %v", err)
	}
	if err := rewrapCanary(f.db, f.svc.encryptionService, f.svc.encryptionService, "v-canary"); err != nil {
		t.Fatalf("positive control: a working new DEK must pass the canary: %v", err)
	}
}

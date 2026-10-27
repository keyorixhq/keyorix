package encryption

// sweep_verify_unit_test.go — unit tests of sweep_verify.go (DEK-ROTATE-SAFETY-1
// item 1). The end-to-end fault test is sweep_verify_test.go.

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"
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

// TestSweptTableReaders_CoverEverySweptModel keeps the verifier in step with
// the sweep: one reader per swept model, each reading that model's table, and
// every per-table count of SweepResult in sweptRowCount. A table added to the
// sweep but not here would otherwise be committed unverified.
func TestSweptTableReaders_CoverEverySweptModel(t *testing.T) {
	db := newTestDB(t)
	readers := sweptTableReaders(map[uint]uint{})
	models := sweptModels()
	if len(readers) != len(models) {
		t.Fatalf("%d verifier readers for %d swept models", len(readers), len(models))
	}
	for i, m := range models {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(m); err != nil {
			t.Fatal(err)
		}
		var queried string
		probe := db.Session(&gorm.Session{DryRun: true})
		probe.Callback().Query().Before("gorm:query").Register("test:table-probe", func(tx *gorm.DB) { queried = tx.Statement.Table })
		_, _, _ = readers[i](probe, 0, 1)
		_ = probe.Callback().Query().Remove("test:table-probe")
		if queried != stmt.Schema.Table {
			t.Errorf("verifier reader %d reads table %q, swept model %d is %q", i, queried, i, stmt.Schema.Table)
		}
	}

	var r SweepResult
	v := reflect.ValueOf(&r).Elem()
	n := 0
	for i := 0; i < v.NumField(); i++ {
		if f := v.Type().Field(i); strings.HasSuffix(f.Name, "Swept") {
			v.Field(i).SetInt(1)
			n++
		}
	}
	if n != len(models) {
		t.Errorf("SweepResult has %d per-table counts for %d swept models", n, len(models))
	}
	if got := r.sweptRowCount(); got != n {
		t.Errorf("sweptRowCount sums %d of the %d per-table counts", got, n)
	}
}

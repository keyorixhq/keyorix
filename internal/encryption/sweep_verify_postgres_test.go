package encryption

// sweep_verify_postgres_test.go — DEK-ROTATE-SAFETY-1 item 1 on real
// PostgreSQL: a rotation refused by its pre-commit decrypt check leaves the DEK
// epoch on the old DEK, so a running replica resumes writing and the old key
// set still decrypts everything. Skips when KEYORIX_TEST_PG_DSN is unset.

import (
	"errors"
	"strconv"
	"testing"
)

func TestRotateDEKWithSweep_Postgres_PreCommitVerifyFailureKeepsOldEpoch(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, node := epochReplicas(t, db)
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 3; v++ {
		if err := epochWrite(t, b, db, node, v); err != nil {
			t.Fatal(err)
		}
	}
	old := fingerprintOf(t, a)
	var target uint
	if err := db.Table("secret_versions").Select("id").Where("secret_node_id = ? AND version_number = 2", node.ID).Scan(&target).Error; err != nil || target == 0 {
		t.Fatalf("find target row: id=%d err=%v", target, err)
	}
	hits := installRewrapFault(t, db, "secret_versions", "encrypted_value", target, flipCiphertextByte)

	_, err := a.RotateDEKWithSweep(epochPass, db)
	if hits.Load() == 0 {
		t.Fatal("the faulting wrapper never saw the sweep's write (fixture broken)")
	}
	if !errors.Is(err, ErrSweepVerification) {
		t.Fatalf("want ErrSweepVerification, got %v", err)
	}
	if v, _ := epochValue(t, db); v != old {
		t.Fatalf("epoch after the refused rotation = %q, want the old fingerprint %q", v, old)
	}
	if fingerprintOf(t, a) != old {
		t.Fatal("the rotating service switched DEK although the rotation was refused")
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("DATA LOSS: versions the old (still active) DEK cannot decrypt: %v", bad)
	}
	waitFor(t, "replica B to resume writing", func() bool { return epochWrite(t, b, db, node, 4) == nil })
}

// DEK-ROTATE-SAFETY-1 item 3: a server start on PostgreSQL records the rotation
// protocol, so an older admin binary that reads it refuses to rotate.
func TestDEKEpoch_Postgres_StartRecordsRotationProtocol(t *testing.T) {
	db := epochPGDB(t)
	_, _, _, b, _ := epochReplicas(t, db)
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	if got := recordedRotationProtocol(t, db); got != strconv.Itoa(dekRotationProtocol) {
		t.Fatalf("recorded protocol after server start = %q, want %d", got, dekRotationProtocol)
	}
}

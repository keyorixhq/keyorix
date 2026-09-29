package auditverify

import (
	"os"
	"path/filepath"
	"testing"
)

// encodeHighWaterForTest builds a syntactically valid encoded high-water
// value with chainedEvents, using a placeholder signature since the tests
// in this file exercise witness comparison logic, not signature
// verification.
func encodeHighWaterForTest(chainedEvents int64) string {
	cp := &Checkpoint{ChainedEvents: chainedEvents, HeadID: 1, HeadHash: "deadbeef", KeyVersion: "v1"}
	return EncodeHighWater(cp, "placeholder-sig")
}

func TestWitnessPath_SiblingOfDBFile(t *testing.T) {
	got := WitnessPath("/data/keyorix.db")
	want := filepath.Join("/data", AuditHighWaterWitnessFileName)
	if got != want {
		t.Fatalf("WitnessPath(%q) = %q, want %q", "/data/keyorix.db", got, want)
	}
}

func TestReadWitness_AbsentIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)

	_, _, found, err := ReadWitness(path)
	if err != nil {
		t.Fatalf("ReadWitness on an absent file returned an error: %v", err)
	}
	if found {
		t.Fatal("ReadWitness on an absent file reported found=true")
	}
}

func TestReadWitness_CorruptedFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)
	if err := os.WriteFile(path, []byte("not a valid high-water value"), 0600); err != nil {
		t.Fatalf("write corrupted witness fixture: %v", err)
	}

	_, _, found, err := ReadWitness(path)
	if err == nil {
		t.Fatal("ReadWitness on a corrupted file returned no error — a corrupted witness must " +
			"never be silently treated as absent, or deleting/corrupting it becomes a rollback-protection bypass")
	}
	if found {
		t.Fatal("ReadWitness on a corrupted file reported found=true")
	}
}

func TestWriteWitnessIfHigher_WritesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)

	wrote, err := WriteWitnessIfHigher(path, encodeHighWaterForTest(10))
	if err != nil {
		t.Fatalf("WriteWitnessIfHigher: %v", err)
	}
	if !wrote {
		t.Fatal("expected wrote=true when no witness existed yet")
	}

	cp, _, found, err := ReadWitness(path)
	if err != nil || !found {
		t.Fatalf("ReadWitness after write: found=%v err=%v", found, err)
	}
	if cp.ChainedEvents != 10 {
		t.Fatalf("ChainedEvents = %d, want 10", cp.ChainedEvents)
	}
}

func TestWriteWitnessIfHigher_NeverLowersTheMark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)

	if _, err := WriteWitnessIfHigher(path, encodeHighWaterForTest(50)); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	wrote, err := WriteWitnessIfHigher(path, encodeHighWaterForTest(20))
	if err != nil {
		t.Fatalf("WriteWitnessIfHigher with a lower value: %v", err)
	}
	if wrote {
		t.Fatal("expected wrote=false when the new value is lower than the existing witness — " +
			"the witness must never regress")
	}

	cp, _, found, err := ReadWitness(path)
	if err != nil || !found {
		t.Fatalf("ReadWitness after attempted lower write: found=%v err=%v", found, err)
	}
	if cp.ChainedEvents != 50 {
		t.Fatalf("ChainedEvents = %d, want the original 50 to still be recorded (unregressed)", cp.ChainedEvents)
	}
}

func TestWriteWitnessIfHigher_AdvancesOnHigherValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)

	if _, err := WriteWitnessIfHigher(path, encodeHighWaterForTest(5)); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	wrote, err := WriteWitnessIfHigher(path, encodeHighWaterForTest(15))
	if err != nil {
		t.Fatalf("WriteWitnessIfHigher with a higher value: %v", err)
	}
	if !wrote {
		t.Fatal("expected wrote=true when the new value is higher than the existing witness")
	}

	cp, _, found, err := ReadWitness(path)
	if err != nil || !found {
		t.Fatalf("ReadWitness after advance: found=%v err=%v", found, err)
	}
	if cp.ChainedEvents != 15 {
		t.Fatalf("ChainedEvents = %d, want 15", cp.ChainedEvents)
	}
}

func TestWriteWitnessIfHigher_RefusesMalformedValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AuditHighWaterWitnessFileName)

	_, err := WriteWitnessIfHigher(path, "not a valid encoded high-water value")
	if err == nil {
		t.Fatal("expected an error for a malformed encoded value, got none")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("a malformed value must never reach disk, but the witness file was created")
	}
}

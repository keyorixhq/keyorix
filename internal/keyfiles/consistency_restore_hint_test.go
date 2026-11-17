package keyfiles

import (
	"os"
	"strings"
	"testing"
)

// The incoherent-set refusal tells the operator to restore the whole set from
// one backup. That host was mid-operation, so its database holds data, and
// since KEY-ROTATION-SAFETY-1 (#4311) `admin restore --overwrite-existing`
// alone refuses a populated target: the hint must name --replace-existing-data
// too, or the operator who follows it hits a second refusal.
func TestIncoherentKeySetRefusal_RestoreHintNamesReplaceExistingData(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK()
	if err := os.Remove(f.salt + ".pending"); err != nil {
		t.Fatal(err)
	}
	err := VerifyKeySetConsistency(passwordSetConfig(), f.dir)
	if err == nil || !strings.Contains(err.Error(), "key material is incoherent") {
		t.Fatalf("want the incoherent-set refusal, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"admin restore", "--overwrite-existing", "--replace-existing-data"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the restore hint must name %q, got %v", want, msg)
		}
	}
}

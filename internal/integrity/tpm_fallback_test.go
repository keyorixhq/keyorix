package integrity

import (
	"strings"
	"testing"
)

// tpmFullEnv is a host where every rung except possibly TPM sealing holds.
func tpmFullEnv(t *testing.T, tpm TPMState) Env {
	t.Helper()
	root := fakeRoot(t, map[string]string{
		secureBootVar:                    "\x07\x00\x00\x00\x01",
		"sys/kernel/security/lockdown":   "none [integrity] confidentiality",
		"sys/kernel/security/ima/policy": "appraise func=BPRM_CHECK\n",
	})
	e := linuxEnv(root)
	e.FSVerity = fakeVerity{on: true}
	e.KeylimePresent = func() (bool, error) { return true, nil }
	e.TPM = tpm
	return e
}

func TestTPMSealingWithWeakerFallbackIsNotCredited(t *testing.T) {
	r := Collect(tpmFullEnv(t, TPMState{Configured: true, BlobPresent: true, WeakerFallback: "password"}))
	l := lineOf(r, CheckTPMSealing)
	if l.State == StateOK {
		t.Fatalf("tpm-sealing is plain ok although a weaker fallback can recover the KEK: %s", l)
	}
	if s := l.String(); !strings.Contains(s, "tpm-sealing: ok (weaker fallback configured: password)") {
		t.Fatalf("line = %s", s)
	}
	if r.Tier != 4 {
		t.Fatalf("tier = %d (%s), want 4: the TPM rung must not be credited", r.Tier, r.TierWhy)
	}
}

func TestTPMSealingWithoutFallbackStillCredited(t *testing.T) {
	r := Collect(tpmFullEnv(t, TPMState{Configured: true, BlobPresent: true}))
	if l := lineOf(r, CheckTPMSealing); l.State != StateOK || strings.Contains(l.String(), "fallback") {
		t.Fatalf("line = %s", l)
	}
	if r.Tier != 6 {
		t.Fatalf("tier = %d (%s), want 6", r.Tier, r.TierWhy)
	}
}

// A missing blob stays degraded; the fallback note must not turn it into ok.
func TestTPMWeakerFallbackDoesNotUpgradeAMissingBlob(t *testing.T) {
	l := lineOf(Collect(tpmFullEnv(t, TPMState{Configured: true, WeakerFallback: "file"})), CheckTPMSealing)
	if l.State != StateDegraded {
		t.Fatalf("line = %s", l)
	}
}

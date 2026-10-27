package pqwrap

import (
	"bytes"
	"crypto/fips140"
	"os"
	"os/exec"
	"testing"
)

const fipsChildEnv = "PQWRAP_FIPS_CHILD"

// TestFIPS140OnlyMode re-runs the round trip in a child process started with
// GODEBUG=fips140=only, the strictest Go FIPS 140-3 setting, where any
// non-approved algorithm is refused. The construction must work there: ML-KEM,
// HKDF-SHA-256 and AES-256-GCM (random nonce) are approved; X25519 is used
// only as the auxiliary secret of an ML-KEM hybrid (pq-key-wrapping.md §9).
func TestFIPS140OnlyMode(t *testing.T) {
	if os.Getenv(fipsChildEnv) == "1" {
		if !fips140.Enforced() {
			t.Fatal("child is not running with fips140=only")
		}
		for _, s := range allSuites {
			priv := testKey(t, s, "fips")
			key := bytes.Repeat([]byte{9}, 32)
			env, err := Wrap(priv.PublicKey(), PurposeDEK, []byte("ctx"), key)
			if err != nil {
				t.Fatalf("%v: Wrap under fips140=only: %v", s, err)
			}
			got, err := Unwrap(priv, PurposeDEK, []byte("ctx"), env)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("%v: Unwrap under fips140=only: %v", s, err)
			}
			if _, err := GenerateKey(s); err != nil {
				t.Fatalf("%v: GenerateKey under fips140=only: %v", s, err)
			}
		}
		// The keyset (KEK slot, MAC, KCV, one hybrid slot) and the legacy
		// reader and writer run under the same mode.
		_, pubs := tRecipients(t, "fips-ks")
		ks := mustSeal(t, tDEK("fips"), tKEK("fips"), tKEKID("fips"), pubs)
		if _, err := OpenKeyset(ks, tKEK("fips")); err != nil {
			t.Fatalf("OpenKeyset under fips140=only: %v", err)
		}
		legacy, err := SealLegacy(tDEK("fips"), tKEK("fips"))
		if err != nil {
			t.Fatalf("SealLegacy under fips140=only: %v", err)
		}
		if _, _, err := OpenKeyFile(legacy, tKEK("fips")); err != nil {
			t.Fatalf("OpenKeyFile(legacy) under fips140=only: %v", err)
		}
		return
	}
	if testing.Short() {
		t.Skip("spawns a child test process")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPS140OnlyMode$", "-test.count=1")
	cmd.Env = append(os.Environ(), fipsChildEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=only failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("child did not report PASS:\n%s", out)
	}
}

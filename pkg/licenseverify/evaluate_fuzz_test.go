// evaluate_fuzz_test.go — FINISH-SPLIT step 2 (docs/cli-split-inventory.md §7 PR 10): a fuzz
// target on the moved verifier, matching pkg/bundleverify's existing fuzzers. Evaluate now
// parses a token string handed to it by the thin CLI's `license install`/`status --license`
// commands (an arbitrary operator-supplied file, no server-side pre-validation) as well as
// the server's own Gate -- exactly the kind of untrusted-input boundary this repo's fuzz
// corpus targets. The one invariant that matters: Evaluate must never panic, and must never
// return a state that grants features (Grants() == true) for a token it could not verify.
package licenseverify

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/pkg/trust"
)

func FuzzEvaluate(f *testing.F) {
	reg := trust.NewRegistry()
	pub, priv, err := trust.GenerateKey()
	if err != nil {
		f.Fatalf("generate seed keypair: %v", err)
	}
	if err := reg.Add(trust.PurposeLicense, "lic-1", pub); err != nil {
		f.Fatalf("register seed key: %v", err)
	}

	valid, err := Issue(License{
		Licensee: "acme", Plan: "enterprise", Features: []string{FeatureAirgapUpdates},
		IssuedAt: time.Now(), NotAfter: time.Now().Add(24 * time.Hour), KeyID: "lic-1",
	}, priv)
	if err != nil {
		f.Fatalf("issue seed token: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("not-a-token")
	f.Add("..")
	f.Add(valid + ".")
	f.Add("a." + valid)

	f.Fuzz(func(t *testing.T, token string) {
		st := Evaluate(token, reg, "", time.Now(), 14*24*time.Hour)
		if st.Grants() && st.State != StateActive && st.State != StateExpiringSoon {
			t.Fatalf("Grants() true for state %q, which should never grant", st.State)
		}
		// Only the one seed token (or a byte-identical resubmission) may ever validate
		// against this registry; anything else reaching Active/ExpiringSoon would mean a
		// signature check was bypassed.
		if st.Grants() && token != valid {
			t.Fatalf("token %q (not the seeded valid token) evaluated to a feature-granting state %q", token, st.State)
		}
	})
}

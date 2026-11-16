// Reachability-first fuzz harness for golang.org/x/text/secure/precis, the
// PRECIS implementation Keyorix uses to normalize identity names.
//
// Live callers (traced from reachgen, prov=request-body):
//   - internal/identity/identity.go:63  NewFoldedName  -> foldedProfile.String(raw)
//     foldedProfile = precis.NewFreeform(precis.LowerCase(), precis.Norm(norm.NFC))
//   - internal/identity/identity.go:102 NewAddressName -> addressProfile.String(raw)
//     addressProfile = precis.OpaqueString
//
// `raw` in both is an operator/attacker-supplied name (machine-identity name,
// address name) arriving on the API. These harnesses reconstruct the EXACT two
// profiles and fuzz them with arbitrary UTF-8.
//
// Oracle (sound): PRECIS enforcement is IDEMPOTENT and DETERMINISTIC
// (RFC 8264 §7 / RFC 8265). For a profile p and any input s:
//   - if p.String(s) succeeds with out, then p.String(out) must also succeed
//     and return out unchanged (enforcing an enforced string is a no-op);
//   - p.String(s) must be deterministic (same output on a second call);
//   - p.String must never panic.
//
// This is the invariant Keyorix relies on when it stores a folded name and
// later compares against a freshly-folded candidate: a value that folded once
// must fold to itself, or two "equal" names would mismatch on re-normalization.
//
// What this oracle does NOT verify:
//   - It does NOT check that the profile REJECTS the code points it should
//     (no disallowed-rune completeness check).
//   - It does NOT check collision behaviour: that two inputs which SHOULD fold
//     equal actually do (no fold-completeness/soundness of the mapping).
//   - It does NOT check the security of the mapping (confusables, bidi).
//   - It says nothing about identity.go's own wrapper logic (length limits,
//     emptiness) layered on top — only about precis.String itself.
package precishostile

import (
	"testing"
	"unicode/utf8"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
)

// foldedProfile mirrors internal/identity/identity.go's foldedProfile exactly.
var foldedProfile = precis.NewFreeform(precis.LowerCase(), precis.Norm(norm.NFC))

// addressProfile mirrors internal/identity/identity.go's addressProfile.
var addressProfile = precis.OpaqueString

func FuzzPrecisProfileIdempotent(f *testing.F) {
	f.Add("Admin")
	f.Add("PROD_KEY")
	f.Add(" leading space ")
	f.Add("café")               // combining vs precomposed (NFC)
	f.Add("ﬀ")                  // compatibility ligature
	f.Add("İstanbul")           // Turkish dotted-I casefold
	f.Add("Å")                 // A + combining ring -> Å under NFC
	f.Add(string([]byte{0xff})) // invalid UTF-8

	profiles := map[string]*precis.Profile{
		"folded":  foldedProfile,
		"address": addressProfile,
	}

	// PK2: resguard resource oracle (see resguard_precis_test.go). Meters the same
	// surface calibration does (both profiles' String enforcement).
	rgBudget, rgErr := resguard.LoadBudget(rgBudgetPath)
	rgHaveBudget := rgErr == nil
	rgProbe := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, s string) {
		c := rgProbe.Measure(len(s), func() { rgRun(s) })
		resguard.FeedCoverage(c)
		if rgHaveBudget {
			rgBudget.Check(t.Fatalf, c)
		}
		if !utf8.ValidString(s) {
			// precis legitimately errors on invalid UTF-8; such inputs can't
			// exercise idempotence. Still assert no panic by calling once.
			for _, p := range profiles {
				_, _ = p.String(s)
			}
			return
		}
		for name, p := range profiles {
			out, err := p.String(s)
			if err != nil {
				// Rejected input: fine. A rejected string must stay rejected
				// (determinism of the error decision).
				if _, err2 := p.String(s); err2 == nil {
					t.Fatalf("[%s] non-deterministic: rejected then accepted %q", name, s)
				}
				continue
			}
			// Determinism.
			if out2, err2 := p.String(s); err2 != nil || out2 != out {
				t.Fatalf("[%s] non-deterministic enforce of %q: (%q,%v) then (%q,%v)",
					name, s, out, err, out2, err2)
			}
			// Idempotence: re-enforcing the output is a no-op.
			reOut, reErr := applyAgain(p, out)
			if reErr != nil {
				t.Fatalf("[%s] enforced output %q (from %q) was then REJECTED: %v",
					name, out, s, reErr)
			}
			if reOut != out {
				t.Fatalf("[%s] NOT idempotent: %q -> %q -> %q", name, s, out, reOut)
			}
		}
	})
}

// applyAgain is the second application of the profile. It is factored out so
// the red-proof can plant a non-idempotent defect here in a scratch copy
// (e.g. `return strings.ToUpper(s), nil`) and watch the idempotence assertion
// fire while the unmodified path stays green.
func applyAgain(p *precis.Profile, s string) (string, error) {
	return p.String(s)
}

package core

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/identity"
)

// LIB-FUZZ-1 item 1 (keyorix's own wrapper logic on top of golang.org/x/text).
//
// domainAllowed decides whether an email's domain is on the membership allowlist
// (ADR-022: an install-wide boundary on who may hold an account). It is reached with
// the RAW email string the IdP asserted: SSO JIT (sso.go provisionSSOUser) and SCIM
// provisioning (scim.go), neither of which runs the ASCII emailRegex that the local
// create and invite paths run first. Right after that, the same raw string is folded
// by identity.NewFoldedName and the folded form is what decides which account the
// email IS (resolveSSOUser / GetUserByEmail match on email_folded).
//
// So the allowlist and the account lookup must agree on what a domain is. domainAllowed
// lower-cases with strings.ToLower (unicode.ToLower, simple mapping); identity folds
// with precis/cases (full mapping + NFC). They disagree on at least U+0130 (LATIN
// CAPITAL LETTER I WITH DOT ABOVE): ToLower gives ASCII "i", the identity fold gives
// "i" + U+0307, a different string and, as a DNS name, a different domain.
//
// Oracle (fail-open direction only): if domainAllowed accepts an email that the
// identity fold also accepts, then the folded domain of that email must equal the
// folded form of one of the allowlist entries. A domain the identity layer treats as
// different from every allowed domain must not pass the allowlist. The converse (a
// fold-equal domain that the allowlist refuses) fails closed and is not asserted.

// allowlistVerdict reports what the allowlist said, so the oracle can be pointed at a
// broken implementation in the red-proof test.
type allowlistFn func(allow []string, email string) bool

func realAllowlist(allow []string, email string) bool {
	c := &KeyorixCore{}
	c.SetMembershipDomainAllowlist(allow)
	return c.domainAllowed(email)
}

func foldedOrEmpty(s string) (string, bool) {
	n, err := identity.NewFoldedName(s)
	if err != nil {
		return "", false
	}
	return n.Folded(), true
}

func checkAllowlistAgreesWithFold(allow []string, email string, allowed allowlistFn) error {
	if len(allow) == 0 || !allowed(allow, email) {
		return nil
	}
	if _, ok := foldedOrEmpty(email); !ok {
		return nil // the identity layer refuses this email later; no account can be formed
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return fmt.Errorf("allowlist accepted %q which has no '@'", email)
	}
	fd, ok := foldedOrEmpty(domain)
	if !ok {
		return fmt.Errorf("allowlist accepted %q whose domain %q the identity fold refuses", email, domain)
	}
	for _, entry := range allow {
		if fe, eok := foldedOrEmpty(entry); eok && fe == fd {
			return nil
		}
	}
	// KNOWN OPEN (TestDomainAllowlist_KnownOpen_DotlessCaseMapping): the U+0130 class
	// only. Every other disagreement stays fatal.
	if strings.ContainsRune(domain, '\u0130') {
		return nil
	}
	return fmt.Errorf("allowlist %q accepted %q, but its domain folds to %q, which is not the fold of any allowlist entry: "+
		"strings.ToLower and the identity fold disagree on what this domain is", allow, email, fd)
}

var allowlistSeeds = []struct{ allow, email string }{
	{"example.com", "alice@example.com"},
	{"example.com", "Alice@EXAMPLE.COM"},
	{"Example.COM", "alice@example.com"},
	{"example.com", "alice@evil.com"},
	{"example.com", "attacker@evil.com@example.com"},
	{"inc.com", "alice@\u0130nc.com"},     // U+0130: ToLower -> "i", fold -> "i"+U+0307
	{"keyorix.com", "a@\u212aeyorix.com"}, // Kelvin sign: both fold it to "k"
	{"example.com", "alice@exam\u0000ple.com"},
	{"example.com", "alice@example.com\u200b"},
	{"example.com", "alice@exa\u00admple.com"},
	{"example.com", "alice@\uff45xample.com"}, // fullwidth e
	{"example.com", "alice@e\u0301xample.com"},
	{"caf\u00e9.com", "a@cafe\u0301.com"}, // NFC vs NFD domain
	{"\u03bf\u03b4\u03bf\u03c2.gr", "a@\u039f\u0394\u039f\u03a3.gr"},
	{"stra\u00dfe.de", "a@STRASSE.de"},
}

func FuzzDomainAllowlistAgreesWithFold(f *testing.F) {
	for _, s := range allowlistSeeds {
		f.Add(s.allow, s.email)
	}
	f.Fuzz(func(t *testing.T, entry, email string) {
		fuzzutil.Guard(t.Fatalf, "core.domainAllowed", func() {
			if err := checkAllowlistAgreesWithFold([]string{entry}, email, realAllowlist); err != nil {
				t.Errorf("ALLOWLIST/FOLD DISAGREEMENT: %v", err)
			}
		})
	})
}

// TestDomainAllowlist_KnownOpen_DotlessCaseMapping pins the disagreement the skip in
// checkAllowlistAgreesWithFold tolerates: with allowlist "inc.com", domainAllowed
// accepts "a@<U+0130>nc.com", whose identity fold is "i<U+0307>nc.com" (a different
// DNS name). It FAILS once domainAllowed compares through the identity fold: then
// delete this test and the skip. Routed to the coordinator as an open defect (see the
// LIB-FUZZ-1 report); this PR is test-only.
func TestDomainAllowlist_KnownOpen_DotlessCaseMapping(t *testing.T) {
	if !realAllowlist([]string{"inc.com"}, "a@\u0130nc.com") {
		t.Fatal("domainAllowed no longer accepts the U+0130 spelling: the known-open defect is fixed, remove this test and the tolerance in checkAllowlistAgreesWithFold")
	}
	if realAllowlist([]string{"inc.com"}, "a@i\u0307nc.com") {
		t.Fatal("known-open reproducer changed shape: the decomposed spelling is now accepted too")
	}
}

// ---- red-proof -----------------------------------------------------------------

// A wrong allowlist (accepts everything) must be caught, and the real one must be
// green on the ordinary seeds, so the oracle is neither vacuous nor always red.
func TestDomainAllowlistFoldOracle_RedGreen(t *testing.T) {
	acceptAll := func(_ []string, _ string) bool { return true }
	red := false
	for _, s := range allowlistSeeds {
		if checkAllowlistAgreesWithFold([]string{s.allow}, s.email, acceptAll) != nil {
			red = true
		}
	}
	if !red {
		t.Fatal("oracle stayed green on an allowlist that accepts every address")
	}
	for _, s := range allowlistSeeds[:5] { // the ordinary, ASCII shapes
		if err := checkAllowlistAgreesWithFold([]string{s.allow}, s.email, realAllowlist); err != nil {
			t.Errorf("real allowlist, seed %+v: %v", s, err)
		}
	}
}

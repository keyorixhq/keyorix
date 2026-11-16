package identity

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// LIB-FUZZ-1 item 1: oracles over golang.org/x/text as keyorix wraps it
// (NewFoldedName = precis Freeform+LowerCase+NFC, NewAddressName = precis
// OpaqueString, FoldForSearch = NFC + per-rune lower).
//
// Who reaches this and with what: NewFoldedName takes the user's own username and
// email (users.go buildUserForCreate; the ASCII charset regexes run first there),
// but ALSO the IdP-supplied email in SSO JIT provisioning (sso.go provisionSSOUser)
// and SCIM provisioning (scim.go), and the IdP displayName of a SCIM group
// (scim_groups.go): those strings are arbitrary Unicode chosen by whoever runs the
// IdP tenant, with no charset check before the fold. NewAddressName takes secret
// names and folder names. FoldForSearch takes the term of every list-filter query
// and, through the SQLite keyorix_fold function, the stored column.
//
// Every oracle below is a function returning an error (not a t.Fatalf) so that the
// red-proof tests can feed it a deliberately wrong implementation and show it goes
// red, without editing production code.
//
// What these oracles do NOT verify: that two visually confusable names (fullwidth vs
// ASCII, Cyrillic vs Latin) fold differently or equal. identity.go documents that NFC
// (not NFKC) is a decision; a confusables oracle would need a skeleton table, and
// asserting the documented choice would be a tautology.

// foldFn is NewFoldedName reduced to (folded, err), so the oracle can be pointed at
// a broken implementation.
type foldFn func(raw string) (string, error)

func realFold(raw string) (string, error) {
	n, err := NewFoldedName(raw)
	if err != nil {
		return "", err
	}
	if n.Display() != raw || n.String() != raw {
		return "", fmt.Errorf("Display()/String() changed the caller's text: %q -> %q", raw, n.Display())
	}
	return n.Folded(), nil
}

// maxFoldExpansion is the largest folded-bytes / raw-bytes ratio the fold may
// produce. NFC expands a few singletons 2x in bytes (U+0344, U+0F73, U+0F75, U+0F81)
// and full lower-casing expands U+0130 1.5x; the factors do not compound on one rune
// because the expanded NFC forms are already lower-case. 4x is the bound a caller may
// rely on: a length limit applied to the RAW name (len(raw) <= N) therefore bounds
// the folded column to 4N, and any column sized for N must be checked against the
// FOLDED length, not the raw one.
const maxFoldExpansion = 4

// checkFoldedNameOracles returns a description of the first violated property.
func checkFoldedNameOracles(raw string, fold foldFn) error {
	f1, err := fold(raw)
	if err != nil {
		return nil // a refusal is always a legal answer; equivalence is checked on accepts
	}

	// 1. The stored key is valid UTF-8 and not empty (the constructor promises both).
	if f1 == "" {
		return fmt.Errorf("accepted %q but folded to the empty string", raw)
	}
	if !utf8.ValidString(f1) {
		return fmt.Errorf("fold(%q) = %q is not valid UTF-8", raw, f1)
	}

	// 2. Size: the folded key is bounded by a constant multiple of the raw bytes.
	if len(f1) > maxFoldExpansion*len(raw) {
		return fmt.Errorf("fold(%q) is %d bytes from %d raw bytes (> %dx): a limit applied before folding does not bound the stored key",
			raw, len(f1), len(raw), maxFoldExpansion)
	}

	// 3. Idempotence: re-folding the stored key must give the same key, or the
	// uniqueness column and a later lookup of the stored value disagree.
	f2, err := fold(f1)
	if err != nil {
		return fmt.Errorf("fold(%q) = %q, but folding that stored key is refused: %v", raw, f1, err)
	}
	if f2 != f1 {
		return fmt.Errorf("fold is not idempotent: fold(%q) = %q, fold(fold) = %q", raw, f1, f2)
	}

	// 4. Canonical equivalence: the same text in another normalization form must be
	// the same identity (the whole point of #1642). Only meaningful for valid UTF-8.
	if utf8.ValidString(raw) {
		for _, form := range []struct {
			name string
			f    norm.Form
		}{{"NFC", norm.NFC}, {"NFD", norm.NFD}} {
			v := form.f.String(raw)
			fv, verr := fold(v)
			if verr != nil {
				return fmt.Errorf("%q is accepted but its %s form %q is refused: %v", raw, form.name, v, verr)
			}
			if fv != f1 {
				return fmt.Errorf("canonically equivalent inputs fold differently: fold(%q) = %q but fold(%s form %q) = %q",
					raw, f1, form.name, v, fv)
			}
		}
	}

	// 5. ASCII case: for pure-ASCII input the fold is exactly strings.ToLower.
	if isASCII(raw) {
		if want := strings.ToLower(raw); f1 != want {
			return fmt.Errorf("ASCII input %q folded to %q, want %q", raw, f1, want)
		}
	}
	return nil
}

// addrFn is NewAddressName reduced to (value, err).
type addrFn func(raw string) (string, error)

func realAddr(raw string) (string, error) {
	n, err := NewAddressName(raw)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// checkAddressNameOracles: secret names are NFC-normalized and case-preserving.
func checkAddressNameOracles(raw string, addr addrFn) error {
	a1, err := addr(raw)
	if err != nil {
		return nil
	}
	if !utf8.ValidString(a1) {
		return fmt.Errorf("address(%q) = %q is not valid UTF-8", raw, a1)
	}
	if len(a1) > maxFoldExpansion*len(raw) {
		return fmt.Errorf("address(%q) is %d bytes from %d raw bytes (> %dx)", raw, len(a1), len(raw), maxFoldExpansion)
	}
	a2, err := addr(a1)
	if err != nil {
		return fmt.Errorf("address(%q) = %q, but re-normalizing that stored name is refused: %v", raw, a1, err)
	}
	if a2 != a1 {
		return fmt.Errorf("address normalization is not idempotent: %q -> %q -> %q", raw, a1, a2)
	}
	if utf8.ValidString(raw) {
		for _, form := range []norm.Form{norm.NFC, norm.NFD} {
			v := form.String(raw)
			av, verr := addr(v)
			if verr != nil {
				return fmt.Errorf("%q accepted but its normalization form %q refused: %v", raw, v, verr)
			}
			if av != a1 {
				return fmt.Errorf("canonically equivalent secret names differ: %q -> %q, %q -> %q", raw, a1, v, av)
			}
		}
	}
	// PROD_KEY and prod_key must stay distinct: the ASCII-only name is stored verbatim.
	if isASCII(raw) && !strings.ContainsAny(raw, " ") && a1 != raw {
		return fmt.Errorf("ASCII secret name %q was rewritten to %q (address names must not be folded or altered)", raw, a1)
	}
	return nil
}

// searchFn is FoldForSearch.
type searchFn func(string) string

// checkSearchFoldOracles: the list-filter fold. lo/hi pick a rune-aligned fragment.
func checkSearchFoldOracles(raw string, lo, hi uint16, fold searchFn) error {
	f1 := fold(raw)
	if utf8.ValidString(raw) && !utf8.ValidString(f1) {
		return fmt.Errorf("FoldForSearch(%q) = %q is not valid UTF-8", raw, f1)
	}
	if len(f1) > maxFoldExpansion*len(raw) {
		return fmt.Errorf("FoldForSearch(%q) is %d bytes from %d raw bytes (> %dx)", raw, len(f1), len(raw), maxFoldExpansion)
	}
	if f2 := fold(f1); f2 != f1 {
		// KNOWN OPEN (TestFoldForSearch_KnownOpen_LowerResultNotNFC): lower-casing an
		// NFC string can leave it non-NFC ("Y"+U+030A has no precomposed capital, its
		// lower-case form composes to U+1E99). Skip ONLY the case where the second
		// pass differs from the first by NFC re-composition and nothing else, so every
		// other source of non-idempotence stays fatal.
		if !(!norm.NFC.IsNormalString(f1) && f2 == norm.NFC.String(f1)) {
			return fmt.Errorf("FoldForSearch is not idempotent: %q -> %q -> %q", raw, f1, f2)
		}
	}
	if isASCII(raw) {
		if want := strings.ToLower(raw); f1 != want {
			return fmt.Errorf("ASCII input %q: FoldForSearch = %q, want %q", raw, f1, want)
		}
	}
	// A search term that is a fragment of a stored name must find that name. The
	// stored column is NFC (every write passes through the constructor), and a term
	// the user types is a rune-aligned fragment of it. Fragments that are not
	// themselves NFC (a cut through a combining sequence) are skipped: those are
	// legitimately a different string.
	if utf8.ValidString(raw) {
		stored := norm.NFC.String(raw)
		rs := []rune(stored)
		if len(rs) > 0 {
			a, b := int(lo)%(len(rs)+1), int(hi)%(len(rs)+1)
			if a > b {
				a, b = b, a
			}
			frag := string(rs[a:b])
			if frag != "" && norm.NFC.IsNormalString(frag) {
				if !strings.Contains(fold(stored), fold(frag)) {
					return fmt.Errorf("search fold loses a fragment: FoldForSearch(%q)=%q does not contain FoldForSearch(%q)=%q",
						stored, fold(stored), frag, fold(frag))
				}
			}
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// identitySeeds are inputs that reach the interesting branches of the real code, not
// only the happy path: precomposed vs decomposed, stacked/reorderable marks, the
// NFC-expanding singletons, the characters whose simple and full lower-casing
// differ (U+0130), Kelvin/Ohm/Angstrom singletons, final sigma, ligatures, fullwidth,
// bidi override and control characters (which PRECIS refuses), and invalid UTF-8.
var identitySeeds = []string{
	"admin", "Admin", "ADMIN role name", "Passsword", "SSS", "alice@example.com", "Alice@Example.COM",
	"caf\u00e9", "cafe\u0301", "e\u0301\u0323", "e\u0323\u0301", "\u1ea0\u030a\u0300\u0301\u0302\u0303",
	"\u0344", "\u0f73", "\u0f75", "\u0f81", "\ufb1d",
	"\u0130stanbul", "x@\u0130nc.com", "\u212a", "x@\u212aeyorix.com", "\u2126", "\u212b",
	"\u039f\u0394\u039f\u03a3", "\u03bf\u03b4\u03bf\u03c2", "\u03bf\u03b4\u03bf\u03c3", "\u0391\u03a3\u0391", "\u00df", "\u1e9e", "\ufb01", "\u2167", "\u2460",
	"\uff41\uff44\uff4d\uff49\uff4e", "\u202eadmin", "ad\u0000min", "ad\tmin", "a b", "a\u00a0b", "a\u3000b",
	"\u1100\u1161\u11a8", "\uac01", "\ud55c", "\u65e5\u672c",
	"\xff\xfe", "ab\xc3", "",
}

func FuzzFoldedNameOracles(f *testing.F) {
	for _, s := range identitySeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		fuzzutil.Guard(t.Fatalf, "identity.NewFoldedName", func() {
			if err := checkFoldedNameOracles(raw, realFold); err != nil {
				t.Errorf("FOLD ORACLE: %v", err)
			}
		})
	})
}

func FuzzAddressNameOracles(f *testing.F) {
	for _, s := range identitySeeds {
		f.Add(s)
	}
	f.Add("PROD_KEY")
	f.Add("prod_key")
	f.Fuzz(func(t *testing.T, raw string) {
		fuzzutil.Guard(t.Fatalf, "identity.NewAddressName", func() {
			if err := checkAddressNameOracles(raw, realAddr); err != nil {
				t.Errorf("ADDRESS ORACLE: %v", err)
			}
		})
	})
}

func FuzzSearchFoldOracles(f *testing.F) {
	for _, s := range identitySeeds {
		f.Add(s, uint16(0), uint16(3))
		f.Add(s, uint16(1), uint16(2))
	}
	f.Fuzz(func(t *testing.T, raw string, lo, hi uint16) {
		fuzzutil.Guard(t.Fatalf, "identity.FoldForSearch", func() {
			if err := checkSearchFoldOracles(raw, lo, hi, FoldForSearch); err != nil {
				t.Errorf("SEARCH-FOLD ORACLE: %v", err)
			}
		})
	})
}

// ---- red-proof: the oracles must fire on a wrong implementation ----------------
//
// Each case is a plausible regression of the real code. The test first proves the
// REAL implementation is green on every seed (so the oracle is not always-red), then
// that each broken one is red on at least one seed.

// TestFoldForSearch_KnownOpen_LowerResultNotNFC pins the defect the skip in
// checkSearchFoldOracles tolerates. FoldForSearch is NFC-then-lower, and lower-casing
// does not preserve NFC: the capital "Y"+U+030A has no precomposed form, so it stays
// decomposed through NFC, and its lower-case "y"+U+030A is the canonical decomposition
// of U+1E99. A name stored as "Y"+U+030A and a user searching for the precomposed
// U+1E99 therefore fold to different strings, and the search misses the name. The
// PostgreSQL expression translate(LOWER(normalize(col, NFC)), ...) has the same shape.
// Impact: a list filter misses a row for such letters; not an authz or uniqueness path
// (searchfold.go says so). The fix is a final NFC pass on both sides, in Go and in SQL.
//
// This test FAILS once the defect is fixed: delete it and the skip in
// checkSearchFoldOracles in the same change.
func TestFoldForSearch_KnownOpen_LowerResultNotNFC(t *testing.T) {
	stored := FoldForSearch("Y\u030a")
	typed := FoldForSearch("\u1e99")
	if stored == typed {
		t.Fatalf("FoldForSearch now agrees (%q): the known-open defect is fixed, remove this test and the tolerance in checkSearchFoldOracles", stored)
	}
	if stored != "y\u030a" || typed != "\u1e99" {
		t.Fatalf("known-open reproducer changed shape: FoldForSearch(Y+U+030A)=%q FoldForSearch(U+1E99)=%q", stored, typed)
	}
}

func TestFoldOracles_GreenOnRealImplementation(t *testing.T) {
	for _, s := range identitySeeds {
		if err := checkFoldedNameOracles(s, realFold); err != nil {
			t.Errorf("fold, seed %q: %v", s, err)
		}
		if err := checkAddressNameOracles(s, realAddr); err != nil {
			t.Errorf("address, seed %q: %v", s, err)
		}
		if err := checkSearchFoldOracles(s, 0, 3, FoldForSearch); err != nil {
			t.Errorf("search, seed %q: %v", s, err)
		}
	}
}

func TestFoldOracles_RedOnBrokenImplementations(t *testing.T) {
	broken := map[string]foldFn{
		// lower-case only, no normalization: NFC/NFD forms of one name differ.
		"no-normalization": func(raw string) (string, error) { return strings.ToLower(raw), nil },
		// a "normalizing" fold that is applied once and is not stable.
		"non-idempotent": func(raw string) (string, error) {
			return strings.ReplaceAll(norm.NFC.String(strings.ToLower(raw)), "ss", "s"), nil
		},
		// expands past any length limit that was checked on the raw name.
		"expands": func(raw string) (string, error) {
			return strings.Repeat(norm.NFC.String(strings.ToLower(raw)), 5), nil
		},
		// truncates in the middle of a rune.
		"invalid-utf8": func(raw string) (string, error) {
			s := norm.NFC.String(strings.ToLower(raw))
			if len(s) > 1 && s[len(s)-1] >= utf8.RuneSelf {
				return s[:len(s)-1], nil
			}
			return s, nil
		},
		// folds ASCII wrongly (upper-cases instead of lower-casing).
		"wrong-case": func(raw string) (string, error) { return strings.ToUpper(norm.NFC.String(raw)), nil },
		// accepts the NFC form but refuses a decomposed input.
		"refuses-nfd": func(raw string) (string, error) {
			if raw != norm.NFC.String(raw) {
				return "", fmt.Errorf("not NFC")
			}
			return strings.ToLower(raw), nil
		},
	}
	for name, bad := range broken {
		red := false
		for _, s := range identitySeeds {
			if checkFoldedNameOracles(s, bad) != nil {
				red = true
				break
			}
		}
		if !red {
			t.Errorf("fold oracle stayed GREEN on the %q implementation: it cannot detect that regression", name)
		}
	}

	brokenAddr := map[string]addrFn{
		"folds-case": func(raw string) (string, error) { return strings.ToLower(norm.NFC.String(raw)), nil },
		"no-nfc":     func(raw string) (string, error) { return raw, nil },
	}
	for name, bad := range brokenAddr {
		red := false
		for _, s := range append([]string{"PROD_KEY"}, identitySeeds...) {
			if checkAddressNameOracles(s, bad) != nil {
				red = true
				break
			}
		}
		if !red {
			t.Errorf("address oracle stayed GREEN on the %q implementation", name)
		}
	}

	brokenSearch := map[string]searchFn{
		"non-idempotent": func(s string) string {
			return strings.ReplaceAll(strings.ToLower(norm.NFC.String(s)), "ss", "s")
		},
		"expands": func(s string) string { return strings.Repeat(strings.ToLower(norm.NFC.String(s)), 5) },
	}
	for name, bad := range brokenSearch {
		red := false
		for _, s := range identitySeeds {
			for _, w := range [][2]uint16{{0, 3}, {1, 2}, {2, 5}} {
				if checkSearchFoldOracles(s, w[0], w[1], bad) != nil {
					red = true
				}
			}
		}
		if !red {
			t.Errorf("search-fold oracle stayed GREEN on the %q implementation", name)
		}
	}
}

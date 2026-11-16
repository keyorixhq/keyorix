package identity

// DF1 Oracle F — Keyorix identity fold vs the RFC 8265 PRECIS UsernameCaseMapped profile
// (golang.org/x/text/secure/precis) and x/text NFKC width mapping.
//
// Keyorix normalises usernames / role / group / project names with a CUSTOM profile
// (foldedProfile = precis.NewFreeform(LowerCase, NFC); see identity.go). An external
// identity source — an OIDC/SAML IdP, a SCIM provisioning client, a directory — that
// follows RFC 8265 uses precis.UsernameCaseMapped, whose IdentifierClass applies width
// mapping (fullwidth→ASCII) and full case folding and rejects spaces/ligatures/numerals.
// The dangerous shape: the IdP decides "user X == user Y" (or "this is a valid username")
// under one normalisation while Keyorix stores/looks-up the principal under another — a
// shadow-admin or account-collision. This oracle feeds the SAME pair of strings to both
// normalisers and fails on an equality/acceptance disagreement that is not a documented
// Keyorix design choice.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - It compares the precis UsernameCaseMapped profile, NOT a specific IdP's actual
//     normalisation. Real IdPs vary; UsernameCaseMapped is the RFC 8265 reference, the
//     closest thing to a standard. A disagreement here is "Keyorix vs the standard", which
//     is the right proxy for "Keyorix vs a standards-following external system" but is not
//     proof any particular IdP behaves this way.
//   - It does NOT drive the storage layer or the SQL fold (keyorix_fold / search_fold.go):
//     it compares the Go-side normalisers only. Whether the DB column fold matches
//     NewFoldedName.Folded() is a separate invariant (internal/storage/store).
//   - AddressName (secret names, case-preserving) and FoldForSearch (list-filter fold) are
//     out of scope; this oracle is about the FoldedName principal-identity key only.
//   - idna/punycode of an email domain part is NOT compared here (noted as follow-up in the
//     DF1 report); the x/text axis is covered via precis + NFKC.

import (
	"testing"

	"golang.org/x/text/cases"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"
)

// foldVerdict runs a string through a normaliser; ok=false means it was rejected.
func keyorixFold(s string) (key string, ok bool) {
	v, err := foldedProfile.String(s)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

func rfc8265Fold(s string) (key string, ok bool) {
	v, err := precis.UsernameCaseMapped.String(s)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

type foldMismatch struct {
	key    string
	detail string
	a, b   string
}

var caseFolder = cases.Fold()

// foldCompare is the pure oracle core over an ordered pair (a, b).
func foldCompare(a, b string) *foldMismatch {
	ka, kaOK := keyorixFold(a)
	kb, kbOK := keyorixFold(b)
	ua, uaOK := rfc8265Fold(a)
	ub, ubOK := rfc8265Fold(b)

	// ACCEPTANCE disagreements (per single string a; b handled symmetrically by the fuzzer
	// also calling with swapped args via its own seeds). We only need to look at `a` here:
	switch {
	case kaOK && !uaOK:
		return &foldMismatch{key: "keyorix-accepts-rfc8265-rejects", detail: "Keyorix accepts a username RFC 8265 rejects", a: a, b: ""}
	case !kaOK && uaOK:
		return &foldMismatch{key: "keyorix-rejects-rfc8265-accepts", detail: "Keyorix rejects a username RFC 8265 accepts", a: a, b: ""}
	}
	if kbOK != ubOK {
		if kbOK {
			return &foldMismatch{key: "keyorix-accepts-rfc8265-rejects", detail: "Keyorix accepts a username RFC 8265 rejects", a: b, b: ""}
		}
		return &foldMismatch{key: "keyorix-rejects-rfc8265-accepts", detail: "Keyorix rejects a username RFC 8265 accepts", a: b, b: ""}
	}

	// EQUALITY disagreement: both normalisers accepted both strings, but disagree on whether
	// a and b denote the same principal.
	if !kaOK || !kbOK { // at least one rejected by both — no equality key to compare
		return nil
	}
	kSame := ka == kb
	uSame := ua == ub
	if kSame == uSame {
		return nil
	}
	return &foldMismatch{key: classifyFoldEqDiff(a, b, kSame), detail: "equality verdict differs (Keyorix-same=" +
		boolStr(kSame) + " RFC8265-same=" + boolStr(uSame) + ")", a: a, b: b}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// classifyFoldEqDiff names the Unicode mechanism behind an equality disagreement. Order
// matters: the narrower explanation (case folding, no width needed) is checked before the
// wider one (needs NFKC width mapping).
//
// Width mapping is allowlisted in ONE direction only: Keyorix keeps the two names distinct
// while RFC 8265 treats them as the same (kSame=false). The opposite (Keyorix merges what
// the RFC keeps apart, an account-collision direction) gets its own key, not allowlisted.
func classifyFoldEqDiff(a, b string, kSame bool) string {
	switch {
	case caseFolder.String(norm.NFC.String(a)) == caseFolder.String(norm.NFC.String(b)):
		// full case folding (ß→ss, final sigma, …) collapses them without any width
		// mapping — Keyorix's one-way LowerCase does not.
		return "casefold-vs-lowercase"
	case caseFolder.String(norm.NFKC.String(a)) == caseFolder.String(norm.NFKC.String(b)):
		// width/compatibility mapping (fullwidth ＡＤＭＩＮ vs ADMIN) collapses under NFKC
		// (+fold) but not under Keyorix's NFC.
		if kSame {
			return "width-compat-mapping-keyorix-same"
		}
		return "width-compat-mapping"
	default:
		return "fold-equality-unexplained"
	}
}

var foldDiffAllow = func() *allowlist {
	return newAllowlist(
		expectedDiff{
			key: "keyorix-accepts-rfc8265-rejects",
			reason: "Keyorix uses a deliberately permissive precis Freeform profile (identity.go: " +
				"spaces are allowed because existing usernames/role/group/project names contain " +
				"them; UsernameCaseMapped's IdentifierClass rejects spaces, ligatures, roman " +
				"numerals, circled digits, trailing space, etc.). So Keyorix accepts many strings " +
				"RFC 8265 refuses. This is a documented design choice, recorded here. SECURITY NOTE " +
				"(report Finding F-2): the extra-permissive surface is a confusable/spoofing vector " +
				"— two visually similar principals Keyorix keeps distinct. RED-PROVEN by `ﬀ`.",
		},
		expectedDiff{
			key: "width-compat-mapping",
			reason: "Keyorix normalises with NFC; RFC 8265 UsernameCaseMapped additionally applies " +
				"width mapping (NFKC-class), so fullwidth ＡＤＭＩＮ folds to `admin` under the RFC " +
				"profile but stays a distinct `ａｄｍｉｎ` under Keyorix. A standards-following IdP would " +
				"treat ＡＤＭＩＮ and admin as the SAME user; Keyorix stores two principals. Documented " +
				"(NFC vs NFKC is the deliberate Keyorix choice) but a genuine shadow-admin concern — " +
				"report Finding F-1. RED-PROVEN by (`ＡＤＭＩＮ`,`admin`).",
		},
	)
	// NOTE: there is deliberately NO "casefold-vs-lowercase" entry. RFC 8265
	// UsernameCaseMapped also lowercases rather than full-folds (confirmed empirically: `ß`
	// stays `ß` under both), so a casefold-only equality split against this reference does
	// not arise. The classifier still NAMES that mechanism, so if a future reference change
	// surfaces one it fails the fuzzer as an unallowlisted finding rather than hiding.
}

// seed pairs; the fuzzer mutates both strings.
var foldSeeds = [][2]string{
	{"admin", "admin"},
	{"ADMIN", "admin"},
	{"café", "café"},
	{"ＡＤＭＩＮ", "admin"},         // width-compat-mapping (allowlisted, red-proof)
	{"ﬀ", "ff"},                // keyorix-accepts-rfc8265-rejects (ligature)
	{"ß", "ss"},                // both keep distinct (agree) / casefold seed
	{"role name", "role name"}, // space: Keyorix accepts, RFC rejects
	{"Σ", "σ"},                 // sigma case
	{"a", "b"},
}

func FuzzIdentityFoldVsPrecis(f *testing.F) {
	for _, s := range foldSeeds {
		f.Add(s[0], s[1])
	}
	allow := foldDiffAllow()
	f.Fuzz(func(t *testing.T, a, b string) {
		m := foldCompare(a, b)
		if m == nil {
			return
		}
		if allow.allows(m.key) {
			return
		}
		t.Fatalf("DIFFERENTIAL [Keyorix fold vs RFC 8265 precis] (key=%s): %s\n  a=%q b=%q", m.key, m.detail, m.a, m.b)
	})
}

func TestFoldDiffAllowlistNoDead(t *testing.T) {
	allow := foldDiffAllow()
	for _, s := range foldSeeds {
		if m := foldCompare(s[0], s[1]); m != nil {
			allow.allows(m.key)
		}
		// also the swapped order, so single-string acceptance classes fire from either slot
		if m := foldCompare(s[1], s[0]); m != nil {
			allow.allows(m.key)
		}
	}
	allow.assertNoDeadEntries(t)
}

func TestFoldCompare_RedGreen(t *testing.T) {
	// GREEN: plain ASCII case-insensitive equality agrees.
	for _, g := range [][2]string{{"ADMIN", "admin"}, {"admin", "admin"}, {"café", "café"}, {"a", "b"}} {
		if m := foldCompare(g[0], g[1]); m != nil {
			t.Fatalf("GREEN pair %q/%q flagged: key=%s %s", g[0], g[1], m.key, m.detail)
		}
	}
	// RED (natural, allowlisted but must be DETECTED): fullwidth width-compat collision.
	if m := foldCompare("ＡＤＭＩＮ", "admin"); m == nil {
		t.Fatal("RED: width-compat collision not detected")
	} else if m.key != "width-compat-mapping" {
		t.Fatalf("RED: width-compat misclassified as %q", m.key)
	}
	// RED (natural): Keyorix accepts a ligature RFC 8265 rejects.
	if m := foldCompare("ﬀ", "x"); m == nil || m.key != "keyorix-accepts-rfc8265-rejects" {
		t.Fatalf("RED: permissiveness divergence not detected/classified (got %v)", m)
	}
	// A genuinely-unexplained equality divergence must NOT be allowlisted (the fuzzer must
	// be able to fail on it).
	if foldDiffAllow().allows("fold-equality-unexplained") {
		t.Fatal("RED: fold-equality-unexplained must not be on the allowlist")
	}
	if foldDiffAllow().allows("keyorix-rejects-rfc8265-accepts") {
		t.Fatal("RED: keyorix-rejects-rfc8265-accepts must not be on the allowlist")
	}
}

package identity

// FuzzIdentityNormalizationStable fuzzes NewFoldedName / NewAddressName (#1642), the
// constructor-enforced Unicode normalization for identity-bearing strings (usernames, role/group/
// project names; secret names). The value each produces is used as the storage/comparison key, so
// the security-critical property is a FIXED POINT: normalising an already-normalised value must
// return it unchanged. If it does not, the same identity stored on write fails to match itself on a
// lookup that re-normalises — exactly the not-found-vs-collision hazard the package exists to close,
// and a Unicode input whose normalisation is not idempotent is a real auth-confusion bug.
//
// Sound metamorphic invariants (assert an equality a correct normaliser always satisfies, so they
// cannot false-positive), plus never-panic on hostile Unicode (a panic crashes the fuzzer):
//
//   - FoldedName: NewFoldedName(x) ok => its Folded() form re-folds to itself, and is not rejected.
//   - AddressName: NewAddressName(x) ok => its normalised value re-normalises to itself, not rejected.

import "testing"

func FuzzIdentityNormalizationStable(f *testing.F) {
	for _, s := range []string{
		"admin", "Admin", "ADMIN", "role name", "project-x",
		"prod_key", "PROD_KEY", "  spaced  ",
		"café", "café", // NFC vs NFD forms of café
		"ﬁle",     // ﬁ ligature
		"Å", "Å", // A + combining ring vs Å
		"straße", "STRASSE", // ß case-fold expansion
		"a\u200bb", "Åadmin", // zero-width space, Kelvin sign
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if fn, err := NewFoldedName(raw); err == nil {
			fn2, err2 := NewFoldedName(fn.Folded())
			if err2 != nil {
				t.Fatalf("FOLD UNSTABLE: NewFoldedName(%q) folded to %q, which is itself REJECTED on re-normalisation: %v", raw, fn.Folded(), err2)
			}
			if fn2.Folded() != fn.Folded() {
				t.Fatalf("FOLD NOT IDEMPOTENT: NewFoldedName(%q).Folded()=%q but re-folding yields %q — a lookup keyed on the folded value would miss", raw, fn.Folded(), fn2.Folded())
			}
		}
		if an, err := NewAddressName(raw); err == nil {
			an2, err2 := NewAddressName(an.String())
			if err2 != nil {
				t.Fatalf("ADDRESS UNSTABLE: NewAddressName(%q) normalised to %q, which is itself REJECTED on re-normalisation: %v", raw, an.String(), err2)
			}
			if an2.String() != an.String() {
				t.Fatalf("ADDRESS NOT IDEMPOTENT: NewAddressName(%q).String()=%q but re-normalising yields %q", raw, an.String(), an2.String())
			}
		}
	})
}

package identity

import "testing"

// TestNewFoldedName_RejectsInvisibleAndFormatRunes pins that both profiles refuse the
// invisible characters that would let two names render identically: zero-width space
// and joiners, word joiner, soft hyphen, variation selectors, tag characters and the
// BOM (PRECIS IgnorableCodePoints / contextual rules). Only control characters and one
// bidi override were pinned before. A hand-rolled replacement such as
// norm.NFC.String(strings.ToLower(raw)) would accept all of these, and the stored
// folded key would then differ from the visible name.
func TestNewFoldedName_RejectsInvisibleAndFormatRunes(t *testing.T) {
	for _, s := range []string{
		"admin\u200b", // zero-width space
		"ad\u200cmin", // zero-width non-joiner
		"admin\u200d", // zero-width joiner
		"ad\u2060min", // word joiner
		"admin\u00ad", // soft hyphen
		"admin\ufe0f", // variation selector-16
		"admin\U000e0041",
		"\ufeffadmin", // BOM
		"admin\u2066", // left-to-right isolate
		"admin\u061c", // Arabic letter mark
	} {
		if n, err := NewFoldedName(s); err == nil {
			t.Errorf("NewFoldedName(%+q) accepted, folded %+q", s, n.Folded())
		}
		if n, err := NewAddressName(s); err == nil {
			t.Errorf("NewAddressName(%+q) accepted, value %+q", s, n.String())
		}
	}
}

// TestNewFoldedName_FoldsCompatibilityCaseForms pins case folding beyond ASCII: the
// Kelvin and Ohm signs, Angstrom sign, titlecase digraphs and capital sharp s fold to the
// same key as their ordinary lowercase letters, so they cannot register as a distinct
// principal next to the plain name.
func TestNewFoldedName_FoldsCompatibilityCaseForms(t *testing.T) {
	for _, tc := range [][2]string{
		{"\u212aey", "key"},          // KELVIN SIGN
		{"\u2126mega", "\u03c9mega"}, // OHM SIGN
		{"\u212bngstrom", "\u00e5ngstrom"},
		{"\u01c5", "\u01c6"}, // titlecase dz with caron
		{"\u1e9e", "\u00df"}, // capital sharp s
		{"\u03a3\u0399\u0393\u039c\u0391", "\u03c3\u03b9\u03b3\u03bc\u03b1"},
	} {
		a, err := NewFoldedName(tc[0])
		if err != nil {
			t.Fatalf("NewFoldedName(%+q): %v", tc[0], err)
		}
		b, err := NewFoldedName(tc[1])
		if err != nil {
			t.Fatalf("NewFoldedName(%+q): %v", tc[1], err)
		}
		if a.Folded() != b.Folded() {
			t.Errorf("NewFoldedName(%+q).Folded() = %+q, NewFoldedName(%+q).Folded() = %+q; want equal", tc[0], a.Folded(), tc[1], b.Folded())
		}
	}
}

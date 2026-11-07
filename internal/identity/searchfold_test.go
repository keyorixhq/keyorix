package identity

import "testing"

func TestFoldForSearch(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"ABC", "abc"},
		{"ÄÖ", "äö"},
		{"a\u0308", "ä"},       // NFC
		{"ΟΔΟΣ", "οδοσ"},       // ΟΔΟΣ -> οδοσ
		{"οδος", "οδοσ"},       // οδος -> οδοσ
		{"İ", "i"},             // İ
		{"ß", "ß"},             // ß unchanged
		{"ẞ", "ß"},             // ẞ -> ß
		{"100%_\\", "100%_\\"}, // LIKE metacharacters untouched
	}
	for _, c := range cases {
		if got := FoldForSearch(c.in); got != c.want {
			t.Errorf("FoldForSearch(%q) = %q, want %q", c.in, got, c.want)
		}
		if again := FoldForSearch(FoldForSearch(c.in)); again != c.want {
			t.Errorf("FoldForSearch not idempotent for %q: %q", c.in, again)
		}
	}
}

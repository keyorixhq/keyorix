package identity

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// FoldForSearch returns s in the form used for case-insensitive substring
// search over display columns (secret names, usernames, emails).
//
// It is NFC-normalized, lower-cased rune by rune (unicode.ToLower, the simple
// one-to-one mapping), and maps the Greek final sigma to the medial sigma so
// that "ΟΔΟΣ", "οδοσ" and "οδος" are all the same search key.
//
// This is deliberately context-free and locale-independent, unlike
// NewFoldedName (which is a storage-key fold with contextual rules such as
// final-sigma selection). A search term is a fragment of a name, and a
// contextual fold of a fragment can disagree with the fold of the whole
// name ("ΑΣ" inside "ΑΣΑ"). Both sides of the comparison are folded with
// this one function: Go-side for the search term, and in SQL for the column
// (the keyorix_fold function on SQLite, translate(LOWER(normalize(col, NFC)),
// ...) on PostgreSQL, see internal/storage/store/search_fold.go).
//
// It is not a security or uniqueness boundary: it only decides which rows a
// list filter returns.
func FoldForSearch(s string) string {
	s = norm.NFC.String(s)
	return strings.Map(func(r rune) rune {
		if r == 'ς' {
			return 'σ'
		}
		return unicode.ToLower(r)
	}, s)
}

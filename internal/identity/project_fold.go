package identity

// FoldProjectName returns the comparison form of a project name: the
// NFC-normalized, case-folded value NewFoldedName produces, stored in
// projects.name_folded and backing the unique index on live project names.
//
// Unlike NewFoldedName it never fails. A name the PRECIS profile rejects (a
// control or bidi character, or an empty string) can only reach storage through
// a path that skips the identifier validation core applies to every project
// create and rename; it falls back to FoldForSearch, which is total and
// deterministic, so such a row still gets a stable value and the migration
// never refuses an upgrade over the shape of one name. Computed in Go and
// stored, so SQLite and PostgreSQL enforce identical uniqueness whatever their
// SQL LOWER() does.
func FoldProjectName(raw string) string {
	if n, err := NewFoldedName(raw); err == nil {
		return n.Folded()
	}
	return FoldForSearch(raw)
}

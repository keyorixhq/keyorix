package backupfmt

// HistoricalReference names one column that references a row which may
// legitimately no longer exist: the row is an immutable historical record, so
// it must outlive the row it points at. CheckDanglingReferences skips exactly
// these (table, column) pairs and nothing else (#3085); every other reference
// stays strictly checked.
//
// Adding an entry is a decision, not a convenience: the column must be one a
// purge or delete is NOT allowed to rewrite. A mutable table is cascaded by the
// purge instead (internal/storage/store/local_purge_secret_refs.go), and
// TestSecretReferencesAreClassified fails for a column that is in neither list.
type HistoricalReference struct {
	Table  string
	Column string
	Why    string
}

var historicalReferences = []HistoricalReference{
	{
		Table: "audit_events", Column: "secret_node_id",
		Why: "audit_events is append-only and hash-chained: a purge must not delete or rewrite an audit row " +
			"(audit-before-disclosure), so the row keeps naming the secret it recorded",
	},
	{
		Table: "access_review_items", Column: "secret_id",
		Why: "an access-review item is a snapshot of the grants at the time the campaign opened, kept for the " +
			"recertification record; the secret may be purged after the campaign without changing what was reviewed",
	},
}

// HistoricalReferences returns the columns CheckDanglingReferences skips.
func HistoricalReferences() []HistoricalReference {
	return append([]HistoricalReference(nil), historicalReferences...)
}

func isHistoricalReference(table, column string) bool {
	for _, h := range historicalReferences {
		if h.Table == table && h.Column == column {
			return true
		}
	}
	return false
}

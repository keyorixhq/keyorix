package backupfmt

import "time"

// FormatVersion is v2's manifest format version -- restore refuses any
// FormatVersion it doesn't recognize (design-b3-backup-v2.md §3.6), the same
// guard v1's backupFormatVersion const already provides for the old
// physical-format archives (server/admin's own const, kept as-is there;
// this is the logical format's independent guard).
const FormatVersion = 2

// Backend names the archive's format explicitly, replacing v1's single
// "sqlite" string (design §3.6) -- logical-v1 archives restore into either
// backend (§3.1), so "backend" here describes the ARCHIVE FORMAT, not which
// database produced it.
const Backend = "logical-v1"

// Manifest is the archive's MANIFEST.json (v2). Every field except
// Signature is covered by H2's manifest HMAC once that lands (design §5.4);
// Signature itself is added by H2, not here.
type Manifest struct {
	FormatVersion int       `json:"format_version"`
	Backend       string    `json:"backend"`
	CreatedAt     time.Time `json:"created_at"`
	// SchemaEpoch is the source binary's currentSchemaEpoch (ADR-097) at
	// backup time -- restore refuses a backup taken on a newer schema epoch
	// than it understands, reusing checkSchemaEpoch's exact existing
	// refusal logic (design §3.5), so a partially-understood schema is
	// never silently misread.
	SchemaEpoch int `json:"schema_epoch"`
	// Tables is written in the exact order data was (and will be, on
	// restore) loaded -- RestoreOrder()'s own derived topological order
	// (design §3.4) -- not re-sorted by name or anything else.
	Tables []TableEntry `json:"tables"`
	// KeyFiles reuses v1's per-file checksum shape (server/admin's
	// backupFileEntry) verbatim -- key-material handling is unchanged by
	// the logical-format switch, only the database payload's shape changes.
	KeyFiles []KeyFileEntry `json:"key_files"`
	// AuditHighWater is the source install's raw
	// "audit_checkpoint_highwater" system_metadata value at backup time --
	// identical contract to v1's own field of the same name and purpose
	// (design §6.3's rollback-protection restore check).
	AuditHighWater string `json:"audit_high_water,omitempty"`
	// DanglingReferences lists any reference (per RestoreOrder()'s derived
	// edges) found, read-only, in the SOURCE database at backup time whose
	// target row does not exist -- a pre-existing orphan, not something
	// admin backup blocks on (design §3.4's corrected text). Empty on a
	// clean database, which is the common case.
	DanglingReferences []DanglingReference `json:"dangling_references,omitempty"`
}

// TableEntry describes one table's NDJSON tar entry -- everything restore
// needs to verify it before loading a single row (design §3.3, §5.4).
type TableEntry struct {
	Name             string `json:"name"`     // GORM table name, e.g. "secret_nodes"
	TarName          string `json:"tar_name"` // "tables/<name>.ndjson"
	RowCount         int64  `json:"row_count"`
	UncompressedSize int64  `json:"uncompressed_size"`
	SHA256           string `json:"sha256"`
}

// KeyFileEntry is server/admin's backupFileEntry shape, duplicated here
// rather than imported (internal/backupfmt must not import server/admin --
// the dependency runs the other way) so this package's Manifest is
// self-contained; server/admin's writer/reader convert between the two at
// its own boundary.
type KeyFileEntry struct {
	OriginalPath string `json:"original_path"`
	TarName      string `json:"tar_name"`
	Mode         uint32 `json:"mode"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

// DanglingReference is one row whose reference field (per RestoreOrder()'s
// derived edges) points to a row that does not exist in the referenced
// table -- design §3.4's backup-time warning / restore-time mandatory
// refusal both report violations in this shape.
type DanglingReference struct {
	Table     string `json:"table"`
	Column    string `json:"column"`
	RowID     uint   `json:"row_id"`
	RefTable  string `json:"ref_table"`
	MissingID uint   `json:"missing_id"`
}

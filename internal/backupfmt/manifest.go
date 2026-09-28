package backupfmt

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

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

// Manifest is the archive's MANIFEST.json (v2). Signature covers every
// other field (design §5.4) -- see SignManifest/VerifyManifestSignature.
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
	// Checkpoint is the source install's signed audit high-water mark at
	// backup time, in the SAME JSON shape auditverify.ExternalAnchorBundle
	// already uses (design §5.4) -- not a bespoke encoding, so this
	// manifest can be handed directly to `admin verify-audit --anchor` with
	// zero translation (§5.4, §6.4). nil when the source install had never
	// written a checkpoint (a fresh/young install, not an error).
	Checkpoint *auditverify.ExternalAnchorBundle `json:"checkpoint,omitempty"`
	// DanglingReferences lists any reference (per RestoreOrder()'s derived
	// edges) found, read-only, in the SOURCE database at backup time whose
	// target row does not exist -- a pre-existing orphan, not something
	// admin backup blocks on (design §3.4's corrected text). Empty on a
	// clean database, which is the common case.
	DanglingReferences []DanglingReference `json:"dangling_references,omitempty"`
	// Signature is this manifest's own HMAC-SHA256, under the
	// auditverify.DeriveBackupManifestKey-derived key, over every field
	// above (design §5.2, §5.4) -- computed last, over everything else
	// already being final; never included in what it signs (see
	// canonicalManifestBytes).
	Signature string `json:"signature,omitempty"`
}

// TableEntry describes one table's NDJSON tar entry -- everything restore
// needs to verify it before loading a single row (design §3.3, §5.4).
type TableEntry struct {
	Name             string `json:"name"`     // GORM table name, e.g. "secret_nodes"
	TarName          string `json:"tar_name"` // "tables/<name>.ndjson"
	RowCount         int64  `json:"row_count"`
	UncompressedSize int64  `json:"uncompressed_size"`
	SHA256           string `json:"sha256"`
	// Columns is this table's full column set (DB names) at backup time --
	// design §3.5's schema-delta detection compares this against the
	// CURRENT (restoring) binary's model to refuse an unrecognized column
	// (a rename or type change the additive-only migration convention
	// should have prevented) rather than silently drop or misparse it.
	Columns []string `json:"columns"`
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

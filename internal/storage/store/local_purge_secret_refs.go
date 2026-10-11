// local_purge_secret_refs.go — the per-column classification of every row that
// references a secret (secret_nodes) or one of its versions (secret_versions),
// and the cascade PurgeDeletedSecretsBefore derives from it (#3085).
//
// A purge hard-deletes the secret_nodes row. Any table that still points at the
// purged id is an orphan, and backupfmt's mandatory dangling-reference check
// makes `admin restore` refuse a backup that holds one. Every referencing
// column therefore has exactly one answer, recorded here or in backupfmt:
//
//   - CASCADE: the purge deletes the referencing rows in the same transaction
//     (SecretPurgeCascades, plus SecretPurgeIndirectCascades for the children
//     of a cascaded table).
//   - HISTORICAL: the row is an immutable record of what happened and is kept;
//     backupfmt.HistoricalReferences names those columns and the restore check
//     skips exactly them.
//
// TestSecretReferencesAreClassified (backupfmt/purge_refs_guard_test.go) fails when a
// new column referencing a secret is in neither list, so the next table cannot
// silently orphan.
package store

import (
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretPurgeParent names which purged id a cascaded column holds.
type SecretPurgeParent string

const (
	// PurgeParentSecretNode: the column holds a secret_nodes.id.
	PurgeParentSecretNode SecretPurgeParent = "secret_nodes"
	// PurgeParentSecretVersion: the column holds a secret_versions.id.
	PurgeParentSecretVersion SecretPurgeParent = "secret_versions"
)

// SecretPurgeCascade is one referencing column PurgeDeletedSecretsBefore
// deletes the rows of.
type SecretPurgeCascade struct {
	Model  any
	Table  string
	Column string
	Parent SecretPurgeParent
}

// SecretPurgeIndirectCascade is a table that references a CASCADED table (not
// the secret itself): its rows go before the rows they reference.
type SecretPurgeIndirectCascade struct {
	Model       any
	Table       string
	Column      string
	ParentTable string // the cascaded table the column references
}

// SecretPurgeCascades lists every mutable table whose rows reference a purged
// secret or version and are deleted with it. Order is the deletion order.
func SecretPurgeCascades() []SecretPurgeCascade {
	return []SecretPurgeCascade{
		{&models.AccessRequest{}, "access_requests", "secret_id", PurgeParentSecretNode},
		{&models.ShareRecord{}, "share_records", "secret_id", PurgeParentSecretNode},
		{&models.SecretTag{}, "secret_tags", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretAccessSchedule{}, "secret_access_schedules", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretMetadataHistory{}, "secret_metadata_histories", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretVersionComment{}, "secret_version_comments", "secret_id", PurgeParentSecretNode},
		{&models.Notification{}, "notifications", "secret_node_id", PurgeParentSecretNode},
		{&models.AnomalyAlert{}, "anomaly_alerts", "secret_node_id", PurgeParentSecretNode},
		{&models.SecretAccessLog{}, "secret_access_logs", "secret_node_id", PurgeParentSecretNode},
		// Version-keyed: must run before secret_versions is deleted.
		{&models.SecretVersionComment{}, "secret_version_comments", "version_id", PurgeParentSecretVersion},
		{&models.SecretAccessLog{}, "secret_access_logs", "secret_version_id", PurgeParentSecretVersion},
	}
}

// SecretPurgeIndirectCascades lists the children of cascaded tables. They are
// deleted BEFORE the cascades above (children first).
func SecretPurgeIndirectCascades() []SecretPurgeIndirectCascade {
	return []SecretPurgeIndirectCascade{
		{&models.AccessRequestApproval{}, "access_request_approvals", "request_id", "access_requests"},
	}
}

// SecretPurgeStatementCount is the number of delete statements the cascade
// issues (indirect + direct), for tests that count statements.
func SecretPurgeStatementCount() int {
	return len(SecretPurgeIndirectCascades()) + len(SecretPurgeCascades())
}

// purgeSecretReferences deletes every row classified CASCADE above. eligible
// returns a fresh subquery of the secret_nodes ids being purged (a *gorm.DB is
// stateful, so one per use).
func purgeSecretReferences(tx *gorm.DB, eligible func() *gorm.DB) error {
	for _, c := range SecretPurgeIndirectCascades() {
		// access_request_approvals.request_id -> access_requests.id, for the
		// requests the direct cascade below deletes.
		requests := tx.Model(&models.AccessRequest{}).Select("id").Where("secret_id IN (?)", eligible())
		if e := tx.Unscoped().Where(c.Column+" IN (?)", requests).Delete(c.Model).Error; e != nil {
			return e
		}
	}
	for _, c := range SecretPurgeCascades() {
		var ids *gorm.DB
		switch c.Parent {
		case PurgeParentSecretVersion:
			ids = tx.Model(&models.SecretVersion{}).Select("id").Where("secret_node_id IN (?)", eligible())
		default:
			ids = eligible()
		}
		// ShareRecord carries its own deleted_at: Unscoped makes this a hard delete.
		if e := tx.Unscoped().Where(c.Column+" IN (?)", ids).Delete(c.Model).Error; e != nil {
			return e
		}
	}
	return nil
}

package storage

// factory_schema_epoch_v096_refusal_test.go -- RELEASE-PREP-2 item 5.
//
// docs/UPGRADING.md (6q, 7) and the v0.97.0 upgrade checklist tell operators that rollback
// across v0.97.0 is a restore, because a v0.96.x binary refuses to start on a database a
// v0.97 server has migrated. The refusal is the compatibility floor (ADR-101). The existing
// floor tests are written relative to currentSchemaEpoch and use floors they pick
// themselves, so none of them would notice the floor being lowered back to what v0.96.x
// satisfies. This one pins the released fact instead: a v0.96.x epoch is refused by a
// database migrated with THIS binary's own constants.
//
// What it does NOT prove: that a real v0.96.x binary prints this message (that is
// scripts/e2e/mixed_version_test.go, PostgreSQL, e2e tag), or anything about a container,
// Helm or a second replica.

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// v096SchemaEpoch is the schema epoch the whole v0.96.x line compiled in
// (v0.96.1/factory.go: currentSchemaEpoch = 2, minCompatibleSchemaEpoch = 2). It describes
// a shipped release and never changes.
const v096SchemaEpoch = 2

func TestV096EpochIsRefusedOnADatabaseThisBinaryMigrated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "v097-database.db"))
	require.NoError(t, err)

	// The database a v0.97 server leaves behind, and the same server starting again: the
	// recorded floor is never lowered by a later boot.
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	require.Greater(t, minCompatibleSchemaEpoch, v096SchemaEpoch,
		"minCompatibleSchemaEpoch must stay above %d, the epoch v0.96.x compiled in: lowering it lets a v0.96.x binary start on a v0.97 database, "+
			"which UPGRADING 6q/7 and the upgrade checklist say is refused (rollback is a restore)", v096SchemaEpoch)

	err = checkSchemaEpochFor(db, v096SchemaEpoch)
	require.Error(t, err, "a v0.96.x binary (epoch %d) must be refused on a database migrated by this binary", v096SchemaEpoch)
	require.Contains(t, err.Error(), fmt.Sprintf("minimum compatible schema epoch of %d (database schema epoch %d)", minCompatibleSchemaEpoch, currentSchemaEpoch))
	require.Contains(t, err.Error(), fmt.Sprintf("this binary's schema epoch %d", v096SchemaEpoch))

	// This binary itself still starts on it.
	require.NoError(t, checkSchemaEpochFor(db, currentSchemaEpoch))
}

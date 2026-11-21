// migrate_machine_actor_columns_test.go — #4518: a database first installed before the
// machine-identity actor columns, the widened ux_access_request_approver and the SSO PKCE
// code_verifier existed gets them from migrateDatabase, and a second boot changes nothing.
//
// The real-old-DB proof is oracle 6 of the upgrade fuzzers (upgrade_schema_matches_fresh_test.go,
// v0.91.0 and v0.92.1 sources); this test pins the two properties it cannot see: the swap
// leaves a unique index on both dialects, and running it again is a no-op.
package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// machineActorColumns is every column #4518 adds: table -> column.
var machineActorColumns = map[string]string{
	"access_request_approvals": "approver_machine_identity_id",
	"access_requests":          "resolved_by_machine_identity_id",
	"access_review_campaigns":  "created_by_machine_identity_id",
	"break_glass_activations":  "revoked_by_machine_identity_id",
	"machine_identities":       "created_by_machine_identity_id",
	"project_invitations":      "invited_by_machine_identity_id",
	"project_memberships":      "invited_by_machine_identity_id",
	"secret_dependencies":      "created_by_machine_identity_id",
	"setup_tokens":             "created_by_machine_identity_id",
	"sso_login_states":         "code_verifier",
}

func TestMachineActorColumns_OldDatabaseGainsThem(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, t.TempDir()+"/old.db")
	require.NoError(t, err)
	assertMachineActorColumnsAdded(t, db)
}

func TestMachineActorColumns_Postgres_OldDatabaseGainsThem(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	assertMachineActorColumnsAdded(t, pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t))))
}

// assertMachineActorColumnsAdded installs fresh, strips what #4518 adds the way an old
// release's schema lacks it (the columns gone, the approver index narrow), then boots twice.
func assertMachineActorColumnsAdded(t *testing.T, db *gorm.DB) {
	t.Helper()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	require.NoError(t, db.Exec("DROP INDEX "+accessRequestApproverIndex).Error)
	for table, col := range machineActorColumns {
		require.NoError(t, db.Exec("ALTER TABLE "+table+" DROP COLUMN "+col).Error, "setup: dropping %s.%s", table, col)
	}
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX "+accessRequestApproverIndex+" ON access_request_approvals (request_id, approver_id)").Error)

	for boot := 1; boot <= 2; boot++ {
		require.NoError(t, f.migrateDatabase(db), "boot %d", boot)
		for table, col := range machineActorColumns {
			require.True(t, columnExists(db, table, col), "boot %d: %s.%s must exist", boot, table, col)
		}
		def := indexDefinition(db, accessRequestApproverIndex)
		require.Contains(t, strings.ToUpper(def), "UNIQUE", "boot %d: the widened index must stay unique", boot)
		require.Contains(t, def, "approver_machine_identity_id", "boot %d: the index must include the machine approver", boot)
	}
}

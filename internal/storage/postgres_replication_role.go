package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// refuseNonOriginReplicationRole refuses to run Keyorix on PostgreSQL sessions
// whose session_replication_role is not 'origin' (#3361).
//
// In 'replica' mode PostgreSQL enforces no foreign keys and fires no ordinary
// trigger; 'local' fires a different set of triggers again. Keyorix's schema
// guarantees are written for 'origin': cascades and referential integrity, and
// the triggers its caches prove before trusting a stamp. A deployment can end up
// in another mode without anyone choosing it for Keyorix: Helm's
// postgresql.settings as the server-wide default, ALTER ROLE ... SET or ALTER
// DATABASE ... SET (also per role in one database), PGOPTIONS, or an options
// parameter in the DSN. current_setting on a session of the configured
// connection reports the effective value after all of those, which is why the
// check reads it rather than inspecting each source.
//
// It runs before migrations, on the request pool. The lock pools and the native
// read pool connect with the same configuration, so their sessions start in
// the same mode. A setting changed after start-up reaches only new
// connections; the read caches' trigger proofs (store.pgTriggerFiresForEveryWriter)
// refuse to trust a stamp or a generation on such a session, and the next
// restart refuses to start.
func refuseNonOriginReplicationRole(db *gorm.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var role string
	if err := db.WithContext(ctx).Raw("SELECT current_setting('session_replication_role')").Scan(&role).Error; err != nil {
		return fmt.Errorf("failed to read session_replication_role: %w", err)
	}
	if role != "origin" {
		return &NonOriginReplicationRoleError{Role: role}
	}
	return nil
}

// NonOriginReplicationRoleError is the session_replication_role refusal itself,
// as opposed to a failure to read the setting (a database that is down or
// answering an error), so a caller can tell the one an operator must fix from
// the ones that may pass (server/boot_exit.go marks only this one exit 78).
type NonOriginReplicationRoleError struct{ Role string }

func (e *NonOriginReplicationRoleError) Error() string {
	return fmt.Sprintf("refusing to start: PostgreSQL session_replication_role is %q for this server's database sessions, want \"origin\". "+
		"In %q mode foreign keys and ordinary triggers do not run, so Keyorix cannot keep its data consistent or its caches fresh. "+
		"Remove the setting (Helm postgresql.settings, ALTER ROLE/ALTER DATABASE ... SET session_replication_role, PGOPTIONS, or the DSN options); "+
		"check with: SELECT current_setting('session_replication_role')", e.Role, e.Role)
}

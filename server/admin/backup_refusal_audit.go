package admin

// backup_refusal_audit.go: a backup refused because a key-rotation staging
// file is present is recorded in the audit chain (#4105), so the outage shows
// where the backup's own success (admin.backup_created) would have, not only
// on the cron job's stderr. The refusal does not depend on the write: it is
// returned whatever happens here.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// backupRefusedEventType is the audit event of an `admin backup` refused
// because a key-rotation staging file is present.
const backupRefusedEventType = "admin.backup_refused"

// recordBackupRefusal writes backupRefusedEventType for refusal r and says on
// stderr whether it did. Best effort: the caller returns the refusal either
// way, so a failed write never turns a refused backup into a taken one.
func recordBackupRefusal(cfg *config.Config, r *pendingRotationRefusal) {
	if err := writeBackupRefusalEvent(cfg, r); err != nil {
		fmt.Fprintf(os.Stderr, "note: this refusal was not recorded to the audit chain: %v. The backup is refused either way.\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "This refusal was recorded to the audit chain (%s).\n", backupRefusedEventType)
}

// writeBackupRefusalEvent opens storage only where the backup itself would
// write admin.backup_created, and only when doing so changes nothing else:
//
//   - under the lock the backup would hold: the exclusive database lock on
//     SQLite and with --exclusive (a live SQLite server refuses it, and then
//     nothing is written), the shared presence lock for a live Postgres backup.
//     With --force the exclusive lock may be bypassed; this write is then
//     skipped rather than made beside a server;
//   - only when the database already records this binary's schema epoch:
//     opening storage migrates the schema, and a backup is what an operator
//     takes before an upgrade, so a refused one must not migrate the database
//     (storage.SchemaEpochIsCurrent). A SQLite file that does not exist is not
//     created.
func writeBackupRefusalEvent(cfg *config.Config, r *pendingRotationRefusal) error {
	if !isPostgresStorage(cfg) || backupExclusive {
		lock, err := acquireDatabaseLock(cfg)
		if err != nil {
			return fmt.Errorf("the database lock is not available (%w)", err)
		}
		if lock == nil {
			return errors.New("--force bypassed the exclusive database lock, and the audit write is not made without it")
		}
		defer lock.Release() //nolint:errcheck
	} else {
		presence, err := acquireLiveBackupPresenceFn(cfg)
		if err != nil {
			return err
		}
		defer presence.Release() //nolint:errcheck
	}
	if err := requireCurrentSchemaForRefusalAudit(cfg); err != nil {
		return err
	}
	description := fmt.Sprintf("backup refused: key rotation staging file present (%s); no archive was written and no "+
		"key file was changed", strings.Join(r.paths, ", "))
	if !r.dek {
		description += ". Remedy: `keyorix-server admin encryption clear-stale-salt-pending`"
	}
	return withUsableStorage(cfg, func(st corestorage.Storage) error {
		ok := false
		// audit-direct-ok: hardcodes ActorType adminActorType ("admin_cli") and never sets UserID, as
		// recordAdminAction does: a host-side `keyorix-server admin` CLI action with no request context.
		return st.LogAuditEvent(context.Background(), &models.AuditEvent{
			EventType:   backupRefusedEventType,
			Description: withLockBypassNote(description),
			Success:     &ok,
			ActorType:   adminActorType,
			EventTime:   time.Now(),
		})
	})
}

// requireCurrentSchemaForRefusalAudit refuses the audit write unless the
// database exists and already records this binary's schema epoch.
func requireCurrentSchemaForRefusalAudit(cfg *config.Config) error {
	if !isPostgresStorage(cfg) {
		if _, err := os.Stat(sqliteDBPath(cfg)); err != nil {
			return fmt.Errorf("the SQLite database %s cannot be opened without creating it (%w)", sqliteDBPath(cfg), err)
		}
	}
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("open the database: %w", err)
	}
	defer closeGormDB(db)
	current, err := storage.SchemaEpochIsCurrent(db)
	if err != nil {
		return err
	}
	if !current {
		return fmt.Errorf("the database does not record this binary's schema epoch %d, and opening storage would migrate it "+
			"before any backup of it exists", storage.CurrentSchemaEpoch())
	}
	return nil
}

package admin

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// refuseBackupDEKBehindDatabase fails a PostgreSQL backup whose key directory
// does not hold the DEK the database's rows are under (#4104). Several key
// directories can serve one PostgreSQL database (storage.encryption.key_dir_lock:
// database, a key copy per replica), and a DEK rotation changes only the one it
// runs in: after its sweep commits and before its dek.key.pending is promoted
// (docs/multi-replica-keys.md, crash table), every other directory still holds
// the old dek.key and no .pending file, so refusePendingKeyRotation sees
// nothing. An archive taken there pairs the old DEK with rows under the new
// one: it restores, but the restored server's start is refused
// (encryption.ErrDEKEpochMismatch) and nothing in it decrypts.
//
// The database records which DEK it is under (dek.epoch, internal/encryption
// dek_epoch.go). The backup goes on only when the epoch is this directory's own
// DEK fingerprint, or "rotating:<own>" (a rotation fence left by a rotation that
// stopped before its sweep committed: the rows are still under this DEK, and the
// restored server's start lifts it), or when there is no epoch and no committed
// rotation's redo marker (dek_rotation.promote_pending) either: the epoch has not
// been seeded yet, and the restored server's start seeds it only after this DEK
// decrypts the newest secret version. A redo marker beside an epoch that names
// this DEK is a completed rotation's, which the next server start clears.
//
// db must be the backup's own read handle (the REPEATABLE READ snapshot the
// rows are read through), so the epoch checked is the one the archive holds.
// A failed read refuses the backup (fail closed). SQLite has one key directory
// and no epoch (dek_epoch.go), so nothing is checked there.
func refuseBackupDEKBehindDatabase(db *gorm.DB, ownFingerprint string) error {
	if db == nil || db.Dialector == nil || db.Name() != "postgres" {
		return nil
	}
	var rows []models.SystemMetadata
	if err := db.Where("key IN ?", []string{encryption.DEKEpochMetadataKey, encryption.DEKRotationPromotePendingMetadataKey}).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("backup refused: could not read the database's DEK epoch (system_metadata %q), so it could not be checked "+
			"that this key directory's dek.key is the DEK the database is encrypted under; no archive was written and no key file "+
			"was changed: %w", encryption.DEKEpochMetadataKey, err)
	}
	var epoch, marker string
	var epochFound, markerFound bool
	for _, r := range rows {
		switch r.Key {
		case encryption.DEKEpochMetadataKey:
			epoch, epochFound = r.Value, true
		case encryption.DEKRotationPromotePendingMetadataKey:
			marker, markerFound = r.Value, true
		}
	}
	if epochFound && (epoch == ownFingerprint || epoch == encryption.DEKEpochRotatingPrefix+ownFingerprint) {
		return nil
	}
	if !epochFound && !markerFound {
		return nil
	}
	shown := epoch
	if !epochFound {
		shown = "(none)"
	}
	if markerFound {
		return fmt.Errorf("%w: backup refused: a DEK rotation committed its re-encryption sweep (new key version %s), so the "+
			"database's rows are under the new DEK, but this key directory holds a different dek.key and no dek.key.pending "+
			"(database DEK epoch %s, this key directory's DEK %s). The new DEK exists only as dek.key.pending in the key directory "+
			"the rotation ran in. An archive taken here would restore, but no server could start on it and nothing in it would "+
			"decrypt, so no archive was written and no key file was changed. Finish the rotation in the key directory that holds "+
			"dek.key.pending (start the server there, or run the rotation's admin command there again, so boot recovery promotes "+
			"it), distribute the new key set (dek.key, kek.salt) to every replica's key directory, including this one, then back up "+
			"again. Never delete dek.key.pending by hand: it is the only copy of the DEK the rows are under",
			encryption.ErrDEKEpochMismatch, marker, shown, ownFingerprint)
	}
	return fmt.Errorf("%w: backup refused: this key directory's dek.key is not the DEK the database is encrypted under "+
		"(database DEK epoch %s, this key directory's DEK %s): the DEK was rotated with another key directory, or this one holds "+
		"another installation's key files. An archive taken here would restore, but no server could start on it and nothing in "+
		"it would decrypt, so no archive was written and no key file was changed. Copy the current key set (dek.key, kek.salt) "+
		"from the key directory that rotated, then back up again",
		encryption.ErrDEKEpochMismatch, shown, ownFingerprint)
}

package storage

// Schema epoch (ADR-097, ADR-101): the compiled-in epoch, the start-up check
// and the recorded value (moved verbatim from factory.go).

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// currentSchemaEpoch (ADR-097) is this binary's compiled-in schema version.
// Bump it by exactly one in the SAME PR as any change to migrateDatabase
// below that adds or alters schema (a new ALTER TABLE, a new AutoMigrate
// model, a new column) -- checkSchemaEpoch uses it to refuse startup if the
// database was already migrated by a newer binary, closing the class of
// silent-downgrade regression this ADR documents (an old binary writing new
// rows via a migrated-in column's DEFAULT, blind to whatever invariant that
// column encodes). NOT bumped for pure comment/refactor changes that don't
// touch what gets written to the database. Every bump must also decide
// minCompatibleSchemaEpoch below (ADR-101).
const currentSchemaEpoch = 8

// schemaEpochMetadataKey is the system_metadata (see models.SystemMetadata)
// key checkSchemaEpoch/recordSchemaEpoch read and write. #nosec G101 --
// metadata key name, not a credential.
const schemaEpochMetadataKey = "schema_epoch"

// minCompatibleSchemaEpoch (ADR-101) is the compatibility floor this binary's
// schema declares: the OLDEST binary schema epoch that may still safely run
// against a database this binary has migrated. recordSchemaEpoch writes it to
// system_metadata next to schema_epoch; checkSchemaEpoch refuses to start any
// binary whose currentSchemaEpoch is below a recorded floor.
//
// When you bump currentSchemaEpoch, you must also decide this value:
//   - an additive-and-safe migration (an older binary's writes still default
//     in the safe direction -- ADR-097's own default-direction reasoning)
//     leaves it UNCHANGED, so old replicas mid-rollout, and a one-release
//     rollback, keep booting;
//   - a migration an older binary cannot safely run against raises it to the
//     new currentSchemaEpoch, so every older binary refuses.
//
// It must stay within [1, currentSchemaEpoch]
// (TestMinCompatibleSchemaEpoch_WithinRange). A floor already recorded in the
// database is never lowered by recordSchemaEpoch, so declaring a lower value
// here cannot reopen a floor a newer binary raised.
//
// Floor 2: an epoch-1 binary's RestoreSecret/RestoreProject do not clear
// secret_nodes.purge_at and its DeleteSecret does not re-stamp it, so a
// restore + re-delete on an old replica would leave a stale date that the
// epoch-2 purge job honours, hard-deleting before the date shown (#3021).
//
// Epoch 3 is ONE epoch (no release has shipped between its two changes): the
// pending_audit_events table, which is additive on its own (an epoch-2 replica
// never reads or writes it, and rows it leaves behind are drained by the next
// epoch-3 replica's backfill), and the HA-READY-1 formats below. The floor is
// therefore 3, HA-READY-1's value.
//
// Epoch 4 (machine_identities.cascade_suspended_project_id/_at, #3433) leaves it at
// 3: an epoch-3 replica's project delete does not suspend (the pre-#3433 behaviour,
// for the length of the rollout), its project restore re-activates nothing (fail
// closed: the identities stay suspended), and its machine-identity writes do not clear
// the marker but do move updated_at, which the epoch-4 restore requires unchanged
// (LocalStorage.ReactivateMachineIdentitiesForRestoredProject). Nothing an epoch-3
// binary does makes an epoch-4 restore re-activate an identity it should not.
//
// Floor 3 (HA-READY-1): epoch-2 binaries (v0.96.x) predate two formats
// the database now holds. (1) The v2 audit retention anchor (#3258): an
// epoch-2 binary reads it as malformed, reports the chain broken, and its
// retention purge rewrites a v1 anchor, dropping the cumulative purged count
// for good (verify "truncated", checkpoints 409; #3359). (2)
// secret_nodes.suspend_clear_synced_copies (#3215): an epoch-2 binary's
// resume/suspend never write it (#3362; the column is also reset by a
// trigger on every status change away from suspended, which covers epoch-2
// replicas still running during a rollout). The floor keeps epoch-2 binaries
// from starting once this binary has migrated.
//
// Epoch 5 (break_glass_activations.degraded/audit_settled_at and
// pending_audit_events.break_glass_activation_id, BREAKGLASS-OWED-1) leaves it at 3:
// an epoch-4 replica never writes a degraded activation (it fails closed on audit, its
// pre-epoch-5 behaviour), its writes default both new columns to "not degraded", and
// its backfill still writes the owed rows of an epoch-5 degraded activation exactly
// once. The only cost is that it does not mark that activation settled, so
// verify-audit keeps reporting it as owed: loud, never silent.
//
// Epoch 6 (audit_events.request_id, AUDIT-REQUEST-ID-1) leaves it at 3: an epoch-5
// replica never reads the column (QueryFields) and inserts without it, so its rows
// have NULL, which means "no request id" -- exactly what such a row has. The column
// is outside the hash chain, so verification is unaffected either way.
//
// Epoch 7 (roles.assignable_scope, GROUP-ROLE-SCOPE-1 Phase 2, #3546) leaves it at
// 3: an epoch-6 (or older) replica never writes the column, so a role it creates
// mid-rollout gets the column default, project (the new-role default: fail closed);
// its grant check ignores the column and still refuses the four project_* built-ins
// at the global scope by name (the Phase 1 rule), so for the length of the rollout
// it accepts what epoch 6 always accepted, never more.
//
// Epoch 8 (users.mfa_enrolment_required and the mfa_reset_requests table,
// RECOVERY-MFA-RESET-1) leaves it at 3: an epoch-7 replica never reads or writes
// either. A reset account also carries password_reset_required and a one-time
// password, which every older binary honours, so an older replica still confines
// it to a password change; what it does not do is demand the new enrolment
// (docs/UPGRADING.md: finish or cancel pending resets before a downgrade).
const minCompatibleSchemaEpoch = 3

// schemaMinCompatibleEpochMetadataKey is the system_metadata key ADR-101's
// compatibility floor (minCompatibleSchemaEpoch) is recorded under. #nosec
// G101 -- metadata key name, not a credential.
const schemaMinCompatibleEpochMetadataKey = "schema_min_compatible_epoch"

// checkSchemaEpoch (ADR-097, ADR-101) refuses to let a binary run
// migrateDatabase against a database whose schema it cannot safely run
// against. Called BEFORE any other migration step. It applies
// checkSchemaEpochFor with this binary's own compiled-in currentSchemaEpoch.
func checkSchemaEpoch(db *gorm.DB) error {
	return checkSchemaEpochFor(db, currentSchemaEpoch)
}

// checkSchemaEpochFor is checkSchemaEpoch with the binary's schema epoch as a
// parameter, so tests can exercise binaries older and newer than this one.
//
// system_metadata not existing yet means a fresh install (or a database old
// enough to predate system_metadata itself, i.e. pre-ADR-029) -- either way,
// there is nothing recorded to compare against, so this proceeds. A missing
// schema_epoch key means an older binary that predates this guard wrote to
// this database last -- absence of a recorded epoch cannot itself justify
// refusing to start, so this proceeds too.
//
// Otherwise it refuses (fail-closed, matching this file's #G54 discipline: a
// corrupted marker is worse to silently ignore than to loudly refuse) when:
//   - schema_epoch, or the ADR-101 floor, does not parse as an integer;
//   - the recorded floor is below 1 -- not an epoch any binary writes;
//   - the recorded floor is above binaryEpoch (ADR-101: a migration declared
//     its schema unsafe for binaries this old -- the dangerous rollback);
//   - schema_epoch is above binaryEpoch and NO floor is recorded (ADR-097's
//     original refusal: no migration author ever stated that this schema is
//     safe for an older binary, and the absence of a compatibility claim is
//     not a claim).
//
// A schema_epoch above binaryEpoch WITH a recorded floor at or below
// binaryEpoch proceeds: that is ADR-101's whole point -- the migration that
// produced the newer schema explicitly declared it safe for this binary
// (an old replica mid-rollout, or a rollback that does not cross the floor).
func checkSchemaEpochFor(db *gorm.DB, binaryEpoch int) error {
	if !tableExists(db, "system_metadata") {
		return nil
	}
	m, epochFound, err := readSchemaMetadata(db, schemaEpochMetadataKey)
	if err != nil {
		return fmt.Errorf("failed to read schema epoch: %w", err)
	}
	floorRow, floorFound, err := readSchemaMetadata(db, schemaMinCompatibleEpochMetadataKey)
	if err != nil {
		return fmt.Errorf("failed to read minimum compatible schema epoch: %w", err)
	}
	// The floor is checked first and independently of schema_epoch: a floor
	// above this binary refuses whatever the epoch row says (or whether it
	// exists at all).
	if floorFound {
		floor, floorErr := strconv.Atoi(floorRow.Value)
		if floorErr != nil {
			return fmt.Errorf("stored minimum compatible schema epoch %q is not a valid integer -- refusing to start rather than guess whether this binary is below the database's compatibility floor (ADR-101)", floorRow.Value)
		}
		if floor < 1 {
			return fmt.Errorf("stored minimum compatible schema epoch %d is below 1, which no version of Keyorix "+
				"writes -- refusing to start rather than trust a corrupted compatibility floor (ADR-101)", floor)
		}
		if floor > binaryEpoch {
			return fmt.Errorf(
				"database declares a minimum compatible schema epoch of %d (database schema epoch %s), above this "+
					"binary's schema epoch %d (floor recorded at %s, %s ago) -- a migration this database has already "+
					"applied was declared unsafe for binaries this old, so this binary must not run against it. "+
					"If this is a rolling upgrade, this pod is expected to be replaced by the new image; if this "+
					"binary was rolled back, roll forward to a version with schema epoch %d or later, or restore a "+
					"backup taken before the newer version ran. Refusing to start (ADR-101)",
				floor, m.Value, binaryEpoch, floorRow.UpdatedAt.Format(time.RFC3339),
				time.Since(floorRow.UpdatedAt).Round(time.Second), floor)
		}
	}
	if !epochFound {
		return nil
	}
	dbEpoch, parseErr := strconv.Atoi(m.Value)
	if parseErr != nil {
		return fmt.Errorf("stored schema epoch %q is not a valid integer -- refusing to start rather than guess whether this database is ahead of this binary (ADR-097)", m.Value)
	}
	if floorFound {
		// floor <= binaryEpoch (checked above): the migration(s) that produced
		// dbEpoch declared this binary compatible (ADR-101) -- proceed even if
		// dbEpoch is newer.
		return nil
	}
	if dbEpoch > binaryEpoch {
		// #1674 (Part 2 continuation, design decision recorded in
		// docs/adr-101-schema-epoch-compatibility-floor.md): this refusal is NOT
		// made conditional on how recently the newer epoch was recorded, or on
		// how many epochs ahead it is -- from inside this process, "a sibling
		// replica migrated moments ago mid-rollout" and "an operator just
		// downgraded onto an already-migrated schema" are the SAME observable
		// state (a higher epoch than this binary knows). Any arithmetic on the
		// timestamp below to auto-proceed would legalize the second case (the
		// most common real downgrade: roll back shortly after a bad deploy) to
		// silence the first. The timestamp is reported to help a human tell them
		// apart, not consulted to decide for them. The ONLY thing that lets an
		// older binary through is ADR-101's explicitly recorded floor, handled
		// above -- and none is recorded here.
		return fmt.Errorf(
			"database schema epoch %d is newer than this binary's schema epoch %d "+
				"(recorded at %s, %s ago) -- this database was migrated by a newer "+
				"version of Keyorix. Two things produce this, and this process cannot "+
				"tell them apart on its own: (a) a rolling upgrade in progress -- a "+
				"sibling replica already migrated to the new epoch, and this pod is "+
				"still running the old binary; it is expected to be replaced by the new "+
				"image shortly, and this failure is self-resolving once that happens "+
				"(this repo does not orchestrate that rollout for you -- see "+
				"docs/adr-039-ha-deployment.md for the supported multi-replica "+
				"topology), or (b) this binary was downgraded against a schema a newer "+
				"version already migrated -- if so, upgrade this binary to match, or "+
				"restore a backup taken before the newer version ran. No minimum "+
				"compatible schema epoch is recorded, so nothing declares this schema "+
				"safe for an older binary. Refusing to start "+
				"is the safe default in both cases (ADR-097, ADR-101)",
			dbEpoch, binaryEpoch, m.UpdatedAt.Format(time.RFC3339), time.Since(m.UpdatedAt).Round(time.Second))
	}
	return nil
}

// readSchemaMetadata reads one system_metadata row; found is false (with a
// nil error) only when the key is absent.
func readSchemaMetadata(db *gorm.DB, key string) (m models.SystemMetadata, found bool, err error) {
	err = db.Where("key = ?", key).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	return m, true, nil
}

// CurrentSchemaEpoch returns this binary's compiled-in schema version
// (ADR-097) -- design-b3-backup-v2.md §3.5/§3.6: `admin backup` records
// this in the manifest at backup time, exactly the same value
// checkSchemaEpoch compares a live database's own recorded epoch against.
func CurrentSchemaEpoch() int {
	return currentSchemaEpoch
}

// SchemaEpochTooNew reports whether epoch is newer than this binary's
// CurrentSchemaEpoch() -- the comparison checkSchemaEpoch applies to a live
// database's recorded epoch when no ADR-101 compatibility floor is recorded
// (ADR-097), exposed so `admin restore` (design §3.5) can apply it to an
// archive's manifest-declared schema_epoch instead: a backup taken by a
// newer binary than this one is refused, for the same reason a newer-schema
// live database with no compatibility claim is. A backup manifest carries no
// floor, so restore keeps this strict rule.
func SchemaEpochTooNew(epoch int) bool {
	return epoch > currentSchemaEpoch
}

// recordSchemaEpoch (ADR-097, ADR-101) records currentSchemaEpoch and its
// compatibility floor minCompatibleSchemaEpoch in system_metadata. Called
// only after migrateDatabase's other steps all succeed -- never on a
// partial/failed migration, so a crash mid-migration can't advance the
// recorded epoch past what was actually, successfully applied.
func recordSchemaEpoch(db *gorm.DB) error {
	return recordSchemaEpochAs(db, currentSchemaEpoch, minCompatibleSchemaEpoch)
}

// recordSchemaEpochAs writes both keys in ONE upsert statement (so neither
// can land without the other), and the upsert only ever RAISES a stored
// value: an older binary that ADR-101 lets boot against a newer schema must
// not stamp the database back down to its own epoch, and no binary may lower
// a floor a newer migration raised. It also means an additive-safe migration
// (one that leaves minCompatibleSchemaEpoch unchanged) never moves the floor.
// The comparison is done in SQL, not read-then-write in Go, so two replicas
// recording concurrently cannot interleave a lower value over a higher one.
func recordSchemaEpochAs(db *gorm.DB, epoch, floor int) error {
	now := time.Now()
	keepHigher := gorm.Expr("CASE WHEN CAST(system_metadata.value AS INTEGER) >= CAST(excluded.value AS INTEGER) " +
		"THEN system_metadata.value ELSE excluded.value END")
	keepHigherTime := gorm.Expr("CASE WHEN CAST(system_metadata.value AS INTEGER) >= CAST(excluded.value AS INTEGER) " +
		"THEN system_metadata.updated_at ELSE excluded.updated_at END")
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{"value": keepHigher, "updated_at": keepHigherTime}),
	}).Create(&[]models.SystemMetadata{
		{Key: schemaEpochMetadataKey, Value: strconv.Itoa(epoch), UpdatedAt: now},
		{Key: schemaMinCompatibleEpochMetadataKey, Value: strconv.Itoa(floor), UpdatedAt: now},
	}).Error; err != nil {
		return fmt.Errorf("failed to record schema epoch: %w", err)
	}
	return nil
}

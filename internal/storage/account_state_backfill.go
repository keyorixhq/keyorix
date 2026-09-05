package storage

import (
	"fmt"
	"log"
	"strings"

	"gorm.io/gorm"
)

// accountStateBackfilledLabel is the explicit value a blank/unset
// users.account_state is backfilled to. Matches core.AccountActive
// (internal/storage cannot import internal/core -- core imports storage --
// so this is the same literal core.NormalizeAccountState's own "" -> active
// mapping already treats blank as meaning).
const accountStateBackfilledLabel = "active"

// backfillBlankAccountState finds every live user row whose account_state is
// blank, unset, or all-whitespace and sets it to an explicit "active"
// (ADR-025 root-cause fix).
//
// This closes a real, confirmed authentication-bypass chain: core.
// AccountLoginBlocked (the single choke point every login/session/PAT/SSO/
// WebAuthn/MFA-step-up/impersonation-target path calls) is a deny-list keyed
// on NormalizeAccountState(state), which maps "" to "active" -- so a
// suspended or deprovisioned account whose account_state was ever written as
// blank reads as NOT blocked. The write-path fix that stops NEW blanks from
// being introduced only closes the ONE call site it was found at; any row
// that was ALREADY blank before that landed -- from that bug, or from any
// other path that ever wrote an empty string -- stays a live landmine until
// backfilled explicitly. This function is that backfill: idempotent (a no-op
// once no blank rows remain, like every other backfill* helper in this
// package), and loud about what it found -- the row count is logged
// unconditionally so an operator upgrading a real database SEES the number,
// not just a silent success.
//
// Deliberately does NOT change any code-level behavior
// (NormalizeAccountState/AccountLoginBlocked stay exactly as they are): the
// fail-open-to-fail-closed behavior change is its own, later deploy --
// flipping the default before every existing blank row is confirmed
// backfilled would lock out any account this migration hasn't reached yet,
// which is worse than the bug it fixes.
func backfillBlankAccountState(db *gorm.DB) error {
	type row struct {
		ID    uint
		State string
	}
	var rows []row
	if err := db.Table("users").Select("id, account_state AS state").
		Where(sqlWhereNotDeleted).
		Find(&rows).Error; err != nil {
		return fmt.Errorf("failed to read users for account_state backfill: %w", err)
	}

	var blankIDs []uint
	for _, r := range rows {
		if strings.TrimSpace(r.State) == "" {
			blankIDs = append(blankIDs, r.ID)
		}
	}
	if len(blankIDs) == 0 {
		return nil
	}

	// Loud on purpose: this is the number an operator upgrading a real
	// database needs to see, not just a silent success. A large count here
	// confirms blank-as-legacy-active was real, live production state, not a
	// theoretical edge case.
	log.Printf("SECURITY: backfilling account_state for %d user row(s) with a blank/unset value -- "+
		"each was reading as NOT login-blocked regardless of any suspension/deprovisioning ever recorded "+
		"for it; setting explicitly to %q", len(blankIDs), accountStateBackfilledLabel)

	if err := db.Table("users").Where("id IN ?", blankIDs).
		Update("account_state", accountStateBackfilledLabel).Error; err != nil {
		return fmt.Errorf("failed to backfill account_state for %d user row(s): %w", len(blankIDs), err)
	}
	return nil
}

// ValidAccountStateSQLValues is the SQL-literal form of every ADR-025 account
// state, for guardAccountStateValid's CHECK constraint. Deliberately
// duplicated as literals rather than imported from internal/core: this
// package (internal/storage) cannot import internal/core, since core already
// imports storage (see accountStateBackfilledLabel's own comment for the
// identical constraint). TestValidAccountStateSQLValues_MatchesCoreRegistry
// (account_state_backfill_core_sync_test.go, an external storage_test
// package, which CAN import core without an import cycle) fails CI if this
// list ever drifts from core's own AccountXxx constants.
var ValidAccountStateSQLValues = []string{
	"active",
	"pending_first_login",
	"password_reset_required",
	"suspended",
	"deprovisioned",
}

// guardAccountStateValid adds a database-level CHECK constraint refusing any
// future write of a users.account_state value outside the ADR-025 canonical
// set, on Postgres. This is the schema-level half of the fix: even before
// core.AccountLoginBlocked is changed to fail closed on an unrecognized value
// (a separate, later behavior change -- see backfillBlankAccountState's own
// doc), a write path that tries to persist blank OR any other non-canonical
// value (a resurgence of the exact bug the write-path containment fix closed
// at one call site, a typo, or a new site nobody has found yet) fails loudly
// at the database instead of silently succeeding.
//
// An ENUM allow-list, not merely a non-empty check: a plain `<> ”` check
// (this constraint's first version) stops a blank write but does nothing
// about a garbage non-blank value reaching the column, which is exactly the
// gap core.AccountLoginBlocked's fail-closed-on-unrecognized behavior needs
// covered at the schema level too. Supersedes and replaces the narrower
// chk_users_account_state_not_blank constraint from that first version.
//
// This constraint does NOT make the Go-level fail-closed check in
// core.AccountLoginBlocked redundant -- that function is a pure function
// over a string, not a query result. A User struct can carry an arbitrary
// value from a session cache entry, an API request body deserialized before
// any write, a test fixture, or (once storage.type: remote / a non-Postgres
// backend is in play) a database this constraint was never applied to at
// all. This constraint is defense-in-depth specifically for Postgres
// production, not a substitute for the code-level check.
//
// Postgres only: SQLite's ALTER TABLE cannot add a CHECK constraint to an
// existing table without a full table rebuild (copy to a new table, drop,
// rename). For the `users` table specifically -- referenced by sessions,
// PATs, group/user role grants, secret ownership, machine-identity
// CreatedBy, webauthn credentials, and audit rows -- doing that rebuild
// inside a boot-time, always-on, every-restart idempotent migration is a
// materially riskier operation than the value justifies now that the
// Go-level check is the actual, dialect-independent enforcement mechanism;
// ADR-039 already documents SQLite as single-instance/development only,
// never the production-HA backend this constraint most needs to protect.
// Explicit, deliberate gap -- not silent: SQLite installs rely entirely on
// core.AccountLoginBlocked's fail-closed behavior for this protection, with
// no schema-level backstop.
func guardAccountStateValid(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	const constraintName = "chk_users_account_state_valid"
	const oldConstraintName = "chk_users_account_state_not_blank"

	var oldExists bool
	if err := db.Raw(
		"SELECT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = ? AND table_name = 'users')",
		oldConstraintName,
	).Scan(&oldExists).Error; err != nil {
		return fmt.Errorf("failed to check for existing %s constraint: %w", oldConstraintName, err)
	}
	if oldExists {
		// Subsumed by the new, stricter allow-list constraint below -- keeping
		// both would be redundant, and Postgres has no "ALTER CONSTRAINT
		// definition" so replacing it means drop-then-add.
		if err := db.Exec("ALTER TABLE users DROP CONSTRAINT " + oldConstraintName).Error; err != nil {
			return fmt.Errorf("failed to drop superseded %s constraint: %w", oldConstraintName, err)
		}
	}

	var exists bool
	if err := db.Raw(
		"SELECT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = ? AND table_name = 'users')",
		constraintName,
	).Scan(&exists).Error; err != nil {
		return fmt.Errorf("failed to check for existing %s constraint: %w", constraintName, err)
	}
	if exists {
		return nil
	}

	quoted := make([]string, len(ValidAccountStateSQLValues))
	for i, v := range ValidAccountStateSQLValues {
		quoted[i] = "'" + v + "'"
	}
	inList := strings.Join(quoted, ",")
	checkExpr := "account_state IN (" + inList + ")"
	if err := db.Exec("ALTER TABLE users ADD CONSTRAINT " + constraintName +
		" CHECK (" + checkExpr + ")").Error; err != nil {
		// This constraint is stricter than the blank-only guard it replaces --
		// backfillBlankAccountState only ever fixes BLANK rows, so an existing
		// row already holding a non-blank, non-canonical value (a typo, manual
		// DB edit, or some unrelated historical bug -- NOT the account-takeover
		// vulnerability this whole fix closes, which was specifically about
		// blank) makes this ADD CONSTRAINT fail with Postgres's own generic
		// "violated by some row" error, naming no row. Since this failure is
		// already fatal to server startup (migrateDatabase's caller aborts via
		// log.Fatalf -- see this function's own doc), a bare Postgres error
		// here would leave an operator with a dead server and no idea which
		// row(s) to fix. Look them up and name them.
		var offenders []struct {
			ID    uint
			State string
		}
		if scanErr := db.Raw("SELECT id, account_state AS state FROM users WHERE account_state NOT IN (" +
			inList + ")").Scan(&offenders).Error; scanErr == nil && len(offenders) > 0 {
			details := make([]string, len(offenders))
			for i, o := range offenders {
				details[i] = fmt.Sprintf("user %d has account_state %q", o.ID, o.State)
			}
			return fmt.Errorf("failed to add %s constraint: %d existing row(s) hold a non-canonical "+
				"account_state value that must be corrected by an administrator before this version can "+
				"start (backfillBlankAccountState only fixes blank values, not typos/garbage): %s: %w",
				constraintName, len(offenders), strings.Join(details, "; "), err)
		}
		return fmt.Errorf("failed to add %s constraint: %w", constraintName, err)
	}
	return nil
}

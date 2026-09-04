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

// guardAccountStateNotBlank adds a database-level CHECK constraint refusing
// any future write of an empty users.account_state, on Postgres. This is the
// schema-level half of the fix: even before NormalizeAccountState/
// AccountLoginBlocked are changed to fail closed on an unrecognized value (a
// separate, later behavior change -- see backfillBlankAccountState's own
// doc), a write path that tries to blank this column again (a resurgence of
// the exact bug the write-path containment fix closed at one call site, or a
// new site nobody has found yet) fails loudly at the database instead of
// silently succeeding.
//
// Postgres only: SQLite's ALTER TABLE cannot add a CHECK constraint to an
// existing table without a full table rebuild (copy to a new table, drop,
// rename) -- a materially riskier operation for a boot-time, idempotent
// migration than this fix is worth, especially since ADR-039 already
// documents SQLite as single-instance/development only, never the
// production-HA backend this constraint most needs to protect. The portable,
// both-dialect backstop is the later code-level fail-closed change to
// NormalizeAccountState/AccountLoginBlocked -- this constraint is
// defense-in-depth specifically for Postgres production, not a substitute
// for it.
func guardAccountStateNotBlank(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	const constraintName = "chk_users_account_state_not_blank"
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
	if err := db.Exec("ALTER TABLE users ADD CONSTRAINT " + constraintName +
		" CHECK (btrim(account_state) <> '')").Error; err != nil {
		return fmt.Errorf("failed to add %s constraint: %w", constraintName, err)
	}
	return nil
}

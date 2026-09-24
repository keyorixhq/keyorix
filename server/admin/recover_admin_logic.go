package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// recoverAdminSummary reports what performRecoverAdmin actually did, for the
// command's own stdout report and the admin-notification message.
type recoverAdminSummary struct {
	userID                     uint
	username                   string
	webAuthnCredentialsCleared int
	sessionsRevoked            int
	recoveryKeyVersion         int
	auditChainBroken           bool
	auditChainFirstBrokenID    uint
}

// performRecoverAdmin is the whole recovery act (design §3): verify the
// target exists and holds a global-admin role, verify the recovery key,
// then reset account state / password / MFA / WebAuthn / lockout / sessions
// on that ONE account, and record it. Every failure path returns before any
// storage write happens except the final audit event, which is written
// regardless of whether the audit chain was already broken (design §4: a
// broken chain does not block recovery, it's recorded alongside it).
func performRecoverAdmin(ctx context.Context, store corestorage.Storage, userIdentifier, rawRecoveryKey string) (*recoverAdminSummary, error) {
	user, err := resolveTargetUser(ctx, store, userIdentifier)
	if err != nil {
		return nil, err
	}

	isAdmin, err := userHoldsGlobalAdminRole(ctx, store, user.ID)
	if err != nil {
		return nil, fmt.Errorf("check target's admin role: %w", err)
	}
	if !isAdmin {
		return nil, fmt.Errorf("account %q (id %d) does not hold a global-admin role -- "+
			"recover-admin is specifically for restoring ADMIN accounts, not general password reset", user.Username, user.ID)
	}

	record, found, err := store.GetRecoveryKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("read recovery-key record: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no recovery key has been generated on this install yet -- " +
			"run `keyorix-server admin recovery-key rotate` first, then retry recover-admin with the key it prints")
	}
	if !recoverykey.Verify(rawRecoveryKey, record.KeyHash) {
		return nil, fmt.Errorf("recovery key does not match")
	}

	now := time.Now()
	summary := &recoverAdminSummary{
		userID:             user.ID,
		username:           user.Username,
		recoveryKeyVersion: record.KeyVersion,
	}

	err = store.WithTransaction(ctx, func(tx corestorage.Storage) error {
		if err := tx.SetAccountState(ctx, user.ID, core.AccountPasswordResetRequired, now); err != nil {
			return fmt.Errorf("reactivate account: %w", err)
		}
		if err := tx.SetPasswordHash(ctx, user.ID, "", now); err != nil {
			return fmt.Errorf("clear password: %w", err)
		}
		if err := tx.SetUserMFAEnabled(ctx, user.ID, false); err != nil {
			return fmt.Errorf("clear MFA enrollment flag: %w", err)
		}
		if err := tx.DeleteMFAForUser(ctx, user.ID); err != nil {
			return fmt.Errorf("clear MFA secret/recovery codes: %w", err)
		}
		creds, err := tx.ListWebAuthnCredentials(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("list WebAuthn credentials: %w", err)
		}
		for _, c := range creds {
			if err := tx.DeleteWebAuthnCredential(ctx, user.ID, c.ID); err != nil {
				return fmt.Errorf("delete WebAuthn credential %d: %w", c.ID, err)
			}
		}
		summary.webAuthnCredentialsCleared = len(creds)
		if err := tx.UpdateLoginLockoutState(ctx, user.ID, 0, nil, nil, 0); err != nil {
			return fmt.Errorf("clear login-lockout state: %w", err)
		}
		tokens, err := tx.ListSessionTokenHashesForUser(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}
		summary.sessionsRevoked = len(tokens)
		if err := tx.DeleteSessionsForUserExcept(ctx, user.ID, 0); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	recordRecoveryAuditEvent(ctx, store, summary)

	return summary, nil
}

// recordRecoveryAuditEvent writes the audit-chain event for this recovery.
// Inherits refuseIfAuditChainBroken's own posture (local_audit_chain.go):
// there is deliberately no auto-repair of a broken chain, because silently
// "fixing" a chain that may reflect tampering would destroy the evidence.
// recover-admin does the same -- verify first, still perform (and record)
// the recovery regardless of the verdict (refusing an admin recovery over an
// unrelated integrity fault would be the worse outcome -- the auth-boundary
// lockout-vs-bypass asymmetry: recovery is the recoverable, visible side of
// that tradeoff), and surface the broken-chain fact loudly rather than
// silently.
//
// Design §4 additionally asks for the new entry to be written as an
// "explicitly-marked chain restart (a new segment whose first entry records
// 'prior chain verification failed at row N' instead of chaining onto the
// broken tail)". This implementation does NOT do that: LogAuditEvent (this
// package's only write path, shared with every other admin command) always
// chains onto whatever the current tail is, broken or not -- reworking its
// hashing to support a genuine segment restart is real surgery on
// internal/storage/store/local_audit_chain.go shared by every caller, out
// of scope for this PR. What this DOES do, and what actually delivers the
// detectability property design §4 is after: verify the chain before
// writing, and when broken, name the exact broken row in both a loud
// stderr warning (never just the human report) AND the event's own
// Description -- so the fact "recovery happened while the audit trail was
// already compromised" is recorded, even though the low-level chain-segment
// mechanics design §4 sketches are not implemented here. Flagged explicitly
// as an open item, not silently narrowed -- see the PR description.
func recordRecoveryAuditEvent(ctx context.Context, store corestorage.Storage, summary *recoverAdminSummary) {
	verification, err := store.VerifyAuditChain(ctx, nil)
	description := fmt.Sprintf(
		"keyorix-server admin recover-admin restored account %q (user id %d): reactivated, password reset required, "+
			"MFA cleared, %d WebAuthn credential(s) cleared, login-lockout cleared, %d session(s) revoked (recovery key generation %d)",
		summary.username, summary.userID, summary.webAuthnCredentialsCleared, summary.sessionsRevoked, summary.recoveryKeyVersion)

	if err == nil && !verification.Valid {
		summary.auditChainBroken = true
		if verification.FirstBrokenID != nil {
			summary.auditChainFirstBrokenID = *verification.FirstBrokenID
		}
		description = fmt.Sprintf(
			"%s -- WARNING: the audit chain was ALREADY BROKEN before this event (first broken row: %d, reason: %s); "+
				"this recovery proceeded anyway (refusing would be a worse outcome than a recorded, visible recovery)",
			description, summary.auditChainFirstBrokenID, verification.Reason)
	} else if err != nil {
		description = fmt.Sprintf("%s -- note: could not verify audit chain integrity before this event (%v)", description, err)
	}

	uid := summary.userID
	ok := true
	writeErr := store.LogAuditEvent(ctx, &models.AuditEvent{
		EventType:   "admin.recover_admin",
		UserID:      &uid,
		Description: description,
		Success:     &ok,
		ActorType:   adminActorType,
		EventTime:   time.Now(),
	})
	if writeErr != nil {
		fmt.Printf("note: could not record this recovery to the audit chain (%v)\n", writeErr)
	}
}

package admin

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// recoverAdminSummary reports what performRecoverAdmin actually did, for the
// command's own stdout report and the admin-notification message.
type recoverAdminSummary struct {
	userID                     uint
	username                   string
	webAuthnCredentialsCleared int
	sessionsRevoked            int
	recoveryKeyVersion         int
	keyless                    bool
	auditChainBroken           bool
	auditChainFirstBrokenID    uint
	// operator is the host OS account that ran the command (design §4: there is
	// no Keyorix identity to attribute an offline recovery to, the actor is the
	// host user). Recorded in the audit event and the admin notification.
	operator string
	// oneTimePassword is the plaintext credential just set on the recovered
	// account, for the CLI to print exactly once. Never logged, audited, or
	// included in the admin-notification text (recordRecoveryAuditEvent/
	// notifyAllAdmins only ever see the summary's OTHER fields) — the same
	// "displayed out-of-band, never persisted in clear" contract
	// CreateUserWithOneTimePassword's OneTimePasswordResult already has.
	oneTimePassword string
	// oneTimePasswordExpiresAt (UTC) is when that password stops working; the CLI
	// prints it and the audit event records it.
	oneTimePasswordExpiresAt time.Time
}

// performRecoverAdmin is the whole recovery act (design §3): verify the
// target exists and holds a global-admin role, verify the recovery key
// (skipped entirely when keyless is true -- design §5's labs/demo escape
// hatch, gated by security.recover_admin.insecure_keyless_admin_recovery and never reachable
// from anywhere but a host-side config-file read, see recover_admin.go),
// then reset account state / password / MFA / WebAuthn / lockout / sessions
// on that ONE account, and record it. Every failure path returns before any
// storage write happens, except a wrong recovery key, which writes an
// admin.recover_admin_failed audit event (recordRecoveryKeyMismatch) and
// nothing else; the success audit event is written regardless of whether
// the audit chain was already broken (design §4: a broken chain does not
// block recovery, it's recorded alongside it).
func performRecoverAdmin(ctx context.Context, store corestorage.Storage, userIdentifier, rawRecoveryKey string, keyless bool) (*recoverAdminSummary, error) {
	return performRecoverAdminWithTTL(ctx, store, userIdentifier, rawRecoveryKey, keyless, core.DefaultRecoveryOneTimePasswordExpiry)
}

// performRecoverAdminWithTTL is performRecoverAdmin with the lifetime of the
// one-time password it issues (security.recovery_one_time_password_ttl,
// OTP-EXPIRY-1). A non-positive otpTTL means the default: the password always
// gets an expiry.
func performRecoverAdminWithTTL(ctx context.Context, store corestorage.Storage, userIdentifier, rawRecoveryKey string, keyless bool, otpTTL time.Duration) (*recoverAdminSummary, error) {
	if otpTTL <= 0 {
		otpTTL = core.DefaultRecoveryOneTimePasswordExpiry
	}
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

	summary := &recoverAdminSummary{
		userID:   user.ID,
		username: user.Username,
		keyless:  keyless,
		operator: hostOperator(),
	}
	if !keyless {
		record, found, err := store.GetRecoveryKeyRecord(ctx)
		if err != nil {
			return nil, fmt.Errorf("read recovery-key record: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("no recovery key has been generated on this install yet -- " +
				"run `keyorix-server admin recovery-key rotate` first, then retry recover-admin with the key it prints " +
				"(or enable security.recover_admin.insecure_keyless_admin_recovery, not recommended outside labs/demo use)")
		}
		if !recoverykey.Verify(rawRecoveryKey, record.KeyHash) {
			recordRecoveryKeyMismatch(ctx, store, summary, record.KeyVersion)
			return nil, fmt.Errorf("recovery key does not match")
		}
		summary.recoveryKeyVersion = record.KeyVersion
	}

	now := time.Now()
	expiresAt := now.Add(otpTTL).UTC()

	// A one-time password the recovered admin can actually log in with, not an
	// empty hash: bcrypt.CompareHashAndPassword (VerifyPasswordCredentials,
	// internal/core/auth.go) fails unconditionally against "" for every
	// password, so clearing the hash outright left the one documented
	// emergency-recovery path ending in the account still being locked out —
	// found live, see the PR this comment landed with. Reuses
	// core.GenerateInitialCredential (the same policy-compliant generator
	// CreateUserWithOneTimePassword uses for new-user onboarding, ADR-028 Part
	// E) and core.PasswordHashCost (the same live bcrypt work factor every
	// other password hash in this codebase is generated with) rather than a
	// separate generator/cost here, so this credential is indistinguishable in
	// strength from any other the system issues.
	otp, err := core.GenerateInitialCredential()
	if err != nil {
		return nil, fmt.Errorf("generate one-time password: %w", err)
	}
	otpHash, err := bcrypt.GenerateFromPassword([]byte(otp), core.PasswordHashCost())
	if err != nil {
		return nil, fmt.Errorf("hash one-time password: %w", err)
	}

	err = store.WithTransaction(ctx, func(tx corestorage.Storage) error {
		if err := tx.SetAccountState(ctx, user.ID, core.AccountPasswordResetRequired, now); err != nil {
			return fmt.Errorf("reactivate account: %w", err)
		}
		// password_reset_required (set above, same transaction) confines the
		// resulting session to the password-change allowlist until a real
		// password is chosen (internal/core/auth.go's AccountLoginBlocked/login
		// middleware) — this OTP is deliberately NOT a normal, indefinitely
		// reusable credential.
		if err := tx.SetPasswordHash(ctx, user.ID, string(otpHash), now); err != nil {
			return fmt.Errorf("set one-time password: %w", err)
		}
		// Same transaction as the hash (SetPasswordHash clears any prior expiry):
		// the credential never exists without its expiry (OTP-EXPIRY-1).
		if err := tx.SetOneTimePasswordExpiry(ctx, user.ID, &expiresAt, now); err != nil {
			return fmt.Errorf("set one-time password expiry: %w", err)
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
		// The flag with the rows: a WebAuthnEnabled account with no credential is
		// asked at login for a passkey it no longer has (a permanent lockout).
		if err := tx.SetUserWebAuthnEnabled(ctx, user.ID, false); err != nil {
			return fmt.Errorf("clear WebAuthn flag: %w", err)
		}
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
	summary.oneTimePassword = otp
	summary.oneTimePasswordExpiresAt = expiresAt

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
// Design §4's idea that recover-admin writes a chain restart is retired
// (docs/design/recovery-options.md §2 "recover-admin"): recover-admin NEVER
// seals or restarts the chain. Accepting a loss is a separate, deliberate,
// audited act with its own evidence, `admin audit accept-loss`
// (audit_accept_loss.go); folding it into a lockout recovery would let a
// recovery silently bless tampering. What this does: verify the chain before
// writing and, when broken, name the exact broken row in both a loud stderr
// warning and the event's own Description, so "recovery happened while the
// audit trail was already compromised" is recorded. Guard:
// TestPerformRecoverAdmin_NeverSealsALoss.
func recordRecoveryAuditEvent(ctx context.Context, store corestorage.Storage, summary *recoverAdminSummary) {
	verification, err := store.VerifyAuditChain(ctx, nil)
	keyDetail := fmt.Sprintf("recovery key generation %d", summary.recoveryKeyVersion)
	if summary.keyless {
		keyDetail = "KEYLESS MODE -- no recovery key was checked (security.recover_admin.insecure_keyless_admin_recovery)"
	}
	description := fmt.Sprintf(
		"keyorix-server admin recover-admin, run by host user %s, restored account %q (user id %d): reactivated, password reset required, "+
			"MFA cleared, %d WebAuthn credential(s) cleared, login-lockout cleared, %d session(s) revoked (%s); one-time password expires %s",
		summary.operator, summary.username, summary.userID, summary.webAuthnCredentialsCleared, summary.sessionsRevoked, keyDetail,
		summary.oneTimePasswordExpiresAt.UTC().Format(time.RFC3339))

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
		Description: withLockBypassNote(description),
		Success:     &ok,
		ActorType:   adminActorType,
		EventTime:   time.Now(),
	})
	if writeErr != nil {
		fmt.Printf("note: could not record this recovery to the audit chain (%v)\n", writeErr)
	}
}

// recordRecoveryKeyMismatch writes the audit event for a recover-admin attempt
// refused because the recovery key did not match (Success=false), the
// counterpart of admin.recover_admin as auth.login_failed is of auth.login:
// host access plus key guessing against an admin account must reach the
// audit chain, not only the operator's terminal. Names the host user, the
// target and the key generation; never the key typed or its hash. Best effort,
// like recordRecoveryAuditEvent: the refusal stands either way.
func recordRecoveryKeyMismatch(ctx context.Context, store corestorage.Storage, summary *recoverAdminSummary, keyVersion int) {
	uid := summary.userID
	failed := false
	err := store.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "admin.recover_admin_failed",
		UserID:    &uid,
		Description: withLockBypassNote(fmt.Sprintf(
			"keyorix-server admin recover-admin, run by host user %s, for account %q (user id %d): refused, the recovery key did not match (stored generation %d); nothing was changed",
			summary.operator, summary.username, summary.userID, keyVersion)),
		Success:   &failed,
		ActorType: adminActorType,
		EventTime: time.Now(),
	})
	if err != nil {
		fmt.Printf("note: could not record this refused attempt to the audit chain (%v)\n", err)
	}
}

// hostOperator names the host OS account running this process, as
// "name (uid N)", for attributing an offline admin action (design §4). Falls
// back to $USER, then "unknown": attribution is best-effort and must never
// block a recovery.
func hostOperator() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return fmt.Sprintf("%q (uid %s)", u.Username, u.Uid)
	}
	if name := os.Getenv("USER"); name != "" {
		return fmt.Sprintf("%q (uid unknown)", name)
	}
	return "unknown"
}

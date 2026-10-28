package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// Audit event types of `admin reset-mfa`.
const (
	eventAdminResetMFA       = "admin.reset_mfa"
	eventAdminResetMFAFailed = "admin.reset_mfa_failed"
)

// resetMFASummary reports what performResetMFA did, for the command's report and
// the notifications. oneTimePassword is printed once and nowhere else.
type resetMFASummary struct {
	userID                   uint
	username                 string
	operator                 string
	recoveryKeyVersion       int
	keyless                  bool
	chainNote                string
	effect                   *core.MFAResetEffect
	oneTimePassword          string
	oneTimePasswordExpiresAt time.Time
}

// performResetMFA is the host-side MFA reset (docs/design/recovery-options.md §1,
// option C): the fallback of the two-admin online reset, for installs with fewer
// than two eligible admins and for air-gapped hosts. Its authority is host access
// plus the recovery key, the same as recover-admin; it adds no power beyond it
// (whoever holds both can already recover a global admin).
//
// Refused, with nothing written: an unknown user, a machine identity, a
// global-admin account (recover-admin is the path for those), an SSO/SCIM
// account, a suspended or inactive one, and a wrong recovery key (which writes
// admin.reset_mfa_failed and nothing else).
//
// The reset itself (core.ResetMFACredentialsInTx) and its admin.reset_mfa audit
// row are one transaction: if the row cannot be written, nothing is reset.
func performResetMFA(ctx context.Context, store corestorage.Storage, ref, rawRecoveryKey string, keyless bool, otpTTL time.Duration) (*resetMFASummary, error) {
	if otpTTL <= 0 {
		otpTTL = core.DefaultRecoveryOneTimePasswordExpiry
	}
	user, err := core.ResolveMFAResetTarget(ctx, store, ref)
	if err != nil {
		return nil, err
	}
	if err := refuseResetMFATarget(ctx, store, user); err != nil {
		return nil, err
	}

	summary := &resetMFASummary{userID: user.ID, username: user.Username, keyless: keyless, operator: hostOperator()}
	if !keyless {
		record, found, err := store.GetRecoveryKeyRecord(ctx)
		if err != nil {
			return nil, fmt.Errorf("read recovery-key record: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("no recovery key has been generated on this install yet -- " +
				"run `keyorix-server admin recovery-key rotate` first, then retry reset-mfa with the key it prints")
		}
		if !recoverykey.Verify(rawRecoveryKey, record.KeyHash) {
			recordResetMFAKeyMismatch(ctx, store, summary, record.KeyVersion)
			return nil, fmt.Errorf("recovery key does not match")
		}
		summary.recoveryKeyVersion = record.KeyVersion
	}

	// The chain verdict at the time, recorded with the event (as recover-admin does).
	// A broken chain does not block the reset: refusing it would leave the user
	// locked out over an unrelated integrity fault, and the event says so loudly.
	if v, verr := store.VerifyAuditChain(ctx, nil); verr != nil {
		summary.chainNote = fmt.Sprintf(" -- note: the audit chain could not be verified before this event (%v)", verr)
	} else if !v.Valid {
		first := uint(0)
		if v.FirstBrokenID != nil {
			first = *v.FirstBrokenID
		}
		summary.chainNote = fmt.Sprintf(" -- WARNING: the audit chain was ALREADY BROKEN before this event (first broken row: %d, reason: %s)", first, v.Reason)
	}

	otp, err := core.GenerateInitialCredential()
	if err != nil {
		return nil, fmt.Errorf("generate one-time password: %w", err)
	}
	otpHash, err := bcrypt.GenerateFromPassword([]byte(otp), core.PasswordHashCost())
	if err != nil {
		return nil, fmt.Errorf("hash one-time password: %w", err)
	}
	now := time.Now()
	expiresAt := now.Add(otpTTL).UTC()

	err = store.WithTransaction(ctx, func(tx corestorage.Storage) error {
		// Re-validated on the row lock: the account may have been suspended, linked
		// to an IdP or made an admin since the read above.
		locked, err := tx.LockUserForUpdate(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("lock account: %w", err)
		}
		if err := refuseResetMFATarget(ctx, tx, locked); err != nil {
			return err
		}
		eff, err := core.ResetMFACredentialsInTx(ctx, tx, locked, string(otpHash), expiresAt, now)
		if err != nil {
			return err
		}
		summary.effect = eff
		uid := locked.ID
		ok := true
		if err := tx.LogAuditEvent(ctx, &models.AuditEvent{
			EventType:   eventAdminResetMFA,
			UserID:      &uid,
			Description: withLockBypassNote(resetMFAAuditDescription(summary, expiresAt)),
			Success:     &ok,
			ActorType:   adminActorType,
			EventTime:   now,
		}); err != nil {
			// Fail closed: an unaudited reset of an authentication factor is not allowed.
			return fmt.Errorf("could not write the %s audit event, nothing was reset: %w", eventAdminResetMFA, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	summary.oneTimePassword = otp
	summary.oneTimePasswordExpiresAt = expiresAt
	return summary, nil
}

// refuseResetMFATarget applies the target rules that need storage: the per-row
// rules plus "not a global admin".
func refuseResetMFATarget(ctx context.Context, store corestorage.Storage, u *models.User) error {
	if err := core.ValidateMFAResetTarget(u); err != nil {
		return err
	}
	isAdmin, err := userHoldsGlobalAdminRole(ctx, store, u.ID)
	if err != nil {
		return fmt.Errorf("check the account's admin role: %w", err)
	}
	if isAdmin {
		return core.ErrMFAResetGlobalAdmin
	}
	return nil
}

func resetMFAKeyDetail(s *resetMFASummary) string {
	if s.keyless {
		return "KEYLESS MODE -- no recovery key was checked (security.recover_admin.insecure_keyless_admin_recovery)"
	}
	return fmt.Sprintf("recovery key generation %d", s.recoveryKeyVersion)
}

func resetMFAAuditDescription(s *resetMFASummary, expiresAt time.Time) string {
	return fmt.Sprintf("keyorix-server admin reset-mfa, run by host user %s, reset the second factor of %q (user id %d): %s (%s); one-time password expires %s%s",
		s.operator, s.username, s.userID, s.effect.Summary(), resetMFAKeyDetail(s), expiresAt.Format(time.RFC3339), s.chainNote)
}

// recordResetMFAKeyMismatch audits a reset-mfa refused for a wrong recovery key.
// Never the key typed or its hash. Best effort: the refusal stands either way.
func recordResetMFAKeyMismatch(ctx context.Context, store corestorage.Storage, s *resetMFASummary, keyVersion int) {
	uid := s.userID
	failed := false
	if err := store.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: eventAdminResetMFAFailed,
		UserID:    &uid,
		Description: withLockBypassNote(fmt.Sprintf(
			"keyorix-server admin reset-mfa, run by host user %s, for %q (user id %d): refused, the recovery key did not match (stored generation %d); nothing was changed",
			s.operator, s.username, s.userID, keyVersion)),
		Success:   &failed,
		ActorType: adminActorType,
		EventTime: time.Now(),
	}); err != nil {
		fmt.Printf("note: could not record this refused attempt to the audit chain (%v)\n", err)
	}
}

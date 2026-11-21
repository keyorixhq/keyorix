// mfa_recovery_reauth.go — an unused recovery code as the re-authentication
// proof for DisableMFA and RegenerateMFARecoveryCodes (#4224): a user who lost
// the phone that holds their TOTP secret, and still has a recovery code, can
// replace the lost factor without an administrator reset.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// reauthMethodRecoveryCode is the method recorded on the audit events of a
// factor change re-authenticated by a recovery code.
const reauthMethodRecoveryCode = "recovery_code"

// recoveryCodeAlphabet is generateRecoveryCodes' alphabet.
const recoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// isRecoveryCodeShaped reports whether code, normalized the way every recovery
// code check normalizes it, has the shape generateRecoveryCodes issues: ten
// characters of its alphabet. It only routes the input. The check itself is
// the conditional consume (consumeRecoveryCodeRecovering), exactly as at login.
// A TOTP code (six digits) is never recovery-shaped.
func isRecoveryCodeShaped(code string) bool {
	n := normalizeRecoveryCode(code)
	if len(n) != 10 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !strings.ContainsRune(recoveryCodeAlphabet, rune(n[i])) {
			return false
		}
	}
	return true
}

// errRecoveryCodeNotMatched rolls the recovery-code transaction back when the
// input matched no unused code of the account: nothing was consumed, and the
// caller hands the input to requireReauth (a password with a reauth step-up
// grant can be recovery-shaped too).
var errRecoveryCodeNotMatched = errors.New("no unused recovery code matched")

// recoveryReauthStage records how far the recovery-code transaction got, so
// its error can be classified after the rollback.
type recoveryReauthStage int

const (
	recoveryStageStart     recoveryReauthStage = iota
	recoveryStageLocked                        // the account was locked under the row lock: nothing evaluated
	recoveryStageMatched                       // the code was consumed: everything after is post-verdict
	recoveryStageCommitted                     // the closure returned nil
)

// reauthWithRecoveryCode re-authenticates a factor change (DisableMFA,
// RegenerateMFARecoveryCodes) with an unused recovery code and applies effect
// in the SAME transaction (#4224). handled=false means the input is not a
// recovery code of this account (not recovery-shaped, or no unused code
// matched): nothing was consumed, counted or audited, and the caller falls back
// to requireReauth, which counts a wrong input exactly once. handled=true with
// a nil error means the code was consumed and effect committed; with an error,
// the refusal has been audited and counted already.
//
// atomicity: one transaction, consume first. Under the account's
// loginFailureMu shard and its LockUserForUpdate row lock (the serialization
// recordFailedLogin uses), the transaction re-reads the lockout state, consumes
// the code with the login path's own check (consumeRecoveryCodeRecovering: the
// conditional UPDATE ... WHERE used_at IS NULL), then runs effect. If the
// consume or effect fails, the transaction rolls back: the code stays unused
// and the factor stays as it was. A rolled-back code may be used again because
// nothing was done with it; that is why every refusal after the match answers
// exactly like a wrong code (#2740 option C), counted toward the lockout
// (#2888): a different answer would tell a guesser that an unused code was
// right. Two concurrent requests with the same code serialize on the row lock
// and the conditional consume; the second finds the code used and gets the
// wrong-code answer.
//
// The lockout gate runs before any code is evaluated: on the caller's snapshot,
// and again under the row lock, where a concurrent burst that locked the
// account is seen before the code is looked at.
//
// FIPS 140-only mode does not change this path: recovery codes are SHA-256,
// as at login and step-up (mfa_fips.go). A TOTP-shaped input is never
// recovery-shaped, so requireReauth's own FIPS refusal still answers it.
func (c *KeyorixCore) reauthWithRecoveryCode(ctx context.Context, user *models.User, code, phase string, effect func(tx storage.Storage) error) (handled bool, err error) {
	if !user.MFAEnabled || !isRecoveryCodeShaped(code) {
		return false, nil
	}
	if c.loginLocked(user) {
		return true, &reauthRejectedError{msg: "account temporarily locked due to repeated failed logins; try again later"}
	}
	stage, txErr := c.consumeRecoveryCodeAndApply(ctx, user.ID, code, effect)
	switch {
	case stage == recoveryStageCommitted && txErr == nil:
		c.clearLoginFailures(ctx, user)
		uid := user.ID
		c.writeAuditEventFull(ctx, "mfa.reauth_verified", &uid, nil, nil, "",
			fmt.Sprintf("user %s completed MFA re-authentication (phase: %s, method: %s)", user.Username, phase, reauthMethodRecoveryCode))
		return true, nil
	case errors.Is(txErr, errRecoveryCodeNotMatched):
		return false, nil
	case stage == recoveryStageLocked:
		// Refused before the code was looked at, like the snapshot gate above.
		return true, &reauthRejectedError{msg: "account temporarily locked due to repeated failed logins; try again later"}
	case stage >= recoveryStageMatched:
		// The code matched; the effect (or the commit) failed and the
		// transaction rolled back. Audited distinctly, counted, and answered
		// like a wrong code.
		log.Printf("SECURITY: MFA %s for user %d: recovery code matched but the change failed (reported to the caller as an invalid code): %v", phase, user.ID, txErr)
		c.auditMFAError(ctx, user.ID, phase, txErr)
		c.recordFailedLogin(ctx, user)
		return true, &reauthRejectedError{msg: "invalid code or password"}
	default:
		// The row lock or the consume itself failed: no verdict on the code.
		// Not counted, audited mfa.error, the same generic answer (the handler
		// maps ErrMFAVerificationStorageFailure to "invalid code or password").
		c.auditMFAError(ctx, user.ID, phase, txErr)
		return true, fmt.Errorf("%w: %s: %w", ErrMFAVerificationStorageFailure, i18n.T("ErrorRetrievalFailed", nil), txErr)
	}
}

// consumeRecoveryCodeAndApply is reauthWithRecoveryCode's transaction. A panic
// in effect comes back as an error after the match (#3277 class): the
// transaction rolls back and the caller answers it like a wrong code, not with
// the Recovery 500 a wrong code never gets.
func (c *KeyorixCore) consumeRecoveryCodeAndApply(ctx context.Context, userID uint, code string, effect func(tx storage.Storage) error) (stage recoveryReauthStage, err error) {
	mu := c.loginFailureLock(userID)
	mu.Lock()
	defer mu.Unlock()
	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) (ferr error) {
		stage = recoveryStageStart
		u, lerr := tx.LockUserForUpdate(ctx, userID)
		if lerr != nil {
			return lerr
		}
		if c.loginLocked(u) {
			stage = recoveryStageLocked
			return errors.New("account locked")
		}
		consumed, cerr := c.consumeRecoveryCodeRecovering(ctx, tx, userID, code)
		if cerr != nil {
			return cerr
		}
		if !consumed {
			return errRecoveryCodeNotMatched
		}
		stage = recoveryStageMatched
		defer func() {
			if r := recover(); r != nil {
				log.Printf("SECURITY: MFA change for user %d panicked after its recovery code matched; "+
					"rolling it back as a post-verdict fault: %v\n%s", userID, r, debug.Stack())
				ferr = fmt.Errorf("%w: factor change for user %d: %v", ErrLoginWritePanicked, userID, r)
			}
		}()
		if eerr := effect(tx); eerr != nil {
			return eerr
		}
		stage = recoveryStageCommitted
		return nil
	})
	if err != nil && stage == recoveryStageCommitted {
		// The closure finished; the commit itself failed.
		stage = recoveryStageMatched
	}
	return stage, err
}

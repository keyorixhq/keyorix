// mfa_reset.go — the online two-admin MFA reset (RECOVERY-MFA-RESET-1,
// docs/design/recovery-options.md §1, option B).
//
// Admin A requests the reset of a user's second factor, a DIFFERENT admin B
// approves it, and only the approval changes the account. Both are human global
// admins with a second factor of their own, each proving it afresh for this
// action (requireReauth: a current TOTP code, or the password plus a passkey
// re-authentication), and neither is the target. The pattern is the existing
// dual-control one (risk exceptions, ApproveRiskException): a request row, a
// different human decides it once through a conditional storage transition, a
// denied self-approval is itself audited. Nothing here is a second approval model.
//
// The approval applies ResetMFACredentialsInTx (mfa_reset_effect.go), the same full
// credential reset the host command applies, and its audit rows in ONE fail-closed
// transaction (withAuditedMutation): if the audit log refuses them, the request
// stays pending and the target keeps every factor. With fewer than two eligible
// admins the request is refused and names the host command.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Audit event types of the online MFA reset. EventMFAReset (mfa_reset_effect.go)
// records the reset itself, in the approval's transaction.
const (
	EventMFAResetRequested = "mfa.reset_requested"
	EventMFAResetApproved  = "mfa.reset_approved"
	EventMFAResetCancelled = "mfa.reset_cancelled"
)

// MFAResetRequestTTL is how long a request waits for its approver.
const MFAResetRequestTTL = 24 * time.Hour

// mfaResetVerifiedBy are the accepted ways the requester confirmed the target.
var mfaResetVerifiedBy = map[string]bool{"in_person": true, "video": true, "ticket": true, "other": true}

// Fixed client-facing texts of the online-flow refusals (transports send these,
// never err.Error()).
const (
	MFAResetAdminRequiredMessage    = "an MFA reset can only be requested, approved or cancelled by a human global administrator"
	MFAResetActorNeedsMFAMessage    = "enrol a second factor on your own account before requesting or approving an MFA reset"
	MFAResetNoSecondAdminMessage    = "an MFA reset needs a second global administrator with a second factor to approve it; on a single-admin install run `keyorix-server admin reset-mfa` on the server host"
	MFAResetSelfApprovalMessage     = "the requester cannot approve their own MFA reset request; a different global administrator must approve it"
	MFAResetAlreadyPendingMessage   = "an MFA reset request for this user is already pending; approve or cancel it"
	MFAResetRequestNotFoundMessage  = "MFA reset request not found"
	MFAResetRequestDecidedMessage   = "this MFA reset request was already approved or cancelled"
	MFAResetRequestExpiredMessage   = "this MFA reset request has expired; open a new one"
	MFAResetRequesterChangedMessage = "the requester is no longer an active global administrator; open a new request"
	MFAResetInputMessage            = "reason is required and verified_by must be one of in_person, video, ticket, other"
)

var (
	ErrMFAResetAdminRequired    = errors.New(MFAResetAdminRequiredMessage)
	ErrMFAResetActorNeedsMFA    = errors.New(MFAResetActorNeedsMFAMessage)
	ErrMFAResetNoSecondAdmin    = errors.New(MFAResetNoSecondAdminMessage)
	ErrMFAResetSelfApproval     = errors.New(MFAResetSelfApprovalMessage)
	ErrMFAResetAlreadyPending   = errors.New(MFAResetAlreadyPendingMessage)
	ErrMFAResetRequestNotFound  = errors.New(MFAResetRequestNotFoundMessage)
	ErrMFAResetRequestDecided   = errors.New(MFAResetRequestDecidedMessage)
	ErrMFAResetRequestExpired   = errors.New(MFAResetRequestExpiredMessage)
	ErrMFAResetRequesterChanged = errors.New(MFAResetRequesterChangedMessage)
	ErrMFAResetInput            = errors.New(MFAResetInputMessage)
)

// MFAResetRequestInput is what the requester submits. Code is the requester's own
// fresh proof (a TOTP code, or the password after a passkey re-authentication).
type MFAResetRequestInput struct {
	User       string // the target: username, email or numeric id
	Reason     string
	VerifiedBy string
	Evidence   string
	Code       string
}

// MFAResetRequestView is a stored request with its effective status at read time
// (pending | approved | cancelled | expired).
type MFAResetRequestView struct {
	*models.MFAResetRequest
	EffectiveStatus string `json:"effective_status"`
}

// MFAResetApproval is the approver's result. OneTimePassword is shown once to the
// approver, who hands it to the user out of band; it is never stored in clear,
// audited or logged.
type MFAResetApproval struct {
	RequestID       uint            `json:"request_id"`
	UserID          uint            `json:"user_id"`
	Username        string          `json:"username"`
	OneTimePassword string          `json:"one_time_password"`
	ExpiresAt       time.Time       `json:"expires_at"`
	Effect          *MFAResetEffect `json:"-"`
}

func mfaResetEffectiveStatus(r *models.MFAResetRequest, now time.Time) string {
	if r.Status == models.MFAResetStatusPending && !r.ExpiresAt.After(now) {
		return "expired"
	}
	return r.Status
}

// requireMFAResetActor checks the actor rules shared by every step: a human (not a
// machine credential, not the 0 sentinel), holding a global-admin role, with a
// second factor of their own. A denied attempt is audited under eventType.
func (c *KeyorixCore) requireMFAResetActor(ctx context.Context, actorID uint, actorIsMachine bool, eventType, what string) (*models.User, error) {
	if actorIsMachine || actorID == 0 {
		c.writeAuditEventFailed(ctx, eventType, nil, nil, "",
			fmt.Sprintf("MFA reset %s DENIED: a machine credential cannot take part in a two-person MFA reset", what))
		return nil, ErrMFAResetAdminRequired
	}
	role, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("check admin role: %w", err)
	}
	if role == "" {
		c.writeAuditEventFailed(ctx, eventType, actorPtr(actorID), nil, "",
			fmt.Sprintf("MFA reset %s DENIED: user %d holds no global-admin role", what, actorID))
		return nil, ErrMFAResetAdminRequired
	}
	actor, err := c.storage.GetUser(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("read actor: %w", err)
	}
	if !userHasSecondFactor(actor) {
		c.writeAuditEventFailed(ctx, eventType, actorPtr(actorID), nil, "",
			fmt.Sprintf("MFA reset %s DENIED: user %d has no second factor", what, actorID))
		return nil, ErrMFAResetActorNeedsMFA
	}
	return actor, nil
}

// auditMFAResetApprovalDenied writes the DENIED mfa.reset_approved row of a refused
// approval. It always goes through c.storage, never a transaction handle, so a
// refusal decided inside the approval transaction keeps its row after that
// transaction rolls back.
func (c *KeyorixCore) auditMFAResetApprovalDenied(ctx context.Context, actorID, requestID uint, why string) {
	c.writeAuditEventFailed(ctx, EventMFAResetApproved, actorPtr(actorID), nil, "",
		fmt.Sprintf("MFA reset request %d approval DENIED: %s", requestID, why))
}

// mfaResetTargetRefusal is the DENIED reason of a refuseMFAResetTarget refusal,
// or "" for an error that is not a refusal (a storage or ceiling-resolution
// failure). Fixed texts and IDs only: the wrapped ceiling error is not copied.
func mfaResetTargetRefusal(err error, targetID uint) string {
	for _, refusal := range []error{ErrMFAResetExternalIdentity, ErrMFAResetAccountBlocked, ErrMFAResetGlobalAdmin, ErrInsufficientAdminAuthority} {
		if errors.Is(err, refusal) {
			return fmt.Sprintf("target %d refused: %v", targetID, refusal)
		}
	}
	return ""
}

// eligibleMFAResetApprovers counts the active global admins other than the
// requester and the target who have a second factor, i.e. who could approve.
func (c *KeyorixCore) eligibleMFAResetApprovers(ctx context.Context, requesterID, targetID uint) (int, error) {
	ids, err := c.globalAdminIDs(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if id == requesterID || id == targetID {
			continue
		}
		u, err := c.storage.GetUser(ctx, id)
		if err != nil {
			continue
		}
		if u.IsActive && !AccountLoginBlocked(u.ID, u.AccountState) && userHasSecondFactor(u) {
			n++
		}
	}
	return n, nil
}

// RequestMFAReset opens a two-admin MFA reset request for in.User on behalf of
// actorID. Nothing about the target changes until a different admin approves.
func (c *KeyorixCore) RequestMFAReset(ctx context.Context, actorID uint, actorIsMachine bool, in MFAResetRequestInput) (*models.MFAResetRequest, error) {
	actor, err := c.requireMFAResetActor(ctx, actorID, actorIsMachine, EventMFAResetRequested, "request")
	if err != nil {
		return nil, err
	}
	in.Reason, in.Evidence = strings.TrimSpace(in.Reason), strings.TrimSpace(in.Evidence)
	if in.Reason == "" || !mfaResetVerifiedBy[in.VerifiedBy] {
		return nil, ErrMFAResetInput
	}
	target, err := ResolveMFAResetTarget(ctx, c.storage, in.User)
	if err != nil {
		return nil, err
	}
	if target.ID == actorID {
		return nil, fmt.Errorf("%w: use your own recovery codes or `keyorix-server admin recover-admin`", ErrCannotActOnSelf)
	}
	if err := c.refuseMFAResetTarget(ctx, actorID, target); err != nil {
		return nil, err
	}
	n, err := c.eligibleMFAResetApprovers(ctx, actorID, target.ID)
	if err != nil {
		return nil, fmt.Errorf("count eligible approvers: %w", err)
	}
	if n == 0 {
		return nil, ErrMFAResetNoSecondAdmin
	}
	now := c.now().UTC()
	if err := refuseIfMFAResetPending(ctx, c.storage, target.ID, now); err != nil {
		return nil, err
	}
	// Last, after every cheap refusal, so a refused request does not spend the code.
	if err := c.requireReauth(ctx, actor, in.Code, "mfa_reset_request"); err != nil {
		return nil, err
	}

	var created *models.MFAResetRequest
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		// Decided again on the target's row lock: a request for the same target that
		// committed after the read above makes this one fail, so at most one is
		// pending per target (the schema does not enforce it).
		if _, lerr := tx.LockUserForUpdate(ctx, target.ID); lerr != nil {
			return lerr
		}
		if perr := refuseIfMFAResetPending(ctx, tx, target.ID, now); perr != nil {
			return perr
		}
		r, cerr := tx.CreateMFAResetRequest(ctx, &models.MFAResetRequest{
			TargetUserID: target.ID, RequestedBy: actorID, Reason: in.Reason,
			VerifiedBy: in.VerifiedBy, Evidence: in.Evidence,
			Status: models.MFAResetStatusPending, CreatedAt: now, ExpiresAt: now.Add(MFAResetRequestTTL),
		})
		if cerr != nil {
			return cerr
		}
		created = r
		c.writeAuditEventFullOn(ctx, tgt, EventMFAResetRequested, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("administrator %d requested an MFA reset of user %d (%s), request %d: reason %q, identity verified by %s%s; expires %s",
				actorID, target.ID, target.Username, r.ID, in.Reason, in.VerifiedBy, evidenceSuffix(in.Evidence), r.ExpiresAt.Format(time.RFC3339)))
		return nil
	}); err != nil {
		return nil, err
	}
	c.notifyMFAResetAdmins(ctx, "MFA reset requested",
		fmt.Sprintf("Administrator %d asked for the second factor of %q (user %d) to be reset (request %d, reason: %s). A different administrator must approve it within 24 hours; if this is unexpected, cancel it.",
			actorID, target.Username, target.ID, created.ID, in.Reason))
	return created, nil
}

// refuseIfMFAResetPending returns ErrMFAResetAlreadyPending when a request for
// targetID is still pending and unexpired, read through st.
func refuseIfMFAResetPending(ctx context.Context, st storage.Storage, targetID uint, now time.Time) error {
	pending, err := st.ListMFAResetRequests(ctx, true)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.TargetUserID == targetID && p.ExpiresAt.After(now) {
			return ErrMFAResetAlreadyPending
		}
	}
	return nil
}

// refuseMFAResetRequesterChanged checks that the requester is still a usable
// global admin: active, not login-blocked, and holding the role, read through st.
// Dual control needs two CURRENT admins: suspending a compromised admin must also
// stop their pending requests from being approved by someone else.
func refuseMFAResetRequesterChanged(ctx context.Context, st storage.Storage, requester *models.User) error {
	if !requester.IsActive || AccountLoginBlocked(requester.ID, requester.AccountState) {
		return ErrMFAResetRequesterChanged
	}
	role, err := isGlobalAdminRoleNameOn(ctx, st, requester.ID)
	if err != nil {
		return fmt.Errorf("check requester's admin role: %w", err)
	}
	if role == "" {
		return ErrMFAResetRequesterChanged
	}
	return nil
}

// mfaResetRequester reads (or, with lock, row-locks) the requester through st; a
// requester who no longer exists is ErrMFAResetRequesterChanged.
func mfaResetRequester(ctx context.Context, st storage.Storage, id uint, lock bool) (*models.User, error) {
	var (
		u   *models.User
		err error
	)
	if lock {
		u, err = st.LockUserForUpdate(ctx, id)
	} else {
		u, err = st.GetUser(ctx, id)
	}
	if err != nil {
		if storage.IsUserNotFound(err) {
			return nil, ErrMFAResetRequesterChanged
		}
		return nil, fmt.Errorf("read requester: %w", err)
	}
	return u, nil
}

// refuseMFAResetApproverChanged re-checks, on the approver's locked row read
// through st, what requireMFAResetActor checked before the transaction: an
// active, not login-blocked global admin with a second factor. An approver
// demoted or suspended after that check gets the actor refusals, never a reset.
func refuseMFAResetApproverChanged(ctx context.Context, st storage.Storage, approver *models.User) error {
	if !approver.IsActive || AccountLoginBlocked(approver.ID, approver.AccountState) {
		return ErrMFAResetAdminRequired
	}
	role, err := isGlobalAdminRoleNameOn(ctx, st, approver.ID)
	if err != nil {
		return fmt.Errorf("check approver's admin role: %w", err)
	}
	if role == "" {
		return ErrMFAResetAdminRequired
	}
	if !userHasSecondFactor(approver) {
		return ErrMFAResetActorNeedsMFA
	}
	return nil
}

// lockMFAResetApprovalRows row-locks the requester, the approver and the target
// through tx in ascending user-ID order (one fixed order for every approval, so
// two concurrent approvals never wait on each other in a cycle) and returns the
// locked rows by ID. A requester or approver who no longer exists is
// ErrMFAResetRequesterChanged / ErrMFAResetAdminRequired.
func lockMFAResetApprovalRows(ctx context.Context, tx storage.Storage, requesterID, approverID, targetID uint) (map[uint]*models.User, error) {
	ids := []uint{requesterID, approverID, targetID}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	rows := make(map[uint]*models.User, len(ids))
	for _, id := range ids {
		var (
			u   *models.User
			err error
		)
		switch id {
		case requesterID:
			u, err = mfaResetRequester(ctx, tx, id, true)
		case approverID:
			u, err = tx.LockUserForUpdate(ctx, id)
			if storage.IsUserNotFound(err) {
				err = ErrMFAResetAdminRequired
			}
		default:
			u, err = tx.LockUserForUpdate(ctx, id)
		}
		if err != nil {
			return nil, err
		}
		rows[id] = u
	}
	return rows, nil
}

func evidenceSuffix(e string) string {
	if e == "" {
		return ""
	}
	return fmt.Sprintf(" (%q)", e)
}

// refuseMFAResetTarget is the target rule set of the online flow: the per-row
// rules, not a global admin (recover-admin is their path), and the actor meets
// the admin-rank ceiling over the target.
func (c *KeyorixCore) refuseMFAResetTarget(ctx context.Context, actorID uint, target *models.User) error {
	if err := validateMFAResetTarget(target); err != nil {
		return err
	}
	role, err := c.isGlobalAdminRoleName(ctx, target.ID)
	if err != nil {
		return fmt.Errorf("check target's admin role: %w", err)
	}
	if role != "" {
		return ErrMFAResetGlobalAdmin
	}
	return c.requireAdminRankCeilingForTarget(ctx, actorID, target.ID, "reset the MFA of")
}

// ApproveMFAReset approves request requestID on behalf of actorID and applies the
// reset. Refused (and the refusal audited where it is an attempt to get around
// dual control): the requester approving their own request, the target approving,
// a non-admin or machine approver, a request already approved or cancelled (a
// replay), an expired one, a requester who has since lost the admin role, and a
// target the rules refuse. Each of these refusals leaves a DENIED
// mfa.reset_approved row, whether decided before the transaction or inside it
// (written after the rollback, auditMFAResetApprovalDenied). Not covered: a
// request that does not exist, a storage error, and a failed re-authentication
// (requireReauth audits that one as mfa.failed / mfa.error).
func (c *KeyorixCore) ApproveMFAReset(ctx context.Context, actorID uint, actorIsMachine bool, requestID uint, code string) (*MFAResetApproval, error) {
	actor, err := c.requireMFAResetActor(ctx, actorID, actorIsMachine, EventMFAResetApproved, fmt.Sprintf("approval of request %d", requestID))
	if err != nil {
		return nil, err
	}
	req, err := c.storage.GetMFAResetRequest(ctx, requestID)
	if err != nil {
		if errors.Is(err, storage.ErrMFAResetRequestNotFound) {
			return nil, ErrMFAResetRequestNotFound
		}
		return nil, err
	}
	switch mfaResetEffectiveStatus(req, c.now()) {
	case models.MFAResetStatusPending:
	case "expired":
		c.auditMFAResetApprovalDenied(ctx, actorID, requestID, "it expired")
		return nil, ErrMFAResetRequestExpired
	default:
		c.auditMFAResetApprovalDenied(ctx, actorID, requestID, fmt.Sprintf("it is already %s", req.Status))
		return nil, ErrMFAResetRequestDecided
	}
	if actorID == req.RequestedBy {
		c.auditMFAResetApprovalDenied(ctx, actorID, requestID, fmt.Sprintf("requester %d cannot approve their own request", actorID))
		return nil, ErrMFAResetSelfApproval
	}
	if actorID == req.TargetUserID {
		c.auditMFAResetApprovalDenied(ctx, actorID, requestID, fmt.Sprintf("user %d is the target", actorID))
		return nil, ErrCannotActOnSelf
	}
	requester, err := mfaResetRequester(ctx, c.storage, req.RequestedBy, false)
	if err != nil {
		if errors.Is(err, ErrMFAResetRequesterChanged) {
			c.auditMFAResetApprovalDenied(ctx, actorID, requestID, fmt.Sprintf("requester %d no longer exists", req.RequestedBy))
		}
		return nil, err
	}
	if err := refuseMFAResetRequesterChanged(ctx, c.storage, requester); err != nil {
		if errors.Is(err, ErrMFAResetRequesterChanged) {
			c.auditMFAResetApprovalDenied(ctx, actorID, requestID, fmt.Sprintf("requester %d is no longer an active global administrator", req.RequestedBy))
		}
		return nil, err
	}
	target, err := c.storage.GetUser(ctx, req.TargetUserID)
	if err != nil {
		return nil, err
	}
	if err := c.refuseMFAResetTarget(ctx, actorID, target); err != nil {
		if why := mfaResetTargetRefusal(err, target.ID); why != "" {
			c.auditMFAResetApprovalDenied(ctx, actorID, requestID, why)
		}
		return nil, err
	}
	if err := c.requireReauth(ctx, actor, code, "mfa_reset_approve"); err != nil {
		return nil, err
	}

	otp, err := GenerateInitialCredential()
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(otp), PasswordHashCost())
	if err != nil {
		return nil, err
	}
	now := c.now()
	expiresAt := now.Add(c.effectiveOneTimePasswordExpiry()).UTC()
	var (
		eff *MFAResetEffect
		// denied is set by a refusal decided inside the transaction. Its DENIED row
		// is written after the rollback, through c.storage: written on tx it would
		// roll back with everything else.
		denied string
	)
	err = func() error {
		c.accountStateMu.Lock()
		defer c.accountStateMu.Unlock()
		return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			denied = ""
			deny := func(refusal error, why string) error {
				denied = why
				return refusal
			}
			// The decision first: of two concurrent approvals exactly one matches, and
			// the loser changes nothing (its transaction rolls back).
			matched, derr := tx.DecideMFAResetRequestIfPending(ctx, requestID, models.MFAResetStatusApproved, actorID, now)
			if derr != nil {
				return derr
			}
			if !matched {
				return deny(ErrMFAResetRequestDecided, "it was approved, cancelled or expired while this approval ran")
			}
			// Every rule read before the transaction holds again on the row locks of
			// the requester, the approver and the target, taken in ascending user-ID
			// order (two admins approving each other's requests cannot deadlock): a
			// suspension, demotion, IdP link or promotion of any of the three that
			// committed in between refuses the approval. Revocation wins.
			rows, lerr := lockMFAResetApprovalRows(ctx, tx, req.RequestedBy, actorID, req.TargetUserID)
			switch {
			case errors.Is(lerr, ErrMFAResetRequesterChanged):
				return deny(lerr, fmt.Sprintf("requester %d no longer exists", req.RequestedBy))
			case errors.Is(lerr, ErrMFAResetAdminRequired):
				return deny(lerr, fmt.Sprintf("approver %d no longer exists", actorID))
			case lerr != nil:
				return lerr
			}
			if qerr := refuseMFAResetRequesterChanged(ctx, tx, rows[req.RequestedBy]); qerr != nil {
				if errors.Is(qerr, ErrMFAResetRequesterChanged) {
					return deny(qerr, fmt.Sprintf("requester %d is no longer an active global administrator", req.RequestedBy))
				}
				return qerr
			}
			if aerr := refuseMFAResetApproverChanged(ctx, tx, rows[actorID]); aerr != nil {
				if errors.Is(aerr, ErrMFAResetAdminRequired) || errors.Is(aerr, ErrMFAResetActorNeedsMFA) {
					return deny(aerr, fmt.Sprintf("approver %d is no longer an active global administrator with a second factor", actorID))
				}
				return aerr
			}
			locked := rows[req.TargetUserID]
			if verr := validateMFAResetTarget(locked); verr != nil {
				return deny(verr, fmt.Sprintf("target %d changed: %v", locked.ID, verr))
			}
			if role, gerr := isGlobalAdminRoleNameOn(ctx, tx, locked.ID); gerr != nil {
				return fmt.Errorf("check target's admin role: %w", gerr)
			} else if role != "" {
				return deny(ErrMFAResetGlobalAdmin, fmt.Sprintf("target %d is now a global administrator", locked.ID))
			}
			e, rerr := ResetMFACredentialsInTx(ctx, tx, locked, string(hash), expiresAt, now)
			if rerr != nil {
				return rerr
			}
			eff = e
			target = locked
			c.writeAuditEventFullOn(ctx, tgt, EventMFAResetApproved, actorPtr(actorID), nil, nil, "",
				fmt.Sprintf("administrator %d approved MFA reset request %d (requested by %d) for user %d (%s)",
					actorID, requestID, req.RequestedBy, locked.ID, locked.Username))
			c.writeAuditEventFullOn(ctx, tgt, EventMFAReset, actorPtr(actorID), nil, nil, "",
				fmt.Sprintf("MFA of user %d (%s) reset by request %d (requested by %d, approved by %d): %s; one-time password expires %s",
					locked.ID, locked.Username, requestID, req.RequestedBy, actorID, e.Summary(), expiresAt.Format(time.RFC3339)))
			return nil
		})
	}()
	if err != nil {
		if denied != "" {
			c.auditMFAResetApprovalDenied(ctx, actorID, requestID, denied)
		}
		return nil, err
	}
	// After commit, never before: a rolled-back reset must not evict live entries.
	c.invalidateTokenCache(eff.EvictHashes...)
	c.auditCredentialDisplayedOutOfBand(ctx, actorPtr(actorID), target.Email, "one_time_password")
	c.notifyMFAResetAdmins(ctx, "MFA reset approved",
		fmt.Sprintf("The second factor of %q (user %d) was reset: requested by administrator %d, approved by administrator %d (request %d). Every session and token of the account was revoked.",
			target.Username, target.ID, req.RequestedBy, actorID, requestID))
	c.notifyMFAResetTarget(ctx, target.ID)
	return &MFAResetApproval{RequestID: requestID, UserID: target.ID, Username: target.Username,
		OneTimePassword: otp, ExpiresAt: expiresAt, Effect: eff}, nil
}

// CancelMFAReset withdraws a pending request. Any human global admin may cancel
// (the requester, or another admin who finds it unexpected); cancelling narrows,
// so it needs no re-authentication and its audit row is owed, never blocking it.
func (c *KeyorixCore) CancelMFAReset(ctx context.Context, actorID uint, actorIsMachine bool, requestID uint) error {
	if actorIsMachine || actorID == 0 {
		return ErrMFAResetAdminRequired
	}
	role, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return fmt.Errorf("check admin role: %w", err)
	}
	if role == "" {
		return ErrMFAResetAdminRequired
	}
	req, err := c.storage.GetMFAResetRequest(ctx, requestID)
	if err != nil {
		if errors.Is(err, storage.ErrMFAResetRequestNotFound) {
			return ErrMFAResetRequestNotFound
		}
		return err
	}
	if err := c.withOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		matched, derr := tx.DecideMFAResetRequestIfPending(ctx, requestID, models.MFAResetStatusCancelled, actorID, c.now())
		if derr != nil {
			return derr
		}
		if !matched {
			return ErrMFAResetRequestDecided
		}
		c.writeAuditEventFullOn(ctx, tgt, EventMFAResetCancelled, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("administrator %d cancelled MFA reset request %d (user %d, requested by %d)", actorID, requestID, req.TargetUserID, req.RequestedBy))
		return nil
	}); err != nil {
		return err
	}
	c.notifyMFAResetAdmins(ctx, "MFA reset request cancelled",
		fmt.Sprintf("Administrator %d cancelled MFA reset request %d for user %d.", actorID, requestID, req.TargetUserID))
	return nil
}

// ListMFAResetRequests lists requests for a human global admin, newest first.
func (c *KeyorixCore) ListMFAResetRequests(ctx context.Context, actorID uint, actorIsMachine, pendingOnly bool) ([]*MFAResetRequestView, error) {
	if actorIsMachine || actorID == 0 {
		return nil, ErrMFAResetAdminRequired
	}
	role, err := c.isGlobalAdminRoleName(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("check admin role: %w", err)
	}
	if role == "" {
		return nil, ErrMFAResetAdminRequired
	}
	rows, err := c.storage.ListMFAResetRequests(ctx, pendingOnly)
	if err != nil {
		return nil, err
	}
	now := c.now()
	out := make([]*MFAResetRequestView, 0, len(rows))
	for _, r := range rows {
		v := &MFAResetRequestView{MFAResetRequest: r, EffectiveStatus: mfaResetEffectiveStatus(r, now)}
		if pendingOnly && v.EffectiveStatus != models.MFAResetStatusPending {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// notifyMFAResetAdmins tells every install-wide admin about a step of an MFA
// reset. Best effort, after the commit: a missed notice is a detection gap, never
// a reason to fail a committed step, and it is logged.
func (c *KeyorixCore) notifyMFAResetAdmins(ctx context.Context, title, msg string) {
	// The admin lookup is storage work too: a panic in it (the transport's recovery
	// would turn it into a 500 for a step that already committed, and for an
	// approval lose the one-time password) is logged like an error, not propagated.
	ids, err := func() (ids []uint, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return c.globalAdminIDs(ctx)
	}()
	if err != nil {
		log.Printf("SECURITY: MFA reset notification: could not list the admins (%v); %q was not delivered", err, title)
	}
	for _, id := range ids {
		func() {
			defer recoverPostCommitNotifyPanic(EventMFAReset, id)
			c.notifyWithSeverity(ctx, id, EventMFAReset, title, msg, nil, "/admin/users", models.NotificationSeverityCritical)
		}()
	}
}

// notifyMFAResetTarget tells the reset user, in-app (they see it after signing in
// with the one-time password; the approver's out-of-band call is the immediate
// notice).
func (c *KeyorixCore) notifyMFAResetTarget(ctx context.Context, userID uint) {
	defer recoverPostCommitNotifyPanic(EventMFAReset, userID)
	c.notifyWithSeverity(ctx, userID, EventMFAReset, "Your second factor was reset",
		"Two administrators reset your MFA: your authenticator, passkeys and recovery codes were removed and every session and token was ended. "+
			"Choose a new password and enrol a new authenticator. If you did not ask for this, contact your administrator now.",
		nil, "/account/security", models.NotificationSeverityCritical)
}

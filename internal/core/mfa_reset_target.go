// mfa_reset_target.go — which accounts an administrator MFA reset may touch
// (RECOVERY-MFA-RESET-1), shared by the host command and the online flow.
package core

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Fixed client-facing texts of the target refusals. Transports send these
// constants, never err.Error().
const (
	MFAResetTargetNotFoundMessage   = "no such user"
	MFAResetMachineIdentityMessage  = "that name is a machine identity: machine identities have no second factor to reset; rotate or revoke its credentials instead"
	MFAResetExternalIdentityMessage = "this account is managed by an external identity provider, which owns its second factor; reset it there"
	MFAResetAccountBlockedMessage   = "account is suspended or inactive; reactivate it before resetting its MFA"
	MFAResetGlobalAdminMessage      = "this account holds a global-admin role: recover it on the server host with `keyorix-server admin recover-admin`"
)

var (
	ErrMFAResetTargetNotFound   = errors.New(MFAResetTargetNotFoundMessage)
	ErrMFAResetMachineIdentity  = errors.New(MFAResetMachineIdentityMessage)
	ErrMFAResetExternalIdentity = errors.New(MFAResetExternalIdentityMessage)
	ErrMFAResetAccountBlocked   = errors.New(MFAResetAccountBlockedMessage)
	ErrMFAResetGlobalAdmin      = errors.New(MFAResetGlobalAdminMessage)
)

// ResolveMFAResetTarget finds the user an MFA reset names: a numeric user id, an
// email address, or a username. A reference that matches no user but does name a
// machine identity is refused with ErrMFAResetMachineIdentity, so an operator who
// typed a service's name is told why rather than "no such user".
func ResolveMFAResetTarget(ctx context.Context, st storage.Storage, ref string) (*models.User, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("a user (id, email or username) is required")
	}
	var (
		u   *models.User
		err error
	)
	// bitSize 32: user ids fit, and the uint conversion cannot overflow.
	if id, perr := strconv.ParseUint(ref, 10, 32); perr == nil {
		u, err = st.GetUser(ctx, uint(id))
	} else if strings.Contains(ref, "@") {
		u, err = st.GetUserByEmail(ctx, ref)
	} else {
		u, err = st.GetUserByUsername(ctx, ref)
	}
	if err == nil && u != nil {
		return u, nil
	}
	if err != nil && !storage.IsUserNotFound(err) {
		return nil, err
	}
	machines, merr := st.ListAllMachineIdentities(ctx)
	if merr != nil {
		return nil, fmt.Errorf("%w (and the machine identities could not be checked: %w)", ErrMFAResetTargetNotFound, merr)
	}
	for _, m := range machines {
		if m.Name == ref {
			return nil, ErrMFAResetMachineIdentity
		}
	}
	return nil, ErrMFAResetTargetNotFound
}

// validateMFAResetTarget is the per-row part of the target rules, checked on the
// row lock inside the reset's own transaction: a local account (an IdP-managed
// one has its factor at the IdP), active and not login-blocked (a reset puts the
// account into password_reset_required, a login-able state, so it would silently
// reactivate a suspended account). The global-admin rule needs the role tables
// and is checked by each caller.
func validateMFAResetTarget(u *models.User) error {
	if u.ExternalID != "" {
		return ErrMFAResetExternalIdentity
	}
	if !u.IsActive || AccountLoginBlocked(u.ID, u.AccountState) {
		return ErrMFAResetAccountBlocked
	}
	return nil
}

// ValidateMFAResetTarget is validateMFAResetTarget for the host command.
func ValidateMFAResetTarget(u *models.User) error { return validateMFAResetTarget(u) }

package faultops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// POST /auth/setup/consume with an invitation_accept token (PARTIAL-COMMIT-TAILS-NOV-3
// item 2): the invitee sets a password, the account is created lazily (through
// c.CreateUser, so its create transaction reads a lost ack back, #4208), the link
// is spent, the invitation's project role is granted, the invitation flips to
// accepted and a session is minted. Several commits, not one transaction: each
// later failure undoes what came before (abandonInvitationAccept). The
// account_setup op on the same route (ops_auth_setup_consume_test.go) never
// reaches this function, so this is a variant key of that route (op_variant_key_test.go).
//
// Setup is deterministic (fixed token, fixed rows), as for the account_setup op:
// oracle (a) compares with an independently built reference world.
const (
	setupInvitationOpKey    = "REST POST /auth/setup/consume" + opVariantSep + "invitation_accept"
	setupInvitationRawToken = "kxst_fuzz-setup-invitation-token-0001"
	setupInvitationEmail    = "fuzzinvitee@example.com"
)

func seedSetupInvitation(ctx context.Context, w *faultWorld) error {
	db := w.db.WithContext(ctx)
	var project models.Project
	if err := db.Where("name = ?", "default").First(&project).Error; err != nil {
		return err
	}
	var admin models.User
	if err := db.Where("username = ?", "faultadmin").First(&admin).Error; err != nil {
		return err
	}
	expires := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	inv := &models.ProjectInvitation{
		ProjectID: project.ID, Email: setupInvitationEmail, Role: "project_viewer",
		State: "pending", InvitedBy: admin.ID, ValidationModeAtInvite: "open", ExpiresAt: &expires,
	}
	if err := db.Create(inv).Error; err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(setupInvitationRawToken))
	invID := inv.ID
	return db.Create(&models.SetupToken{
		TokenHash: hex.EncodeToString(sum[:]), Purpose: "invitation_accept",
		InvitationID: &invID, SubjectEmail: setupInvitationEmail, State: "active", ExpiresAt: expires,
	}).Error
}

func init() {
	wrongCredentialRequests[setupInvitationOpKey] = setupConsumeDeadTokenRequest
	registerOps("auth_setup_consume_invitation", operation{
		Key: setupInvitationOpKey,
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			return nil, seedSetupInvitation(ctx, w)
		},
		Execute: func(ctx context.Context, w *faultWorld, _ any) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/setup/consume", map[string]any{
				"token": setupInvitationRawToken, "password": setupConsumeNewPassword,
			})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
	})
	registerOverrides("auth_setup_consume_invitation", map[string]overrideEntry{
		setupInvitationOpKey: {StatusFuzzed, "PARTIAL-COMMIT-TAILS-NOV-3 item 2: the invitation_accept purpose of POST /auth/setup/consume (completeInvitationAccept)"},
	})
}

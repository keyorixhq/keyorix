// pat.go — Personal Access Tokens (ADR-027).
//
// A PAT is a long-lived bearer credential a user creates from the My Account page.
// It authenticates API requests AS that user, inheriting their full permission set
// (no per-token scoping in v1). The raw token is returned once on creation; only its
// SHA-256 hash is stored. Raw tokens carry the patPrefix so the auth middleware can
// route them to ValidatePATToken and secret scanners can detect leaks.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	// patPrefix marks a raw PAT. Load-bearing: middleware routing + secret scanning.
	patPrefix = "kx_pat_"
	// patTouchInterval throttles last_used_at writes on the auth hot path.
	patTouchInterval = 30 * time.Second
)

// CreatePATResult carries the freshly created token plus its one-time plaintext.
// The plaintext is never persisted and never returned again.
type CreatePATResult struct {
	Token      *models.PersonalAccessToken
	PlainToken string
}

// hashPAT returns the SHA-256 hex of a raw token — the stored, indexed form.
func hashPAT(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateOwnPAT generates a new personal access token for the caller. expiresAt may
// be nil for a non-expiring token.
func (c *KeyorixCore) CreateOwnPAT(ctx context.Context, userID uint, name string, expiresAt *time.Time) (*CreatePATResult, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s: token name is required", i18n.T("ErrorValidation", nil))
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := patPrefix + base64.RawURLEncoding.EncodeToString(b)

	pat := &models.PersonalAccessToken{
		UserID:      userID,
		Name:        strings.TrimSpace(name),
		TokenHash:   hashPAT(raw),
		TokenPrefix: raw[:len(patPrefix)+6], // e.g. "kx_pat_ab12cd" for display
		ExpiresAt:   expiresAt,
		CreatedAt:   c.now(),
	}
	created, err := c.storage.CreatePersonalAccessToken(ctx, pat)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &CreatePATResult{Token: created, PlainToken: raw}, nil
}

// ListOwnPATs returns the caller's tokens (hashes are never exposed by the HTTP DTO).
func (c *KeyorixCore) ListOwnPATs(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListPersonalAccessTokensByUser(ctx, userID)
}

// RevokeOwnPAT revokes one of the caller's tokens after verifying ownership. A token
// owned by another user is reported as not found to prevent ID enumeration.
func (c *KeyorixCore) RevokeOwnPAT(ctx context.Context, userID, tokenID uint) error {
	if userID == 0 || tokenID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and token IDs are required")
	}
	pat, err := c.storage.GetPersonalAccessTokenByID(ctx, tokenID)
	if err != nil || pat.UserID != userID {
		return fmt.Errorf("%s: token not found", i18n.T("ErrorNotFound", nil))
	}
	return c.storage.RevokePersonalAccessToken(ctx, tokenID)
}

// ValidatePATToken resolves a raw PAT to its owning user and role names, mirroring
// the shape of ValidateSessionToken so the auth middleware can use either. It rejects
// revoked/expired tokens and inactive users, and best-effort throttled-updates
// last_used_at. The caller (middleware) is expected to gate on the patPrefix.
func (c *KeyorixCore) ValidatePATToken(ctx context.Context, raw string) (*models.User, []string, error) {
	if !strings.HasPrefix(raw, patPrefix) {
		return nil, nil, fmt.Errorf("not a personal access token")
	}
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, hashPAT(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token")
	}
	if pat.Revoked {
		return nil, nil, fmt.Errorf("token revoked")
	}
	if pat.ExpiresAt != nil && c.now().After(*pat.ExpiresAt) {
		return nil, nil, fmt.Errorf("token expired")
	}
	user, err := c.storage.GetUser(ctx, pat.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, nil, fmt.Errorf("user inactive")
	}

	// Best-effort, throttled last-used stamp — never fails the request.
	_ = c.storage.TouchPersonalAccessToken(ctx, pat.ID, c.now(), patTouchInterval)

	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, nil
}

// pat.go — Personal Access Tokens (ADR-027, ADR-042).
//
// A PAT is a long-lived bearer credential a user creates from the My Account page.
// It authenticates API requests AS that user. By default it inherits the owner's
// full permission set; optionally (ADR-042) it carries a least-privilege
// restriction — a permission allowlist and/or a single-project or single-
// environment scope — that narrows it below the owner (never above). The raw
// token is returned once on
// creation; only its SHA-256 hash is stored. Raw tokens carry the patPrefix so the
// auth middleware can route them to ValidatePATToken and secret scanners can detect
// leaks.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

// CreateOwnPAT generates a new personal access token for the caller. expiresAt may
// be nil for a non-expiring token. scopes, when non-empty, is a least-privilege
// permission allowlist (ADR-042); projectScope/environmentScope, when non-zero,
// confine the token to a single project / environment. All only ever NARROW the
// token below its owner — they are enforced at request time as a filter
// intersected with the owner's live permissions, so a token can never grant more
// than its owner currently holds.
func (c *KeyorixCore) CreateOwnPAT(ctx context.Context, userID uint, name string, expiresAt *time.Time, scopes []string, projectScope, environmentScope uint) (*CreatePATResult, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s: token name is required", i18n.T("ErrorValidation", nil))
	}

	scopesJSON, err := encodePATScopes(scopes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := patPrefix + base64.RawURLEncoding.EncodeToString(b)

	pat := &models.PersonalAccessToken{
		UserID:           userID,
		Name:             strings.TrimSpace(name),
		TokenHash:        sha256Hex(raw),
		TokenPrefix:      raw[:len(patPrefix)+6], // e.g. "kx_pat_ab12cd" for display
		Scopes:           scopesJSON,
		ProjectScope:     projectScope,
		EnvironmentScope: environmentScope,
		ExpiresAt:        expiresAt,
		CreatedAt:        c.now(),
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

// ValidatePATToken resolves a raw PAT to its owning user, role names, and any
// least-privilege restriction (ADR-042; nil when the token is unrestricted),
// mirroring the shape of ValidateSessionToken so the auth middleware can use
// either. It rejects revoked/expired tokens and inactive users, and best-effort
// throttled-updates last_used_at. The caller (middleware) is expected to gate on
// the patPrefix.
func (c *KeyorixCore) ValidatePATToken(ctx context.Context, raw string) (*models.User, []string, *PATRestriction, error) {
	if !strings.HasPrefix(raw, patPrefix) {
		return nil, nil, nil, fmt.Errorf("not a personal access token")
	}
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid token")
	}
	if pat.Revoked {
		return nil, nil, nil, fmt.Errorf("token revoked")
	}
	if pat.ExpiresAt != nil && c.now().After(*pat.ExpiresAt) {
		return nil, nil, nil, fmt.Errorf("token expired")
	}
	user, err := c.storage.GetUser(ctx, pat.UserID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, nil, nil, fmt.Errorf("user inactive")
	}
	// A suspended/blocked account must not authenticate via a PAT either. SuspendUser sets
	// account_state but deliberately leaves is_active untouched (and kills sessions), so
	// without this an admin's suspend would cut off session access yet leave the user's
	// personal access tokens fully working. Mirror ValidateSessionToken's account-state
	// gate so suspension is immediately effective on every credential type.
	if AccountLoginBlocked(user.AccountState) {
		return nil, nil, nil, fmt.Errorf("account is not active")
	}

	// Best-effort, throttled last-used stamp — never fails the request.
	_ = c.storage.TouchPersonalAccessToken(ctx, pat.ID, c.now(), patTouchInterval)

	restriction := patRestrictionFrom(pat)

	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, restriction, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, restriction, nil
}

// encodePATScopes normalises and JSON-encodes a permission allowlist for storage.
// Blank entries are dropped and duplicates removed; an all-blank/empty list
// encodes to "" so the token stays unrestricted (the back-compat default).
func encodePATScopes(scopes []string) (string, error) {
	cleaned := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodePATScopes parses a stored scopes column back into a permission list.
// An empty/invalid column yields nil (unrestricted) — fail-open here is correct
// because an empty allowlist already means "inherit the owner", and the owner's
// own RBAC still gates every action.
func DecodePATScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// patRestrictionFrom builds the request-time restriction for a token, or nil when
// the token is unrestricted (no scopes and no project confinement).
func patRestrictionFrom(pat *models.PersonalAccessToken) *PATRestriction {
	scopes := DecodePATScopes(pat.Scopes)
	if len(scopes) == 0 && pat.ProjectScope == 0 && pat.EnvironmentScope == 0 {
		return nil
	}
	return &PATRestriction{Permissions: scopes, ProjectID: pat.ProjectScope, EnvironmentID: pat.EnvironmentScope}
}

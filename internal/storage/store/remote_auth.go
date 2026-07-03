// remote_auth.go — Session and Personal Access Token / Setup Token operations for
// RemoteStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
// personal access tokens (ADR-027), and setup tokens (ADR-028).
//
// For the local (GORM) equivalent see local_auth.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Sessions ---

// CreateSession creates a new session via remote API.
func (rs *RemoteStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/sessions", session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create session failed: %s", resp.Error.Error())
	}
	var result models.Session
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetSession retrieves a session by token via remote API.
func (rs *RemoteStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	path := fmt.Sprintf("/api/v1/sessions/%s", url.PathEscape(token))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get session failed: %s", resp.Error.Error())
	}
	var result models.Session
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteSession deletes a session via remote API.
func (rs *RemoteStorage) DeleteSession(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/sessions/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete session failed: %s", resp.Error.Error())
	}
	return nil
}

// CleanupExpiredSessions triggers server-side session cleanup via remote API.
func (rs *RemoteStorage) CleanupExpiredSessions(ctx context.Context) error {
	resp, err := rs.client.Post(ctx, "/api/v1/sessions/cleanup", nil)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("cleanup expired sessions failed: %s", resp.Error.Error())
	}
	return nil
}

// --- Sessions (My Account) + Personal Access Tokens ---
//
// These methods exist to satisfy the Storage interface. Session validation and
// PAT auth run server-side against LocalStorage; the remote (CLI) client manages
// its own credentials over the public /api/v1/auth/* HTTP API directly, not
// through these storage methods. The server-only hot-path lookups therefore
// return errUnsupportedRemote, and the best-effort "touch" calls are no-ops.

var errUnsupportedRemote = fmt.Errorf("operation not supported over remote storage")

func (rs *RemoteStorage) GetSessionByID(_ context.Context, _ uint) (*models.Session, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) ListSessionsByUser(_ context.Context, _ uint) ([]*models.Session, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) DeleteSessionsForUserExcept(_ context.Context, _, _ uint) error {
	return errUnsupportedRemote
}

func (rs *RemoteStorage) ListSessionTokenHashesForUser(_ context.Context, _ uint) ([]string, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) EnforceSessionLimit(_ context.Context, _ uint, _ int) error {
	return errUnsupportedRemote
}

func (rs *RemoteStorage) TouchSession(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return nil // best-effort; no-op on remote storage
}

func (rs *RemoteStorage) CreatePersonalAccessToken(_ context.Context, _ *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) ListPersonalAccessTokensByUser(_ context.Context, _ uint) ([]*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) ListActivePersonalAccessTokens(_ context.Context) ([]*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) GetPersonalAccessTokenByID(_ context.Context, _ uint) (*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) GetPersonalAccessTokenByHash(_ context.Context, _ string) (*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) RevokePersonalAccessToken(_ context.Context, _ uint) error {
	return errUnsupportedRemote
}

func (rs *RemoteStorage) RevokeAllPersonalAccessTokensForUser(_ context.Context, _ uint) ([]string, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) TouchPersonalAccessToken(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return nil // best-effort; no-op on remote storage
}

// Setup Token Management (ADR-028) — credential delivery is a server-side concern;
// a remote CLI client does not mint or consume setup tokens.

func (rs *RemoteStorage) CreateSetupToken(_ context.Context, _ *models.SetupToken) (*models.SetupToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) GetSetupTokenByHash(_ context.Context, _ string) (*models.SetupToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) SupersedeActiveSetupTokens(_ context.Context, _, _ string) error {
	return errUnsupportedRemote
}

func (rs *RemoteStorage) MarkSetupTokenConsumed(_ context.Context, _ uint, _ time.Time) (bool, error) {
	return false, errUnsupportedRemote
}

func (rs *RemoteStorage) MarkSetupTokenExpired(_ context.Context, _ uint) error {
	return errUnsupportedRemote
}

func (rs *RemoteStorage) CountSetupTokensSince(_ context.Context, _, _ string, _ time.Time) (int64, error) {
	return 0, errUnsupportedRemote
}

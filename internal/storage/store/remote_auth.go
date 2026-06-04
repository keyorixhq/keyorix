// remote_auth.go — Session and API Client/Token operations for RemoteStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
//
//	CreateAPIClient, GetAPIClient, RevokeAPIClient, ListAPIClients, UpdateAPIClient,
//	CreateAPIToken, GetAPIToken, ListAPITokens, RevokeAPIToken.
//
// For the local (GORM) equivalent see local_auth.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
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
	path := fmt.Sprintf("/api/v1/sessions/%s", token)
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

// --- API Clients ---

// CreateAPIClient creates a new API client via remote API.
func (rs *RemoteStorage) CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/api-clients", client)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create API client failed: %s", resp.Error.Error())
	}
	var result models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetAPIClient retrieves an API client by client ID via remote API.
func (rs *RemoteStorage) GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error) {
	path := fmt.Sprintf("/api/v1/api-clients/%s", clientID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get API client: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get API client failed: %s", resp.Error.Error())
	}
	var result models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// RevokeAPIClient revokes an API client via remote API.
func (rs *RemoteStorage) RevokeAPIClient(ctx context.Context, clientID string) error {
	path := fmt.Sprintf("/api/v1/api-clients/%s/revoke", clientID)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke API client: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("revoke API client failed: %s", resp.Error.Error())
	}
	return nil
}

// ListAPIClients retrieves all API clients via remote API.
func (rs *RemoteStorage) ListAPIClients(ctx context.Context) ([]*models.APIClient, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/service-accounts")
	if err != nil {
		return nil, fmt.Errorf("failed to list API clients: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list API clients failed: %s", resp.Error.Error())
	}
	var result []*models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// UpdateAPIClient updates an API client via remote API.
func (rs *RemoteStorage) UpdateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	path := fmt.Sprintf("/api/v1/service-accounts/%s", client.ClientID)
	resp, err := rs.client.Put(ctx, path, client)
	if err != nil {
		return nil, fmt.Errorf("failed to update API client: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update API client failed: %s", resp.Error.Error())
	}
	var result models.APIClient
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// --- API Tokens ---

// CreateAPIToken creates a new API token via remote API.
func (rs *RemoteStorage) CreateAPIToken(ctx context.Context, token *models.APIToken) (*models.APIToken, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/api-tokens", token)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create API token failed: %s", resp.Error.Error())
	}
	var result models.APIToken
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetAPIToken retrieves an API token by ID via remote API.
func (rs *RemoteStorage) GetAPIToken(ctx context.Context, id uint) (*models.APIToken, error) {
	path := fmt.Sprintf("/api/v1/api-tokens/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get API token failed: %s", resp.Error.Error())
	}
	var result models.APIToken
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListAPITokens retrieves API tokens, optionally filtered by clientID, via remote API.
func (rs *RemoteStorage) ListAPITokens(ctx context.Context, clientID *uint) ([]*models.APIToken, error) {
	path := "/api/v1/api-tokens"
	if clientID != nil {
		path = fmt.Sprintf("%s?client_id=%d", path, *clientID)
	}
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list API tokens: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list API tokens failed: %s", resp.Error.Error())
	}
	var result []*models.APIToken
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// RevokeAPIToken revokes an API token via remote API.
func (rs *RemoteStorage) RevokeAPIToken(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/api-tokens/%d/revoke", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke API token: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("revoke API token failed: %s", resp.Error.Error())
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

func (rs *RemoteStorage) TouchSession(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return nil // best-effort; no-op on remote storage
}

func (rs *RemoteStorage) CreatePersonalAccessToken(_ context.Context, _ *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	return nil, errUnsupportedRemote
}

func (rs *RemoteStorage) ListPersonalAccessTokensByUser(_ context.Context, _ uint) ([]*models.PersonalAccessToken, error) {
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

func (rs *RemoteStorage) TouchPersonalAccessToken(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return nil // best-effort; no-op on remote storage
}

// remote_auth.go — Session and API Client operations for RemoteStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
//
//	CreateAPIClient, GetAPIClient, RevokeAPIClient.
//
// For the local (GORM) equivalent see local_auth.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

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

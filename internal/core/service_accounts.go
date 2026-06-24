// service_accounts.go — Service account and API token business logic.
//
// Routes (all under /api/v1/service-accounts):
//
//	GET    /                            — List service accounts
//	POST   /                            — Create service account (returns plain secret once)
//	GET    /{clientId}                  — Get service account
//	PUT    /{clientId}                  — Update service account
//	DELETE /{clientId}                  — Revoke service account
//	GET    /{clientId}/tokens           — List tokens for a service account
//	POST   /{clientId}/tokens           — Create token (returns plain token once)
//	DELETE /{clientId}/tokens/{tokenId} — Revoke token
package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateServiceAccountRequest holds input for creating a service account.
type CreateServiceAccountRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Description string `json:"description"`
	Scopes      string `json:"scopes"`
}

// UpdateServiceAccountRequest holds fields that may be updated on a service account.
type UpdateServiceAccountRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Description string `json:"description"`
	Scopes      string `json:"scopes"`
	IsActive    bool   `json:"is_active"`
}

// CreateServiceAccountResult wraps the created APIClient with the one-time plain secret.
type CreateServiceAccountResult struct {
	*models.APIClient
	PlainClientSecret string `json:"client_secret"`
}

// CreateServiceTokenRequest holds input for creating an API token.
type CreateServiceTokenRequest struct {
	Scope     string     `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at"`
	UserID    *uint      `json:"user_id"`
}

// CreateServiceTokenResult wraps the created APIToken with the one-time plain token.
type CreateServiceTokenResult struct {
	*models.APIToken
	PlainToken string `json:"token"`
}

// CreateServiceAccount generates a new service account with a random client ID and secret.
// The plain secret is returned only in the result and never stored retrievably.
func (c *KeyorixCore) CreateServiceAccount(ctx context.Context, req *CreateServiceAccountRequest) (*CreateServiceAccountResult, error) {
	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}
	secret, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Store only the SHA-256 hash of the client secret, never the plaintext — matching
	// how session tokens, PATs, machine tokens and setup tokens are persisted. The
	// plaintext is returned once to the caller (below) and never kept retrievably, so a
	// database read (backup, replica, injection, insider) yields no usable credential.
	client := &models.APIClient{
		Name:         req.Name,
		Description:  req.Description,
		ClientID:     clientID,
		ClientSecret: sha256Hex(secret),
		Scopes:       req.Scopes,
		IsActive:     true,
	}
	created, err := c.storage.CreateAPIClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}
	return &CreateServiceAccountResult{APIClient: created, PlainClientSecret: secret}, nil
}

// GetServiceAccount retrieves a service account by its string client ID.
func (c *KeyorixCore) GetServiceAccount(ctx context.Context, clientID string) (*models.APIClient, error) {
	client, err := c.storage.GetAPIClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("service account not found")
	}
	return client, nil
}

// ListServiceAccounts returns all service accounts.
func (c *KeyorixCore) ListServiceAccounts(ctx context.Context) ([]*models.APIClient, error) {
	clients, err := c.storage.ListAPIClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}
	return clients, nil
}

// UpdateServiceAccount applies name/description/scopes/is_active changes to a service account.
func (c *KeyorixCore) UpdateServiceAccount(ctx context.Context, clientID string, req *UpdateServiceAccountRequest) (*models.APIClient, error) {
	client, err := c.storage.GetAPIClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("service account not found")
	}

	client.Name = req.Name
	client.Description = req.Description
	client.Scopes = req.Scopes
	client.IsActive = req.IsActive

	updated, err := c.storage.UpdateAPIClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to update service account: %w", err)
	}
	return updated, nil
}

// RevokeServiceAccount marks the service account as inactive (soft revoke).
func (c *KeyorixCore) RevokeServiceAccount(ctx context.Context, clientID string) error {
	if _, err := c.storage.GetAPIClient(ctx, clientID); err != nil {
		return fmt.Errorf("service account not found")
	}
	if err := c.storage.RevokeAPIClient(ctx, clientID); err != nil {
		return fmt.Errorf("failed to revoke service account: %w", err)
	}
	return nil
}

// CreateServiceToken generates a new API token for the given service account.
// The plain token is returned only in the result and never stored retrievably.
func (c *KeyorixCore) CreateServiceToken(ctx context.Context, clientID string, req *CreateServiceTokenRequest) (*CreateServiceTokenResult, error) {
	client, err := c.storage.GetAPIClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("service account not found")
	}
	if !client.IsActive {
		return nil, fmt.Errorf("service account is revoked")
	}

	plainToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Store only the SHA-256 hash of the token, never the plaintext (see
	// CreateServiceAccount). The hash is unique per token, satisfying the column's
	// unique index, and the plaintext is returned to the caller exactly once below.
	token := &models.APIToken{
		ClientID:  client.ID,
		UserID:    req.UserID,
		Token:     sha256Hex(plainToken),
		Scope:     req.Scope,
		Revoked:   false,
		ExpiresAt: req.ExpiresAt,
	}
	created, err := c.storage.CreateAPIToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create API token: %w", err)
	}
	return &CreateServiceTokenResult{APIToken: created, PlainToken: plainToken}, nil
}

// GetServiceToken retrieves an API token by its numeric ID.
func (c *KeyorixCore) GetServiceToken(ctx context.Context, id uint) (*models.APIToken, error) {
	token, err := c.storage.GetAPIToken(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}
	return token, nil
}

// ListServiceTokens returns all tokens for the given service account.
func (c *KeyorixCore) ListServiceTokens(ctx context.Context, clientID string) ([]*models.APIToken, error) {
	client, err := c.storage.GetAPIClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("service account not found")
	}
	tokens, err := c.storage.ListAPITokens(ctx, &client.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	return tokens, nil
}

// RevokeServiceToken marks an API token as revoked.
func (c *KeyorixCore) RevokeServiceToken(ctx context.Context, id uint) error {
	if _, err := c.storage.GetAPIToken(ctx, id); err != nil {
		return fmt.Errorf("token not found")
	}
	if err := c.storage.RevokeAPIToken(ctx, id); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// generateClientID returns a unique service-account identifier prefixed with "kx-client-".
func generateClientID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("kx-client-%x", b), nil
}

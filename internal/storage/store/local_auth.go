// local_auth.go — Session and API Client/Token operations for LocalStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
//
//	CreateAPIClient, GetAPIClient, RevokeAPIClient, ListAPIClients, UpdateAPIClient,
//	CreateAPIToken, GetAPIToken, ListAPITokens, RevokeAPIToken.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_auth.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Sessions ---

func (ls *LocalStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if err := ls.db.WithContext(ctx).Create(session).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return session, nil
}

func (ls *LocalStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).Where("session_token = ?", token).First(&session).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &session, nil
}

func (ls *LocalStorage) DeleteSession(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Session{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// CleanupExpiredSessions hard-deletes all sessions whose expires_at is in the past.
func (ls *LocalStorage) CleanupExpiredSessions(ctx context.Context) error {
	return ls.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{}).Error
}

// --- API Clients ---

func (ls *LocalStorage) CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	if err := ls.db.WithContext(ctx).Create(client).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return client, nil
}

func (ls *LocalStorage) GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error) {
	var client models.APIClient
	if err := ls.db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &client, nil
}

// RevokeAPIClient sets is_active = false; does not delete the record.
func (ls *LocalStorage) RevokeAPIClient(ctx context.Context, clientID string) error {
	result := ls.db.WithContext(ctx).Model(&models.APIClient{}).
		Where("client_id = ?", clientID).
		Update("is_active", false)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) ListAPIClients(ctx context.Context) ([]*models.APIClient, error) {
	var clients []*models.APIClient
	if err := ls.db.WithContext(ctx).Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("failed to list API clients: %w", err)
	}
	return clients, nil
}

func (ls *LocalStorage) UpdateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	if err := ls.db.WithContext(ctx).Save(client).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return client, nil
}

// --- API Tokens ---

func (ls *LocalStorage) CreateAPIToken(ctx context.Context, token *models.APIToken) (*models.APIToken, error) {
	if err := ls.db.WithContext(ctx).Create(token).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return token, nil
}

func (ls *LocalStorage) GetAPIToken(ctx context.Context, id uint) (*models.APIToken, error) {
	var token models.APIToken
	if err := ls.db.WithContext(ctx).First(&token, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &token, nil
}

func (ls *LocalStorage) ListAPITokens(ctx context.Context, clientID *uint) ([]*models.APIToken, error) {
	query := ls.db.WithContext(ctx).Model(&models.APIToken{})
	if clientID != nil {
		query = query.Where("client_id = ?", *clientID)
	}
	var tokens []*models.APIToken
	if err := query.Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("failed to list API tokens: %w", err)
	}
	return tokens, nil
}

// RevokeAPIToken sets revoked = true; does not delete the record.
func (ls *LocalStorage) RevokeAPIToken(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Model(&models.APIToken{}).
		Where("id = ?", id).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

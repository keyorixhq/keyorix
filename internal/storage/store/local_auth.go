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

func (ls *LocalStorage) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).First(&session, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &session, nil
}

// ListSessionsByUser returns the user's non-expired sessions, most-recently-seen first.
func (ls *LocalStorage) ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error) {
	var sessions []*models.Session
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", userID, time.Now()).
		Order("created_at DESC").
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return sessions, nil
}

func (ls *LocalStorage) DeleteSession(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Session{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// DeleteSessionsForUserExcept removes all of the user's sessions except exceptID.
func (ls *LocalStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	result := ls.db.WithContext(ctx).
		Where("user_id = ? AND id <> ?", userID, exceptID).
		Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// TouchSession bumps last_seen_at only if the stored value is older than staleness
// (or NULL), keeping the auth hot path from writing on every request.
func (ls *LocalStorage) TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error {
	cutoff := seenAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)", id, cutoff).
		UpdateColumn("last_seen_at", seenAt).Error
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

// --- Personal Access Tokens (ADR-027) ---

func (ls *LocalStorage) CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	if err := ls.db.WithContext(ctx).Create(t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return t, nil
}

func (ls *LocalStorage) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	var tokens []*models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return tokens, nil
}

func (ls *LocalStorage) GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).First(&t, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// GetPersonalAccessTokenByHash is the auth hot-path lookup (indexed equality on token_hash).
func (ls *LocalStorage) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// RevokePersonalAccessToken sets revoked = true; does not delete the record.
func (ls *LocalStorage) RevokePersonalAccessToken(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
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

// TouchPersonalAccessToken bumps last_used_at only when older than staleness (or NULL),
// keeping the auth hot path from writing on every request (mirrors TouchSession).
func (ls *LocalStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	cutoff := usedAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, cutoff).
		UpdateColumn("last_used_at", usedAt).Error
}

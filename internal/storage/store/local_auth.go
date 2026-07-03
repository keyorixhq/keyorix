// local_auth.go — Session and Personal Access Token / Setup Token operations for
// LocalStorage.
//
// Covers: CreateSession, GetSession, DeleteSession, CleanupExpiredSessions,
// personal access tokens (ADR-027), and setup tokens (ADR-028).
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_auth.go.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Sessions ---

// hashSessionToken is the at-rest representation of a session token. Sessions, like
// PATs / machine / setup tokens, are stored only as a SHA-256 hash so a database read
// (backup, replica, injection, insider) never yields a live, replayable token. The
// plaintext lives only in the client's possession.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (ls *LocalStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	// Persist the hash, not the plaintext token. Hand the plaintext back to the caller
	// (it must reach the client) but keep it out of the row; the column holds the hash.
	plaintext := session.SessionToken
	session.SessionToken = hashSessionToken(plaintext)
	err := ls.db.WithContext(ctx).Create(session).Error
	session.SessionToken = plaintext // restore for the caller (transient, never re-stored)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return session, nil
}

// GetSession looks up a LIVE session by the hash of the presented token — the row
// stores only the hash. A rotated row (RotatedAt set) is excluded: it must
// authenticate nothing, exactly like a deleted row (#211).
func (ls *LocalStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).
		Where("session_token = ? AND rotated_at IS NULL", hashSessionToken(token)).
		First(&session).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &session, nil
}

// GetSessionAny looks up a session by token hash regardless of rotation state —
// used only by RefreshSession's reuse-detection path (#211), which must tell an
// already-rotated token (a reuse signal) apart from one that never existed.
func (ls *LocalStorage) GetSessionAny(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).Where("session_token = ?", hashSessionToken(token)).First(&session).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &session, nil
}

// RotateSession atomically supersedes the session at oldID with newSession, inside
// one DB transaction (#211). The conditional UPDATE's WHERE guard (rotated_at IS
// NULL) is the CAS: under concurrent refreshes of the same token, only the caller
// whose UPDATE matches a still-live row wins (won=true) and gets its replacement
// created in the SAME transaction, so a crash between the two steps can never leave
// an old row marked rotated with no live descendant. The loser's UPDATE matches zero
// rows (won=false, created=nil) — the caller must treat that exactly like an
// out-of-band replay of an already-rotated token.
func (ls *LocalStorage) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	var created *models.Session
	won := false
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.Session{}).
			Where("id = ? AND rotated_at IS NULL", oldID).
			Update("rotated_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil // lost the race / already rotated — won stays false, not an error
		}
		won = true
		plaintext := newSession.SessionToken
		newSession.SessionToken = hashSessionToken(plaintext)
		if err := tx.Create(newSession).Error; err != nil {
			return err
		}
		newSession.SessionToken = plaintext
		created = newSession
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, won, nil
}

// ListSessionTokenHashesByFamily returns the stored session_token hashes for every
// (live or rotated) session sharing familyID, so the reuse-detection path can evict
// each from the auth cache before deleting them (#211).
func (ls *LocalStorage) ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("family_id = ?", familyID).
		Pluck("session_token", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return hashes, nil
}

// DeleteSessionsByFamily removes every session sharing familyID — used to revoke
// the whole lineage descended from one login when a refresh-token reuse is
// detected (#211), not just the single replayed row.
func (ls *LocalStorage) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	if err := ls.db.WithContext(ctx).Where("family_id = ?", familyID).Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
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

// EnforceSessionLimit keeps only the `keep` most-recent sessions for a user and deletes
// the rest, so unbounded logins can't grow the table or enlarge the credential-theft
// blast radius. No-op when the user is at or under the cap.
func (ls *LocalStorage) EnforceSessionLimit(ctx context.Context, userID uint, keep int) error {
	if keep <= 0 {
		return nil
	}
	var keepIDs []uint
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ?", userID).
		Order("created_at DESC").Limit(keep).Pluck("id", &keepIDs).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(keepIDs) < keep {
		return nil // under the cap — nothing to prune
	}
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND id NOT IN ?", userID, keepIDs).
		Delete(&models.Session{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// DeleteSessionsForUserExcept removes all of the user's sessions except exceptID.
// It also removes impersonation sessions the user STARTED (impersonated_by = userID):
// an impersonation session is keyed to the target's user_id, so without this clause a
// suspend/deactivate/force-logout of the impersonating admin would leave their live
// impersonation session running until its TTL — elevated access outliving the admin.
func (ls *LocalStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	result := ls.db.WithContext(ctx).
		Where("(user_id = ? OR impersonated_by = ?) AND id <> ?", userID, userID, exceptID).
		Delete(&models.Session{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// ListSessionTokenHashesForUser returns the stored session_token hashes for every session
// the user owns or is impersonated through, for auth-cache eviction on a state change.
func (ls *LocalStorage) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? OR impersonated_by = ?", userID, userID).
		Pluck("session_token", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return hashes, nil
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

// ListActivePersonalAccessTokens returns every non-revoked PAT, newest first — the
// deployment-wide token-hygiene view.
func (ls *LocalStorage) ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error) {
	var tokens []*models.PersonalAccessToken
	if err := ls.db.WithContext(ctx).
		Where("revoked = ?", false).
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

// RevokeAllPersonalAccessTokensForUser revokes every not-already-revoked PAT belonging to
// the user and returns the revoked tokens' hashes so the caller can evict them from the
// auth cache immediately. Used on a password change/reset: a PAT is a parallel, longer-
// lived credential that must die with the password, or a thief who minted one from a
// stolen session would survive the reset.
func (ls *LocalStorage) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	var hashes []string
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Pluck("token_hash", &hashes).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(hashes) == 0 {
		return nil, nil
	}
	if err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return hashes, nil
}

// TouchPersonalAccessToken bumps last_used_at only when older than staleness (or NULL),
// keeping the auth hot path from writing on every request (mirrors TouchSession).
func (ls *LocalStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	cutoff := usedAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, cutoff).
		UpdateColumn("last_used_at", usedAt).Error
}

// --- Setup Tokens (ADR-028) ---

func (ls *LocalStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	if err := ls.db.WithContext(ctx).Create(t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return t, nil
}

// GetSetupTokenByHash is the consumption lookup (indexed equality on token_hash).
func (ls *LocalStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	var t models.SetupToken
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &t, nil
}

// SupersedeActiveSetupTokens flips every active token for (purpose, email) to
// superseded so a reissue kills the prior link atomically.
func (ls *LocalStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string) error {
	return ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("purpose = ? AND subject_email = ? AND state = ?", purpose, email, "active").
		Update("state", "superseded").Error
}

// MarkSetupTokenConsumed transitions active → consumed only if still active. The
// state guard in the WHERE clause makes consumption single-use even under a
// concurrent replay: the second caller matches zero rows and gets false.
func (ls *LocalStorage) MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error) {
	result := ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("id = ? AND state = ?", id, "active").
		Updates(map[string]interface{}{"state": "consumed", "consumed_at": consumedAt})
	if result.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected == 1, nil
}

// MarkSetupTokenExpired transitions active → expired (lazy expiry on read).
func (ls *LocalStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("id = ? AND state = ?", id, "active").
		Update("state", "expired").Error
}

// CountSetupTokensSince counts tokens minted for (purpose, email) since a cutoff,
// backing resend throttling and the daily cap.
func (ls *LocalStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.SetupToken{}).
		Where("purpose = ? AND subject_email = ? AND created_at >= ?", purpose, email, since).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return n, nil
}

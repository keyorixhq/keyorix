// local_webauthn.go — WebAuthn / passkey persistence (ADR-036): registered
// credentials and the short-lived, single-use ceremony sessions.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (ls *LocalStorage) CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	return ls.db.WithContext(ctx).Create(c).Error
}

func (ls *LocalStorage) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	var creds []*models.WebAuthnCredential
	if err := ls.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at").Find(&creds).Error; err != nil {
		return nil, err
	}
	return creds, nil
}

// GetWebAuthnCredentialByCredID looks up a credential by credential ID, scoped to
// the claimed owner (user_id = userID) so a caller cannot fetch another user's
// credential blob by omitting or forgetting an ownership check (#307).
func (ls *LocalStorage) GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	var c models.WebAuthnCredential
	if err := ls.db.WithContext(ctx).Where("credential_id = ? AND user_id = ?", credentialID, userID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// LockWebAuthnCredentialForUpdate re-reads a credential by (credential_id, user_id),
// taking a row-level write lock on backends that support one (Postgres: SELECT …
// FOR UPDATE). Historically used inside WithTransaction so a read-modify-write of
// the advanced signature counter serialized against a concurrent write for the same
// credential (#306) — that specific path now goes through
// AdvanceWebAuthnCredentialCounter below instead (a single atomic call, required so
// RemoteStorage — whose WithTransaction is a no-op passthrough — gets the same
// guarantee, #517). This method remains for callers that need a locked read outside
// that race (e.g. rejectIfCloned's best-effort disable). On backends without row
// locks (SQLite) it is a plain scoped read, and the caller is responsible for its
// own process-level serialization — mirrors LockUserForUpdate.
func (ls *LocalStorage) LockWebAuthnCredentialForUpdate(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	q := ls.db.WithContext(ctx)
	if ls.db.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var c models.WebAuthnCredential
	if err := q.Where("credential_id = ? AND user_id = ?", credentialID, userID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (ls *LocalStorage) UpdateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	return ls.db.WithContext(ctx).Save(c).Error
}

// webauthnStoredCounter decodes just the one field this package needs out of a
// WebAuthnCredential.CredentialBlob (the JSON-serialized go-webauthn Credential) —
// deliberately NOT the full github.com/go-webauthn/webauthn.Credential type, so this
// storage-layer package doesn't need to import that library merely to read back a
// uint32 it never otherwise interprets. The field name mirrors go-webauthn's own
// Authenticator.SignCount json tag (`json:"signCount,omitempty"`,
// webauthn/authenticator.go) exactly; encoding/json ignores every other field in the
// blob it doesn't recognize.
type webauthnStoredCounter struct {
	Authenticator struct {
		SignCount uint32 `json:"signCount"`
	} `json:"authenticator"`
}

// AdvanceWebAuthnCredentialCounter is the storage.Storage primitive
// persistUpdatedCredential (internal/core/webauthn.go) is built on: it conditionally
// persists newBlob/lastUsedAt for the credential identified by (credentialID,
// userID) IFF newSignCount is not stale relative to whatever counter is CURRENTLY
// persisted, all inside ONE row-locked transaction — extracted, unchanged in
// behavior, from what persistUpdatedCredential used to run inline via
// WithTransaction(Lock+compare+Update) (#306), just moved down a layer so every
// backend gets it for free, not only LocalStorage (#517). See the interface doc
// (internal/core/storage/interface.go) for the full contract, including the (0, 0)
// "authenticator doesn't implement a counter" carve-out.
func (ls *LocalStorage) AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (bool, error) {
	advanced := false
	err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		row, err := tx.LockWebAuthnCredentialForUpdate(ctx, credentialID, userID)
		if err != nil {
			return err
		}
		var stored webauthnStoredCounter
		if err := json.Unmarshal(row.CredentialBlob, &stored); err != nil {
			return err
		}
		storedCount := stored.Authenticator.SignCount
		if newSignCount <= storedCount && (newSignCount != 0 || storedCount != 0) {
			// A concurrent writer already advanced the stored counter past (or to)
			// this candidate: stale, so skip the write rather than regress the
			// persisted counter.
			return nil
		}
		row.CredentialBlob = newBlob
		row.LastUsedAt = &lastUsedAt
		if err := tx.UpdateWebAuthnCredential(ctx, row); err != nil {
			return err
		}
		advanced = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return advanced, nil
}

// DeleteWebAuthnCredential removes one of the user's credentials (scoped by user
// so a caller can't delete another user's passkey by id).
func (ls *LocalStorage) DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error {
	res := ls.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&models.WebAuthnCredential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

func (ls *LocalStorage) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.WebAuthnCredential{}).
		Where("user_id = ?", userID).Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

func (ls *LocalStorage) SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error {
	return ls.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).Update("web_authn_enabled", enabled).Error
}

func (ls *LocalStorage) CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error {
	return ls.db.WithContext(ctx).Create(s).Error
}

// ConsumeWebAuthnSession atomically marks a valid (unused, unexpired) ceremony
// session used and returns it. Returns an error if none matched.
func (ls *LocalStorage) ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error) {
	// G81 (WebAuthnSession.ExpiresAt): normalize internally — see GetAuditLogs.
	now = now.UTC()
	var sess *models.WebAuthnSession
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.WebAuthnSession{}).
			Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, now).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("invalid or expired webauthn session")
		}
		var loaded models.WebAuthnSession
		if err := tx.Where("token_hash = ?", tokenHash).First(&loaded).Error; err != nil {
			return err
		}
		sess = &loaded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

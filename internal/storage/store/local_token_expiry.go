// local_token_expiry.go — LocalStorage implementations of ListExpiringPATs and
// ListExpiringMachineCredentials, used by core.CheckTokenExpiry to find PATs and
// machine credentials approaching their deadline.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListExpiringPATs returns every non-revoked PersonalAccessToken whose ExpiresAt
// is non-nil and strictly before before. Already-expired tokens are included so
// the critical-window check inside core.CheckTokenExpiry can catch them too
// (they are skipped there via the "after now" guard).
func (ls *LocalStorage) ListExpiringPATs(ctx context.Context, before time.Time) ([]models.PersonalAccessToken, error) {
	// G81 (PersonalAccessToken.ExpiresAt): normalize internally — see GetAuditLogs.
	var pats []models.PersonalAccessToken
	return pats, ls.db.WithContext(ctx).
		Where("revoked = ? AND expires_at IS NOT NULL AND expires_at < ?", false, before.UTC()).
		Find(&pats).Error
}

// ListExpiringMachineCredentials returns every non-revoked MachineIdentityCredential
// whose ExpiresAt is non-nil and strictly before before.
func (ls *LocalStorage) ListExpiringMachineCredentials(ctx context.Context, before time.Time) ([]models.MachineIdentityCredential, error) {
	// G81 (MachineIdentityCredential.ExpiresAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	var creds []models.MachineIdentityCredential
	return creds, ls.db.WithContext(ctx).
		Where("revoked = ? AND expires_at IS NOT NULL AND expires_at < ?", false, before).
		Find(&creds).Error
}

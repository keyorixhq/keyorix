// local_legal_hold.go — legal-hold persistence (ISO 27001 A.5.34 / eDiscovery).
// For the remote equivalent see remote_legal_hold.go (server-side only).
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateLegalHold inserts a hold row. A partial unique index on legal_holds
// (released) WHERE released = false (see storage.ensureLegalHoldActiveIndex) allows
// at most one un-released row at a time, so a second concurrent placement — which
// core.PlaceLegalHold's own read-then-insert check cannot fully exclude (#305) —
// fails here with a UNIQUE-constraint violation instead of creating a duplicate
// active row. That violation is surfaced as storage.ErrLegalHoldAlreadyActive so
// the caller can map it to a client error rather than a 500.
func (ls *LocalStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	if err := ls.db.WithContext(ctx).Create(h).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, storage.ErrLegalHoldAlreadyActive
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return h, nil
}

// isUniqueConstraintErr reports whether err is a UNIQUE-constraint violation from the
// SQLite or Postgres driver. GORM only maps driver errors to gorm.ErrDuplicatedKey
// when opened with TranslateError (this app does not set that), so the driver's raw
// message is matched instead: mattn/go-sqlite3 says "UNIQUE constraint failed";
// pgx/lib/pq say "duplicate key value violates unique constraint".
func isUniqueConstraintErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key value violates unique constraint")
}

// GetActiveLegalHold returns the current un-released hold, or (nil, nil) when none
// is active.
func (ls *LocalStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	var h models.LegalHold
	err := ls.db.WithContext(ctx).Where("released = ?", false).Order("id DESC").First(&h).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &h, nil
}

func (ls *LocalStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	if err := ls.db.WithContext(ctx).Save(h).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// auth_encryption_stats.go — showAuthEncryptionStats.
//
// The actual logic lives in internal/encryptionops.ShowAuthEncryptionStats
// (docs/cli-split-inventory.md §7 PR 12).
package encryption

import (
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"gorm.io/gorm"
)

// showAuthEncryptionStats is a thin re-export of
// encryptionops.ShowAuthEncryptionStats — kept as a package-local name
// because this package's tests call it directly.
func showAuthEncryptionStats(db *gorm.DB, encryptionEnabled bool) error {
	return encryptionops.ShowAuthEncryptionStats(db, encryptionEnabled)
}

// auth_encryption_migrate.go — runMigrateAuthData.
//
// The actual logic lives in internal/encryptionops.MigrateAuthDataWithConfig
// (docs/cli-split-inventory.md §7 PR 12).
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func runMigrateAuthData(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return migrateAuthDataWithConfig(cfg, dryRun)
}

// migrateAuthDataWithConfig is a thin re-export of
// encryptionops.MigrateAuthDataWithConfig — kept as a package-local name
// because this package's tests call it directly.
func migrateAuthDataWithConfig(cfg *config.Config, dryRun bool) error {
	return encryptionops.MigrateAuthDataWithConfig(cfg, dryRun, common.PassphraseSource)
}

// migratePasswordResetTokens is a thin re-export of
// encryptionops.MigratePasswordResetTokens — kept as a package-local name
// because this package's tests call it directly.
func migratePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	return encryptionops.MigratePasswordResetTokens(db, authEnc, dryRun)
}

// auth_encryption_validate.go — runValidateAuthEncryption.
//
// The actual logic lives in internal/encryptionops.ValidateAuthEncryptionWithConfig
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

func runValidateAuthEncryption(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return validateAuthEncryptionWithConfig(cfg, verbose)
}

// validateAuthEncryptionWithConfig is a thin re-export of
// encryptionops.ValidateAuthEncryptionWithConfig — kept as a package-local
// name because this package's tests call it directly.
func validateAuthEncryptionWithConfig(cfg *config.Config, verbose bool) error {
	return encryptionops.ValidateAuthEncryptionWithConfig(cfg, verbose, common.PassphraseSource)
}

// validatePasswordResetTokens is a thin re-export of
// encryptionops.ValidatePasswordResetTokens — kept as a package-local name
// because this package's tests call it directly.
func validatePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	return encryptionops.ValidatePasswordResetTokens(db, authEnc, verbose)
}

// rotate_kek.go — `keyorix encryption rotate-kek`.
//
// Changes the master passphrase by re-wrapping the current DEK under a new KEK
// derived from the new passphrase + a freshly generated salt. Unlike
// `encryption rotate`, no database rows are re-encrypted and no database
// connection is required — only the key files are updated.
//
// The actual logic lives in internal/encryptionops.RotateKEKWithConfig
// (docs/cli-split-inventory.md §7 PR 12), shared with the
// `keyorix-server admin encryption rotate-kek` subcommand.
package encryption

import (
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
)

var rotateKEKCmd = &cobra.Command{
	Use:   "rotate-kek",
	Short: "Change the master passphrase (re-wraps DEK, no database re-encryption)",
	Long: `Derives a new KEK from a new master passphrase and re-wraps the existing
Data Encryption Key (DEK) under it. Unlike 'encryption rotate', this does NOT
re-encrypt any database rows — the DEK itself is unchanged. The server must be
stopped before running this command.

The new passphrase is read from KEYORIX_NEW_MASTER_PASSWORD (required).
The old passphrase is read from KEYORIX_MASTER_PASSWORD (required).

After this command succeeds, update KEYORIX_MASTER_PASSWORD in your deployment
configuration to the new passphrase before restarting the server.

Note: the evidence-signing key fingerprint (esk-...) and audit-checkpoint key
fingerprint (ack-...) will change, because both are derived from the KEK.`,
	RunE: runRotateKEK,
}

var rotateKEKConfirm bool

// rotateKEKNewPassphraseSource holds the byte-based sources (ADR-099) for the
// NEW master passphrase, mirroring common.PassphraseSource (which supplies the
// OLD passphrase via masterPassphrase). Registered under a "new-" flag prefix
// so both sets of flags can coexist on this command.
var rotateKEKNewPassphraseSource crypto.PassphraseSource

func init() {
	EncryptionCmd.AddCommand(rotateKEKCmd)
	rotateKEKCmd.Flags().BoolVar(&rotateKEKConfirm, "confirm", false,
		"required acknowledgement that the master passphrase will be changed")

	fdFlag, fileFlag, stdinFlag := common.RegisterPassphraseFlags(
		rotateKEKCmd.Flags(), &rotateKEKNewPassphraseSource, "new-", "new master passphrase")
	rotateKEKCmd.MarkFlagsMutuallyExclusive(fdFlag, fileFlag, stdinFlag)
}

func runRotateKEK(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return rotateKEKWithConfig(cfg, rotateKEKConfirm)
}

// rotateKEKWithConfig is a thin re-export of encryptionops.RotateKEKWithConfig
// — kept as a package-local name because this package's tests call it
// directly.
func rotateKEKWithConfig(cfg *config.Config, confirm bool) error {
	return encryptionops.RotateKEKWithConfig(cfg, confirm, common.PassphraseSource, rotateKEKNewPassphraseSource)
}

// shamir_split.go — `keyorix encryption shamir-split`.
//
// The actual logic lives in internal/encryptionops.ShamirSplitWithConfig
// (docs/cli-split-inventory.md §7 PR 12), shared with the
// `keyorix-server admin encryption shamir-split` subcommand. This command
// touches no config/DB at all — see docs/cli-split-inventory.md §2.4, it is
// the one command in this package that already satisfies ADR-108's thin-CLI
// constraint unmodified.
package encryption

import (
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

var (
	ssShares    int
	ssThreshold int
	ssOutDir    string
)

var shamirSplitCmd = &cobra.Command{
	Use:   "shamir-split",
	Short: "Generate a new KEK split into K-of-N Shamir shares",
	Long: `Generate a fresh random 32-byte key-encryption key (KEK) and split it into N
Shamir shares such that any K of them reconstruct it and any K-1 reveal nothing
(ADR-038). Use it to put the master key under split custody — no single party holds
it.

The KEK is NEVER printed or written anywhere; only the shares are emitted. Give one
share to each custodian. To USE it, set storage.encryption.key_provider.type to
"shamir" and list at least K share files/env vars — the server reconstructs the KEK
in memory at startup. For an EXISTING (already-encrypted) install, re-wrap the DEK
onto these shares with:

    keyorix encryption migrate-provider --to-type shamir \
        --to-shamir-share-files share-1.hex,share-2.hex,share-3.hex --confirm

WARNING: losing more than N-K shares makes the KEK — and thus all data — permanently
unrecoverable. Store shares separately and back them up.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		return encryptionops.ShamirSplitWithConfig(ssShares, ssThreshold, ssOutDir)
	},
}

func init() {
	EncryptionCmd.AddCommand(shamirSplitCmd)
	f := shamirSplitCmd.Flags()
	f.IntVar(&ssShares, "shares", 5, "total number of shares to generate (N)")
	f.IntVar(&ssThreshold, "threshold", 3, "shares required to reconstruct the KEK (K)")
	f.StringVar(&ssOutDir, "out-dir", "", "write shares to this directory as share-N.hex (default: print to stdout)")
}

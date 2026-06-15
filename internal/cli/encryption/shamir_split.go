// shamir_split.go — `keyorix encryption shamir-split`.
//
// Generates a fresh random 32-byte KEK and splits it into N Shamir shares with a
// K-of-N threshold (ADR-038), then prints/writes the shares. The KEK itself is
// NEVER printed or stored — it only ever exists reconstructed in memory at startup
// when at least K custodians supply their shares. Distribute one share per
// custodian, then point key_provider.type: shamir at >=K of them (or migrate an
// existing install with `migrate-provider --to-type shamir`).
package encryption

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/crypto"
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
		if ssThreshold < 2 {
			return fmt.Errorf("--threshold must be at least 2")
		}
		if ssShares < ssThreshold {
			return fmt.Errorf("--shares (%d) must be >= --threshold (%d)", ssShares, ssThreshold)
		}
		kek := make([]byte, crypto.KEKSize)
		if _, err := cryptorand.Read(kek); err != nil {
			return fmt.Errorf("generate KEK: %w", err)
		}
		shares, err := crypto.Split(kek, ssShares, ssThreshold)
		if err != nil {
			return err
		}

		fmt.Printf("Generated a new 32-byte KEK split into %d shares (threshold %d).\n", ssShares, ssThreshold)
		fmt.Println("The KEK itself is not stored — keep at least the threshold many shares safe.")
		fmt.Println()
		for i, s := range shares {
			enc := hex.EncodeToString(s)
			if ssOutDir == "" {
				fmt.Printf("  share %d: %s\n", i+1, enc)
				continue
			}
			path := filepath.Join(ssOutDir, fmt.Sprintf("share-%d.hex", i+1))
			if err := os.WriteFile(path, []byte(enc+"\n"), 0600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Printf("  share %d -> %s\n", i+1, path)
		}
		fmt.Println()
		fmt.Printf("Configure: key_provider.type: shamir with at least %d of the shares.\n", ssThreshold)
		return nil
	},
}

func init() {
	EncryptionCmd.AddCommand(shamirSplitCmd)
	f := shamirSplitCmd.Flags()
	f.IntVar(&ssShares, "shares", 5, "total number of shares to generate (N)")
	f.IntVar(&ssThreshold, "threshold", 3, "shares required to reconstruct the KEK (K)")
	f.StringVar(&ssOutDir, "out-dir", "", "write shares to this directory as share-N.hex (default: print to stdout)")
}

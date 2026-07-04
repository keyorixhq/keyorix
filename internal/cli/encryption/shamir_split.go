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
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
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
		shares, err := crypto.SplitKEK(kek, ssShares, ssThreshold)
		if err != nil {
			return err
		}
		// #429: the magic byte embedded in the split payload is forgeable by an
		// attacker holding threshold-1 genuine shares (see combineKEK's doc comment),
		// so also emit a real cryptographic commitment to the KEK, computed here from
		// the actual (never-split) secret and verified against the RECONSTRUCTED KEK
		// at unseal time. It reveals nothing about the KEK, so printing/storing it in
		// the clear next to the shares is safe.
		commitment := hex.EncodeToString(crypto.CommitKEK(kek))

		fmt.Printf("Generated a new 32-byte KEK split into %d shares (threshold %d).\n", ssShares, ssThreshold)
		fmt.Println("The KEK itself is not stored — keep at least the threshold many shares safe.")
		fmt.Println()
		for i, s := range shares {
			enc := hex.EncodeToString(s)
			if ssOutDir == "" {
				fmt.Printf("  share %d: %s\n", i+1, enc)
				continue
			}
			fileName := fmt.Sprintf("share-%d.hex", i+1)
			path := filepath.Join(ssOutDir, fileName)
			// SecureWriteFileSync (#269) refuses to write through a pre-planted symlink
			// (O_NOFOLLOW) and enforces the mode even if a file already existed with a
			// looser one — a plain os.WriteFile silently follows a symlink and never
			// chmods an existing file, so a Shamir key-share could land world-readable
			// or redirected to an attacker-controlled path with no error. Sync'd since
			// this is unrecoverable key material (losing shares is permanent data loss).
			if err := securefiles.SecureWriteFileSync(ssOutDir, fileName, []byte(enc+"\n"), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Printf("  share %d -> %s\n", i+1, path)
		}
		fmt.Println()
		fmt.Println("KEK integrity commitment (safe to store/print in the clear — reveals nothing")
		fmt.Println("about the KEK; verified against the RECONSTRUCTED key at unseal time so a")
		fmt.Println("forged/wrong share is rejected rather than silently accepted, #429):")
		fmt.Printf("  shamir_commitment: %s\n", commitment)
		if ssOutDir != "" {
			commitPath := filepath.Join(ssOutDir, "commitment.hex")
			if err := securefiles.SecureWriteFileSync(ssOutDir, "commitment.hex", []byte(commitment+"\n"), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", commitPath, err)
			}
			fmt.Printf("  -> also written to %s\n", commitPath)
		}
		fmt.Println()
		fmt.Printf("Configure: key_provider.type: shamir with at least %d of the shares, plus\n", ssThreshold)
		fmt.Println("shamir_commitment (above) — without it, reconstruction falls back to a weaker,")
		fmt.Println("forgeable check and logs a loud warning at every startup.")
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

// shamir_split.go — the testable core of `encryption shamir-split`.
//
// Generates a fresh random 32-byte KEK and splits it into N Shamir shares with a
// K-of-N threshold (ADR-038), then prints/writes the shares. The KEK itself is
// NEVER printed or stored — it only ever exists reconstructed in memory at startup
// when at least K custodians supply their shares.
package encryptionops

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// ShamirSplitWithConfig generates a fresh KEK, splits it into shares many
// Shamir shares (threshold to reconstruct), and either prints them to stdout
// (outDir == "") or writes them to outDir as share-N.hex plus commitment.hex.
// The KEK is wiped from memory once split.
func ShamirSplitWithConfig(shares, threshold int, outDir string) error {
	if threshold < 2 {
		return fmt.Errorf("--threshold must be at least 2")
	}
	if shares < threshold {
		return fmt.Errorf("--shares (%d) must be >= --threshold (%d)", shares, threshold)
	}
	kek := make([]byte, crypto.KEKSize)
	if _, err := cryptorand.Read(kek); err != nil {
		return fmt.Errorf("generate KEK: %w", err)
	}
	// The KEK is genuine, maximally sensitive key material — this command's own
	// doc comment promises it is "NEVER printed or stored". Wipe it from memory
	// once split/committed below, rather than leaving it for the GC.
	defer crypto.WipeBytes(kek)
	splitShares, err := crypto.SplitKEK(kek, shares, threshold)
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

	fmt.Printf("Generated a new 32-byte KEK split into %d shares (threshold %d).\n", shares, threshold)
	fmt.Println("The KEK itself is not stored — keep at least the threshold many shares safe.")
	fmt.Println()
	if outDir == "" {
		// #cli-encryption-005: each printed share, on its own, is genuine key
		// material below the configured threshold (only the KEK itself is never
		// printed). A run without --out-dir puts these shares straight into
		// whatever is watching this terminal — scrollback, a tmux/screen logger,
		// a session recorder, a CI log, or a shoulder-surfer during a live demo.
		// Enough of them reaching the same log/recording lets the reader
		// reconstruct the KEK without ever touching a custodian's share file.
		// Warn loudly on stderr (not stdout) immediately before printing any
		// share, so the warning survives even if stdout alone is piped/
		// redirected away from the terminal.
		fmt.Fprintln(os.Stderr, "⚠️  WARNING: printing Shamir shares to stdout.")
		fmt.Fprintln(os.Stderr, "   Each share below is genuine key material — enough of them (threshold")
		fmt.Fprintln(os.Stderr, "   many) reconstruct the KEK. Anything capturing this terminal (scrollback,")
		fmt.Fprintln(os.Stderr, "   tmux/screen logging, session recorders, CI logs) can leak that key.")
		fmt.Fprintln(os.Stderr, "   Prefer --out-dir <dir> unless this is a live, unrecorded,")
		fmt.Fprintln(os.Stderr, "   single-viewer terminal.")
		fmt.Fprintln(os.Stderr)
	}
	for i, s := range splitShares {
		enc := hex.EncodeToString(s)
		if outDir == "" {
			fmt.Printf("  share %d: %s\n", i+1, enc)
			continue
		}
		fileName := fmt.Sprintf("share-%d.hex", i+1)
		path := filepath.Join(outDir, fileName)
		// SecureWriteFileSync (#269) refuses to write through a pre-planted symlink
		// (O_NOFOLLOW) and enforces the mode even if a file already existed with a
		// looser one. Sync'd since this is unrecoverable key material (losing
		// shares is permanent data loss).
		if err := securefiles.SecureWriteFileSync(outDir, fileName, []byte(enc+"\n"), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("  share %d -> %s\n", i+1, path)
	}
	fmt.Println()
	fmt.Println("KEK integrity commitment (safe to store/print in the clear — reveals nothing")
	fmt.Println("about the KEK; verified against the RECONSTRUCTED key at unseal time so a")
	fmt.Println("forged/wrong share is rejected rather than silently accepted, #429):")
	fmt.Printf("  shamir_commitment: %s\n", commitment)
	if outDir != "" {
		commitPath := filepath.Join(outDir, "commitment.hex")
		if err := securefiles.SecureWriteFileSync(outDir, "commitment.hex", []byte(commitment+"\n"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", commitPath, err)
		}
		fmt.Printf("  -> also written to %s\n", commitPath)
	}
	fmt.Println()
	fmt.Printf("Configure: key_provider.type: shamir with at least %d of the shares, plus\n", threshold)
	fmt.Println("shamir_commitment (above) — without it, reconstruction falls back to a weaker,")
	fmt.Println("forgeable check and logs a loud warning at every startup.")
	return nil
}

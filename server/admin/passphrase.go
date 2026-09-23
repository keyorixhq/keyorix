package admin

import (
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/spf13/cobra"
)

// registerPassphraseFlags adds the SAME byte-based master-passphrase source
// flags server/main.go's own main() registers (ADR-099): fd (strongest --
// never touches argv, an env var, or a path this process opens by name; the
// usual answer for systemd's LoadCredential=), file, and stdin. Never argv
// directly (task requirement 4) -- there is deliberately no --passphrase
// flag here, matching the server binary's own flag set exactly.
func registerPassphraseFlags(cmd *cobra.Command, src *crypto.PassphraseSource) {
	cmd.Flags().IntVar(&src.FD, "passphrase-fd", 0,
		"Read the master passphrase from this already-open file descriptor")
	cmd.Flags().StringVar(&src.FilePath, "passphrase-file", "",
		"Read the master passphrase from this file (refused if group- or world-readable)")
	cmd.Flags().BoolVar(&src.Stdin, "passphrase-stdin", false,
		"Read the master passphrase from stdin")
}

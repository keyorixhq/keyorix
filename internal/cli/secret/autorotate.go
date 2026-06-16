package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	autoRotateID      uint
	autoRotateOff     bool
	autoRotateLength  int
	autoRotateCharset string
	autoRotateBackend string
	autoRotateRef     string
)

var autoRotateCmd = &cobra.Command{
	Use:   "auto-rotate",
	Short: "Enable/disable automated rotation for a secret (ADR-046)",
	Long: `Opt a secret into automated rotation: when it is overdue under an active
rotation policy, Keyorix regenerates its value on schedule. Optionally set the generated
value's shape with --length and --charset. Use --off to disable.

Enable only for secrets whose value Keyorix owns — auto-rotation changes the stored
value without touching any upstream system. Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if autoRotateID == 0 {
			return fmt.Errorf("--id is required")
		}
		switch autoRotateCharset {
		case "", "alphanumeric", "lower_alphanumeric", "hex", "alphanumeric_symbols":
		default:
			return fmt.Errorf("--charset must be alphanumeric, lower_alphanumeric, hex, or alphanumeric_symbols")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if (autoRotateBackend == "") != (autoRotateRef == "") {
			return fmt.Errorf("--backend and --ref must be set together (or both omitted)")
		}
		body := map[string]interface{}{
			"enabled": !autoRotateOff,
			"length":  autoRotateLength,
			"charset": autoRotateCharset,
			"backend": autoRotateBackend,
			"ref":     autoRotateRef,
		}
		var out struct{}
		path := "/api/v1/secrets/" + strconv.Itoa(int(autoRotateID)) + "/auto-rotate"
		if err := c.Patch(context.Background(), path, body, &out); err != nil {
			return err
		}
		if autoRotateOff {
			fmt.Printf("Auto-rotation disabled for secret %d.\n", autoRotateID)
		} else {
			fmt.Printf("Auto-rotation enabled for secret %d.\n", autoRotateID)
		}
		return nil
	},
}

func init() {
	autoRotateCmd.Flags().UintVar(&autoRotateID, "id", 0, "Secret ID (required)")
	autoRotateCmd.Flags().BoolVar(&autoRotateOff, "off", false, "Disable auto-rotation (default enables)")
	autoRotateCmd.Flags().IntVar(&autoRotateLength, "length", 0, "Generated value length (8–256, 0 = default 32)")
	autoRotateCmd.Flags().StringVar(&autoRotateCharset, "charset", "", "alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols (empty = default)")
	autoRotateCmd.Flags().StringVar(&autoRotateBackend, "backend", "", "Rotation backend name — rotate the upstream credential too (ADR-047)")
	autoRotateCmd.Flags().StringVar(&autoRotateRef, "ref", "", "Upstream identifier the backend rotates (required with --backend)")
	SecretCmd.AddCommand(autoRotateCmd)
}

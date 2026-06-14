package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	classifyID    uint
	classifyLevel string
)

var classifyCmd = &cobra.Command{
	Use:   "classify",
	Short: "Set a secret's data-classification label (ISO 27001 A.5.12)",
	Long: `Label a secret with its data-sensitivity classification: public, internal,
confidential, or restricted (or empty to clear). The label drives the compliance
classification posture. Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if classifyID == 0 {
			return fmt.Errorf("--id is required")
		}
		switch classifyLevel {
		case "", "public", "internal", "confidential", "restricted":
		default:
			return fmt.Errorf("--level must be public, internal, confidential, restricted, or empty to clear")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct{}
		path := "/api/v1/secrets/" + strconv.Itoa(int(classifyID)) + "/classification"
		if err := c.Patch(context.Background(), path, map[string]string{"classification": classifyLevel}, &out); err != nil {
			return err
		}
		label := classifyLevel
		if label == "" {
			label = "unclassified"
		}
		fmt.Printf("Secret %d classified as %s.\n", classifyID, label)
		return nil
	},
}

func init() {
	classifyCmd.Flags().UintVar(&classifyID, "id", 0, "Secret ID (required)")
	classifyCmd.Flags().StringVar(&classifyLevel, "level", "", "public|internal|confidential|restricted (empty clears)")
	SecretCmd.AddCommand(classifyCmd)
}

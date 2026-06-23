// csv_export.go — `keyorix compliance inventory` plus the emitCSV helper shared with
// `compliance controls --csv`. These download the server's canonical CSV artifacts
// (the same bytes the dashboard exports) for an auditor hand-off, rather than
// re-deriving them client-side. Remote-only, like the rest of the compliance group.
package compliance

import (
	"context"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	inventoryProject uint
	inventoryOutput  string
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Export the secret asset inventory as CSV (deployment-wide, or one project)",
	Long: `Download the secret asset-inventory as CSV for an auditor hand-off — secrets
listed by name, project, environment, type, classification, owner, and lifecycle
status, with no secret values. Deployment-wide by default (needs system.read);
--project <id> scopes it to a single project (needs secrets.read on that project).
Writes to stdout, or to --output FILE.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		path := "/api/v1/secrets/inventory.csv"
		if inventoryProject != 0 {
			path = fmt.Sprintf("/api/v1/projects/%d/secrets/inventory.csv", inventoryProject)
		}
		return emitCSV(c, path, inventoryOutput, "Secret inventory CSV")
	},
}

// emitCSV downloads the CSV artifact at path and writes it to outputPath (0600) or, if
// empty, to stdout. label names the artifact in the file-written confirmation line.
func emitCSV(rc *common.RemoteClient, path, outputPath, label string) error {
	data, err := rc.GetRaw(context.Background(), path)
	if err != nil {
		return err
	}
	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0o600); err != nil {
			return fmt.Errorf("failed to write %s: %w", outputPath, err)
		}
		fmt.Printf("%s written to %s.\n", label, outputPath)
		return nil
	}
	_, _ = os.Stdout.Write(data)
	return nil
}

func init() {
	inventoryCmd.Flags().UintVar(&inventoryProject, "project", 0, "Scope to one project by ID (default: deployment-wide)")
	inventoryCmd.Flags().StringVar(&inventoryOutput, "output", "", "Write the CSV to a file instead of stdout")
	ComplianceCmd.AddCommand(inventoryCmd)
}

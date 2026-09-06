// csv_export.go — `keyorix compliance inventory` plus the emitCSV helper shared with
// `compliance controls --csv`. These download the server's canonical CSV artifacts
// (the same bytes the dashboard exports) for an auditor hand-off, rather than
// re-deriving them client-side. Remote-only, like the rest of the compliance group.
package compliance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

var (
	inventoryProject uint
	inventoryOutput  string
	inventoryForce   bool
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Export the secret asset inventory as CSV (deployment-wide, or one project)",
	Long: `Download the secret asset-inventory as CSV for an auditor hand-off — secrets
listed by name, project, environment, type, classification, owner, and lifecycle
status, with no secret values. Deployment-wide by default (needs system.read);
--project <id> scopes it to a single project (needs secrets.read on that project).
Writes to stdout, or to --output FILE. Refuses to overwrite an existing --output file
unless --force is passed (a scheduled/CI evidence run reusing a fixed path needs it).`,
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
		return emitCSV(c, path, inventoryOutput, "Secret inventory CSV", inventoryForce)
	},
}

// emitCSV downloads the CSV artifact at path and writes it to outputPath (0600) or, if
// empty, to stdout. label names the artifact in the file-written confirmation line.
//
// The artifact is auditor-sensitive data (secret inventory, permission baseline,
// compliance evidence) written to an operator-supplied --output path. Without force,
// this routes through securefiles.SecureCreateFile, which refuses both a symlink-
// redirect (a per-path-component O_NOFOLLOW walk) AND a silent overwrite (O_EXCL) of
// whatever was already at that path — see internal/securefiles's doc comments for why.
// outputPath is split into (baseDir, relPath) the way securefiles expects, the same
// idiom already used at internal/cli/license/license.go and
// internal/cli/config/cli_config.go.
//
// force (mirroring internal/cli/trust/trust.go's keygen --force) relaxes EXACTLY the
// overwrite refusal, not the symlink protection: it switches to
// securefiles.SecureWriteFile, which still walks every path component with O_NOFOLLOW,
// just without O_EXCL — a compliance evidence run scheduled to a fixed path (CI, cron)
// needs to be able to overwrite its own prior output on every run, the same legitimate
// repeated-write workflow internal/cli/bundle/bundle.go's `build` command already has,
// but that must be an explicit opt-in with a clear refusal otherwise, not bundle.go's
// default-always-overwrites behavior — an auditor evidence artifact silently
// overwriting an operator's unrelated file at the same path by coincidence is a much
// worse failure mode than a build artifact doing so.
func emitCSV(rc *common.RemoteClient, path, outputPath, label string, force bool) error {
	data, err := rc.GetRaw(context.Background(), path)
	if err != nil {
		return err
	}
	if outputPath != "" {
		writeOut := securefiles.SecureCreateFile
		if force {
			writeOut = securefiles.SecureWriteFile
		}
		if err := writeOut(filepath.Dir(outputPath), filepath.Base(outputPath), data, 0o600); err != nil {
			return fmt.Errorf("cannot create output file %q (it may already exist — remove it, choose a different path, or pass --force): %w", outputPath, err)
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
	inventoryCmd.Flags().BoolVar(&inventoryForce, "force", false, "Overwrite an existing --output file (default: refuse)")
	ComplianceCmd.AddCommand(inventoryCmd)
}

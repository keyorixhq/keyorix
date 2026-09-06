// baseline.go — `keyorix compliance permission-baseline`: download the
// deployment's full user→role→permission edge list as CSV (default) or JSON.
// Remote-only: calls GET /api/v1/compliance/permission-baseline[.csv].
package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/spf13/cobra"
)

var (
	baselineFormat string
	baselineOutput string
	baselineForce  bool
)

var baselineCmd = &cobra.Command{
	Use:   "permission-baseline",
	Short: "Export the permission baseline (every user's effective permissions) as CSV or JSON",
	Long: `Download the full permission baseline — every user's effective permissions,
expanded through direct role grants and group membership — for auditor hand-off.
Outputs CSV by default; use --format json for the JSON form.
Writes to stdout by default, or to --output FILE. Refuses to overwrite an existing
--output file unless --force is passed (a scheduled/CI evidence run reusing a fixed
path needs it).
Requires audit.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		switch baselineFormat {
		case "json":
			var raw json.RawMessage
			if err := c.Get(context.Background(), "/api/v1/compliance/permission-baseline", &raw); err != nil {
				return err
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, raw, "", "  "); err != nil {
				pretty.Write(raw)
			}
			pretty.WriteByte('\n')
			if baselineOutput != "" {
				// See emitCSV's doc comment (csv_export.go) for why --force switches to
				// SecureWriteFile (overwrite allowed, symlink protection unchanged) rather
				// than dropping safety wholesale.
				writeOut := securefiles.SecureCreateFile
				if baselineForce {
					writeOut = securefiles.SecureWriteFile
				}
				if err := writeOut(filepath.Dir(baselineOutput), filepath.Base(baselineOutput), pretty.Bytes(), 0o600); err != nil {
					return fmt.Errorf("cannot create output file %q (it may already exist — remove it, choose a different path, or pass --force): %w", baselineOutput, err)
				}
				fmt.Printf("Permission baseline JSON written to %s.\n", baselineOutput)
				return nil
			}
			_, _ = os.Stdout.Write(pretty.Bytes())
			return nil
		case "csv", "":
			return emitCSV(c, "/api/v1/compliance/permission-baseline.csv", baselineOutput, "Permission baseline CSV", baselineForce)
		default:
			return fmt.Errorf("unknown format %q — use csv or json", baselineFormat)
		}
	},
}

func init() {
	baselineCmd.Flags().StringVar(&baselineFormat, "format", "csv", "Output format: csv or json")
	baselineCmd.Flags().StringVar(&baselineOutput, "output", "", "Write the output to a file instead of stdout")
	baselineCmd.Flags().BoolVar(&baselineForce, "force", false, "Overwrite an existing --output file (default: refuse)")
	ComplianceCmd.AddCommand(baselineCmd)
}

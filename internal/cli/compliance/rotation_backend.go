// rotation_backend.go — `keyorix compliance rotation-by-backend` command.
// Prints a table of rotation-overdue secrets grouped by RotationBackend across
// the whole deployment. Talks to GET /api/v1/compliance/rotation-by-backend.
package compliance

import (
	"context"
	"fmt"
	"text/tabwriter"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// backendReport mirrors core.RotationBackendReport for JSON decoding in the CLI.
type backendReport struct {
	GeneratedAt  time.Time           `json:"generated_at"`
	Backends     []backendStat       `json:"backends"`
	TotalOverdue int                 `json:"total_overdue"`
}

type backendStat struct {
	Backend      string `json:"backend"`
	Total        int    `json:"total"`
	Overdue      int    `json:"overdue"`
	UpToDate     int    `json:"up_to_date"`
	NeverRotated int    `json:"never_rotated"`
}

var rotationByBackendCmd = &cobra.Command{
	Use:          "rotation-by-backend",
	Short:        "Rotation-overdue secrets grouped by backend",
	Long: `Print a table of rotation-overdue secrets grouped by RotationBackend across
the whole deployment. Requires audit.read permission.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var report backendReport
		if err := c.Get(context.Background(), "/api/v1/compliance/rotation-by-backend", &report); err != nil {
			return err
		}
		fmt.Printf("Rotation overdue by backend — %s\n", report.GeneratedAt.Format(time.RFC3339))
		fmt.Printf("Total overdue: %d\n\n", report.TotalOverdue)

		if len(report.Backends) == 0 {
			fmt.Println("No rotation policies found.")
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "BACKEND\tTOTAL\tOVERDUE\tUP-TO-DATE\tNEVER ROTATED")
		for _, b := range report.Backends {
			backend := b.Backend
			if backend == "" {
				backend = "(keyorix-internal)"
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n",
				backend, b.Total, b.Overdue, b.UpToDate, b.NeverRotated)
		}
		_ = tw.Flush()
		return nil
	},
}

func init() {
	ComplianceCmd.AddCommand(rotationByBackendCmd)
}

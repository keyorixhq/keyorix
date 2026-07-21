// permission_changes.go — `keyorix compliance permission-changes` subcommand.
//
// Calls GET /api/v1/compliance/permission-changes and prints a table of role
// grant/revoke events: Time | Actor | Action | Target | Role | Scope.
// Requires audit.read.
package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

const permChangeTimeFormat = "2006-01-02T15:04:05Z"

// permChangeReport mirrors core.PermissionChangeReport for JSON decoding.
type permChangeReport struct {
	Since   time.Time         `json:"since"`
	Until   time.Time         `json:"until"`
	Changes []permChangeEvent `json:"changes"`
	Total   int               `json:"total"`
}

// permChangeEvent mirrors core.PermissionChangeEvent for JSON decoding.
type permChangeEvent struct {
	EventID    uint      `json:"event_id"`
	Action     string    `json:"action"`
	ActorName  string    `json:"actor_name"`
	TargetUser string    `json:"target_user"`
	RoleName   string    `json:"role_name"`
	Scope      string    `json:"scope"`
	ChangedAt  time.Time `json:"changed_at"`
}

var (
	permChangeSince string
	permChangeUntil string
	permChangeLimit int
)

var permissionChangesCmd = &cobra.Command{
	Use:   "permission-changes",
	Short: "Show role grant/revoke events from the audit trail (permission change audit)",
	Long: `Download a structured list of permission change events (role grants and
revokes) from the audit trail. Prints a table of: Time | Actor | Action | Target | Role | Scope.
Requires audit.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		url := "/api/v1/compliance/permission-changes"
		sep := "?"
		if permChangeSince != "" {
			if _, err := time.Parse(time.RFC3339, permChangeSince); err != nil {
				return fmt.Errorf("invalid --since value %q: must be RFC3339 (e.g. 2026-01-01T00:00:00Z)", permChangeSince)
			}
			url += sep + "since=" + permChangeSince
			sep = "&"
		}
		if permChangeUntil != "" {
			if _, err := time.Parse(time.RFC3339, permChangeUntil); err != nil {
				return fmt.Errorf("invalid --until value %q: must be RFC3339 (e.g. 2026-12-31T23:59:59Z)", permChangeUntil)
			}
			url += sep + "until=" + permChangeUntil
			sep = "&"
		}
		if permChangeLimit > 0 {
			url += fmt.Sprintf("%slimit=%d", sep, permChangeLimit)
		}

		var report permChangeReport
		if err := c.Get(context.Background(), url, &report); err != nil {
			return err
		}

		fmt.Printf("Permission change audit trail (%d events, %s – %s)\n\n",
			report.Total,
			report.Since.UTC().Format(permChangeTimeFormat),
			report.Until.UTC().Format(permChangeTimeFormat),
		)

		if report.Total == 0 {
			fmt.Println("No permission changes in the selected window.")
			return nil
		}

		fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
			"Time", "Actor", "Action", "Target", "Role", "Scope")
		fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
			"----------------------", "----------------", "----------------",
			"----------------", "--------------------", "------")
		for _, e := range report.Changes {
			fmt.Printf("%-22s  %-16s  %-16s  %-16s  %-20s  %s\n",
				e.ChangedAt.UTC().Format(permChangeTimeFormat),
				truncate(e.ActorName, 16),
				truncate(e.Action, 16),
				truncate(e.TargetUser, 16),
				truncate(e.RoleName, 20),
				e.Scope,
			)
		}
		return nil
	},
}

// truncate shortens s to at most n runes, appending "…" when cut.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

func init() {
	permissionChangesCmd.Flags().StringVar(&permChangeSince, "since", "", "Start of the time window (RFC3339, e.g. 2026-01-01T00:00:00Z); defaults to 30 days ago")
	permissionChangesCmd.Flags().StringVar(&permChangeUntil, "until", "", "End of the time window (RFC3339); defaults to now")
	permissionChangesCmd.Flags().IntVar(&permChangeLimit, "limit", 0, "Maximum number of events to return (default 100, max 1000)")
	ComplianceCmd.AddCommand(permissionChangesCmd)
}

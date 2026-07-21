// inactivity_suspend.go — CLI command: keyorix user suspend-inactive
//
// Suspends all non-admin users who have been inactive longer than --days days.
//
// In remote mode (KEYORIX_SERVER + KEYORIX_TOKEN, or ~/.keyorix/cli.yaml) the
// command POSTs to POST /api/v1/admin/jobs/suspend-inactive-users on the
// connected server and prints the job result.
//
// In local mode it calls SuspendInactiveUsers directly against the configured
// storage backend.
//
// --dry-run lists which users would be suspended without modifying any state.
package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	suspendInactiveDays   int
	suspendInactiveDryRun bool
)

// suspendInactiveResult mirrors the JSON body returned by the HTTP endpoint.
// Used only for remote-mode decoding.
type suspendInactiveResult struct {
	Suspended []uint `json:"suspended"`
	Skipped   int    `json:"skipped"`
	Total     int    `json:"total"`
}

var suspendInactiveCmd = &cobra.Command{
	Use:   "suspend-inactive",
	Short: "Suspend users who have been inactive beyond a threshold",
	Long: `Suspend all non-admin users whose last login (or account creation, if they
have never logged in) is older than --days days.

In remote mode the command triggers the server-side job via
POST /api/v1/admin/jobs/suspend-inactive-users (requires system.write).
In local (embedded) mode it operates directly against the configured storage.

With --dry-run the command evaluates all users against the threshold but makes
no changes — it prints what would be suspended.`,
	SilenceUsage: true,
	RunE:         runSuspendInactive,
}

func init() {
	suspendInactiveCmd.Flags().IntVar(&suspendInactiveDays, "days", 0, "Inactivity threshold in days (required, must be > 0)")
	suspendInactiveCmd.Flags().BoolVar(&suspendInactiveDryRun, "dry-run", false, "Preview which users would be suspended without making changes")
	_ = suspendInactiveCmd.MarkFlagRequired("days")
}

func runSuspendInactive(_ *cobra.Command, _ []string) error {
	if suspendInactiveDays <= 0 {
		return fmt.Errorf("--days must be greater than 0")
	}

	ctx := context.Background()

	// Remote mode: POST to the server endpoint.
	if rc, ok := common.NewRemoteClient(); ok {
		return runSuspendInactiveRemote(ctx, rc)
	}

	// Local mode: initialize core and call directly.
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	return runSuspendInactiveWithService(ctx, svc)
}

func runSuspendInactiveRemote(ctx context.Context, rc *common.RemoteClient) error {
	reqBody := map[string]interface{}{
		"inactive_days": suspendInactiveDays,
		"dry_run":       suspendInactiveDryRun,
	}
	var result suspendInactiveResult
	if err := rc.Post(ctx, "/api/v1/admin/jobs/suspend-inactive-users", reqBody, &result); err != nil {
		return err
	}
	printSuspendResult(result.Suspended, result.Skipped, result.Total, suspendInactiveDryRun)
	return nil
}

// runSuspendInactiveWithService executes the job using the supplied core service.
// Split out from runSuspendInactive so the error path from SuspendInactiveUsers
// can be exercised in tests without going through InitializeCoreService.
func runSuspendInactiveWithService(ctx context.Context, svc *core.KeyorixCore) error {
	result, err := svc.SuspendInactiveUsers(ctx, core.InactivitySuspendConfig{
		InactiveDays: suspendInactiveDays,
		DryRun:       suspendInactiveDryRun,
	})
	if err != nil {
		return fmt.Errorf("failed: %w", err)
	}
	printSuspendResult(result.Suspended, result.Skipped, result.Total, suspendInactiveDryRun)
	return nil
}

// printSuspendResult formats the suspension job output.
func printSuspendResult(suspended []uint, skipped, total int, dryRun bool) {
	prefix := ""
	if dryRun {
		prefix = "[dry-run] "
	}
	fmt.Printf("%sInactive users examined: %d\n", prefix, total)
	fmt.Printf("%sSkipped (already suspended or admin): %d\n", prefix, skipped)
	if dryRun {
		fmt.Printf("%sWould suspend: %d\n", prefix, len(suspended))
	} else {
		fmt.Printf("%sSuspended: %d\n", prefix, len(suspended))
	}
	if len(suspended) > 0 {
		ids := make([]string, len(suspended))
		for i, id := range suspended {
			ids[i] = fmt.Sprintf("%d", id)
		}
		action := "Suspended"
		if dryRun {
			action = "Would suspend"
		}
		fmt.Printf("%s%s user IDs: %s\n", prefix, action, strings.Join(ids, ", "))
	}
}

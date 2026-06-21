package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var assignRoleCmd = &cobra.Command{
	Use:   "assign-role",
	Short: "Assign a role to a user",
	Long: `Assign a role to a user by email address.

With --ttl, the grant is time-bound (just-in-time access): it stops authorizing
once the window passes and is swept automatically. Useful for emergency or
contractor access. Example: --ttl 4h grants the role for four hours.

Time-bound grants require a server connection (run 'keyorix connect <server>').`,
	RunE: runAssignRole,
}

var (
	userEmail string
	roleName  string
	roleTTL   time.Duration
)

func init() {
	assignRoleCmd.Flags().StringVar(&userEmail, "user", "", "User email address (required)")
	assignRoleCmd.Flags().StringVar(&roleName, "role", "", "Role name to assign (required)")
	assignRoleCmd.Flags().DurationVar(&roleTTL, "ttl", 0, "Time-bound grant lifetime (e.g. 4h, 30m); omit for a permanent grant")

	_ = assignRoleCmd.MarkFlagRequired("user")
	_ = assignRoleCmd.MarkFlagRequired("role")
}

func runAssignRole(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if roleTTL < 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if rc, ok := common.NewRemoteClient(); ok {
		return runAssignRoleRemote(ctx, rc, userEmail, roleName, roleTTL)
	}

	// Embedded (direct-DB) mode has no time-bound path — the JIT expiry sweep runs
	// in the server, so a grant made here would never be reclaimed.
	if roleTTL > 0 {
		return fmt.Errorf("--ttl requires a server connection; run 'keyorix connect <server>'")
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}

	// Create core service
	coreService := core.NewKeyorixCore(st)

	// Use core service to assign role
	err = coreService.AssignRoleToUser(ctx, userEmail, roleName)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	fmt.Printf("✅ Successfully assigned role '%s' to user '%s'\n", roleName, userEmail)
	return nil
}

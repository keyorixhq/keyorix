// user_to_machine.go — `keyorix migrate user-to-machine <username>` (ADR-023).
//
// Converts a service-account-shaped human user into a project machine identity.
// Local mode only (operator tool): resolves the acting admin via --by, the
// project via --project / KEYORIX_PROJECT / the active project, verifies --by
// actually holds the authority the equivalent HTTP route requires (#264), then
// delegates to core.MigrateUserToMachine. By default the source user is
// suspended so it can no longer log in; --keep-user leaves it active.
package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	u2mProject  string
	u2mType     string
	u2mName     string
	u2mBy       string
	u2mKeepUser bool
)

var userToMachineCmd = &cobra.Command{
	Use:   "user-to-machine <username>",
	Short: "Convert a service-account-shaped user into a machine identity",
	Long: "Materialise a project machine identity (ADR-023) for an existing user and,\n" +
		"unless --keep-user is set, suspend the source user so it can no longer log in.\n" +
		"The user is never deleted; suspension is reversible via `keyorix user reactivate`.",
	Args: cobra.ExactArgs(1),
	RunE: runUserToMachine,
}

func init() {
	userToMachineCmd.Flags().StringVar(&u2mProject, "project", "", "Project for the new machine identity (defaults to the active project)")
	userToMachineCmd.Flags().StringVar(&u2mType, "type", "service", "Identity type: ci | k8s | service | automation | other")
	userToMachineCmd.Flags().StringVar(&u2mName, "name", "", "Machine identity name (defaults to the username)")
	userToMachineCmd.Flags().StringVar(&u2mBy, "by", "", "Acting admin email (required, for audit)")
	userToMachineCmd.Flags().BoolVar(&u2mKeepUser, "keep-user", false, "Leave the source user active (default: suspend it)")
	_ = userToMachineCmd.MarkFlagRequired("by")
}

func runUserToMachine(cmd *cobra.Command, args []string) error {
	username := args[0]
	if u2mBy == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	// Local mode only, enforced at runtime, not just documented: this command
	// migrates a row directly in the local embedded database and has no
	// server-side equivalent to relay to. If keyorix connect (or any other
	// remote config source) is active, refuse loudly rather than silently
	// operating on a stray local SQLite file the operator likely didn't intend
	// to touch — see the opt-in-correctness design note (2026-09-05): a
	// documented-only limitation is not enforcement.
	if _, ok := common.NewRemoteClient(); ok {
		return fmt.Errorf("this command operates on local embedded storage only and has no remote " +
			"equivalent; a remote server is configured (via KEYORIX_SERVER/KEYORIX_TOKEN, " +
			"~/.keyorix/cli.yaml, or keyorix.yaml) — run POST /api/v1/projects/{id}/machine-identities/" +
			"migrate-from-user directly against the hub instead, authenticated with your own real " +
			"session (e.g. via 'keyorix connect')")
	}

	ctx := context.Background()
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	admin, err := svc.GetUserByEmail(ctx, u2mBy)
	if err != nil {
		return fmt.Errorf("no user found for --by %q: %w", u2mBy, err)
	}

	projectID, err := resolveProjectID(ctx, svc, u2mProject)
	if err != nil {
		return err
	}

	if err := requireMigrationAuthority(ctx, svc, admin.ID, projectID); err != nil {
		return err
	}

	m, err := svc.MigrateUserToMachine(ctx, username, projectID, u2mType, u2mName, admin.ID, !u2mKeepUser)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	fmt.Printf("Migrated user %q to machine identity: id=%d name=%q type=%s state=%s\n",
		username, m.ID, m.Name, m.IdentityType, m.State)
	if !u2mKeepUser {
		fmt.Println("Source user suspended (login blocked). Use `keyorix user reactivate` to restore.")
	}
	return nil
}

// requireMigrationAuthority verifies that actorID — the user resolved from
// --by — actually holds the authority the equivalent HTTP route requires for
// this exact operation: POST .../machine-identities/migrate-from-user needs
// BOTH roles.assign (scoped to the target project, for creating the machine
// identity) AND users.write (global, for suspending the source user). The
// local CLI has no session/middleware to enforce this, so --by resolving ANY
// email — with zero authority check — would let an operator attribute a
// destructive migration to an arbitrary or unprivileged account purely for
// what appears in the audit trail (#264). MigrateUserToMachine itself does not
// check permissions (like its sibling CreateMachineIdentity/SuspendUser, it
// assumes the caller already authorized — the HTTP handler's job is done by
// router middleware), so this must be verified here, at the CLI entrypoint,
// before the resolved actor is credited with the action.
//
// Role/permission possession alone is not enough: a suspended or deactivated
// admin's role assignments remain in the database (suspension flips
// IsActive/AccountState, it does not revoke grants), so Authorize would still
// return true for them. Without an explicit liveness check here, a suspended
// admin reachable through some other still-valid credential (an unrevoked
// session or PAT) could attribute a privileged migration to themselves. This
// mirrors the account-state gate the real login/session-validation path
// enforces (AccountStillUsable, used by ValidateSessionToken's cache-hit
// re-check per ADR-025) rather than inventing a new one.
func requireMigrationAuthority(ctx context.Context, svc *core.KeyorixCore, actorID, projectID uint) error {
	usable, err := svc.AccountStillUsable(ctx, actorID)
	if err != nil {
		return fmt.Errorf("failed to verify --by account state: %w", err)
	}
	if !usable {
		return fmt.Errorf("--by actor's account is suspended or deactivated; refusing to attribute this migration to them")
	}

	migrationAlternative := "run POST /api/v1/projects/{id}/machine-identities/migrate-from-user directly against " +
		"the hub instead, authenticated with your own real session (e.g. via 'keyorix connect')"
	ok, err := svc.Authorize(ctx, actorID, "roles.assign", core.Scope{ProjectID: projectID})
	if err != nil {
		return common.ByAuthorityUnavailableError(err, migrationAlternative)
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold roles.assign at project %d; refusing to attribute this migration to them", projectID)
	}
	ok, err = svc.Authorize(ctx, actorID, "users.write", core.Scope{})
	if err != nil {
		return common.ByAuthorityUnavailableError(err, migrationAlternative)
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold users.write; refusing to attribute this migration to them")
	}
	return nil
}

// resolveProjectID resolves a project name (flag / env / active) to its numeric
// ID against the local core service.
func resolveProjectID(ctx context.Context, svc *core.KeyorixCore, flagValue string) (uint, error) {
	name, err := common.ResolveProject(flagValue)
	if err != nil {
		return 0, err
	}
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range projects {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}

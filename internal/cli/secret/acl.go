// acl.go — the `keyorix secret acl` CLI (RBAC Phase 3): manage per-secret ACL grants.
// All commands talk to the server's REST API under /api/v1/secrets/{id}/acl,
// requiring secrets.manage permission server-side.
package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// aclView is a single ACL entry as returned by the server.
type aclView struct {
	ID          uint     `json:"id"`
	SecretID    uint     `json:"secret_id"`
	UserID      uint     `json:"user_id"`
	Permissions []string `json:"permissions"`
	GrantedBy   uint     `json:"granted_by"`
}

var (
	aclGrantUser  uint
	aclGrantPerms []string
)

var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "Manage per-secret ACL grants (RBAC Phase 3)",
	Long: `Manage fine-grained per-secret access control (RBAC Phase 3).

An ACL grant allows a specific user to access one secret independently of their
project role. This is the Vault-path-style least-privilege model: a CI token can
be granted secrets.read on exactly one secret without any project membership.

ACL management requires secrets.manage at the secret's project scope.`,
}

var aclListCmd = &cobra.Command{
	Use:          "list <secret-id>",
	Short:        "List ACL grants for a secret",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := aclClient()
		if err != nil {
			return err
		}
		var acls []aclView
		if err := c.Get(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/acl", id), &acls); err != nil {
			return err
		}
		if len(acls) == 0 {
			fmt.Println("No ACL grants for this secret.")
			return nil
		}
		fmt.Printf("%-6s %-10s %-12s %s\n", "ID", "USER_ID", "GRANTED_BY", "PERMISSIONS")
		for _, a := range acls {
			fmt.Printf("%-6d %-10d %-12d %s\n", a.ID, a.UserID, a.GrantedBy, strings.Join(a.Permissions, ","))
		}
		return nil
	},
}

var aclGrantCmd = &cobra.Command{
	Use:          "grant",
	Short:        "Grant a user ACL access to a secret",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		secretIDStr, _ := cmd.Flags().GetUint("secret")
		if secretIDStr == 0 {
			return fmt.Errorf("--secret <id> is required")
		}
		if aclGrantUser == 0 {
			return fmt.Errorf("--user <user-id> is required")
		}
		if len(aclGrantPerms) == 0 {
			return fmt.Errorf("--perm <permission> is required (e.g. --perm secrets.read)")
		}
		c, err := aclClient()
		if err != nil {
			return err
		}
		body := map[string]interface{}{
			"user_id":     aclGrantUser,
			"permissions": aclGrantPerms,
		}
		var out map[string]bool
		if err := c.Post(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/acl", secretIDStr), body, &out); err != nil {
			return err
		}
		fmt.Printf("ACL granted: user %d now has %v on secret %d.\n", aclGrantUser, aclGrantPerms, secretIDStr)
		return nil
	},
}

var aclRevokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke an ACL grant from a secret",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		secretIDStr, _ := cmd.Flags().GetUint("secret")
		if secretIDStr == 0 {
			return fmt.Errorf("--secret <id> is required")
		}
		aclIDStr, _ := cmd.Flags().GetUint("acl")
		if aclIDStr == 0 {
			return fmt.Errorf("--acl <acl-id> is required")
		}
		c, err := aclClient()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/acl/%d", secretIDStr, aclIDStr)); err != nil {
			return err
		}
		fmt.Printf("ACL %d revoked from secret %d.\n", aclIDStr, secretIDStr)
		return nil
	},
}

func aclClient() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

func init() {
	// grant flags
	aclGrantCmd.Flags().Uint("secret", 0, "Secret ID to grant access to")
	aclGrantCmd.Flags().UintVar(&aclGrantUser, "user", 0, "User ID to grant access to")
	aclGrantCmd.Flags().StringArrayVar(&aclGrantPerms, "perm", nil, "Permission to grant (secrets.read or secrets.write); may be repeated")

	// revoke flags
	aclRevokeCmd.Flags().Uint("secret", 0, "Secret ID to revoke the ACL from")
	aclRevokeCmd.Flags().Uint("acl", 0, "ACL entry ID to revoke (from `acl list`)")

	aclCmd.AddCommand(aclListCmd, aclGrantCmd, aclRevokeCmd)
	SecretCmd.AddCommand(aclCmd)
}

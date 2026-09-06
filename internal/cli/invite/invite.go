// Package invite provides the `keyorix invite` CLI commands for project
// invitations (ADR-024): send, list, resend, and revoke. When `keyorix connect`
// (or KEYORIX_SERVER/KEYORIX_TOKEN) configures a remote server, these commands
// go through the real hub REST API (POST/GET /projects/{id}/invitations,
// DELETE .../invitations/{invitationId}, POST .../invitations/{invitationId}/resend
// -- server/http/router.go, server/http/handlers/invitations.go) so the
// invitation lands in the server's own store, exactly like the dashboard.
// Otherwise they fall back to the local core service directly. (Earlier this
// package doc claimed these commands "operate on the local core service
// directly" unconditionally -- that was stale/wrong the moment a real
// project-scoped REST surface existed for invitations; it silently ignored
// keyorix connect's remote config.)
package invite

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

// InviteCmd is the root command for invitation operations.
var InviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage project invitations",
	Long:  "Send, list, and revoke project invitations (ADR-024).",
}

func init() {
	InviteCmd.AddCommand(sendCmd)
	InviteCmd.AddCommand(listCmd)
	InviteCmd.AddCommand(revokeCmd)
	InviteCmd.AddCommand(resendCmd)
}

// resolveUserID resolves an email address to a user ID via the core service.
func resolveUserID(ctx context.Context, service *core.KeyorixCore, email string) (uint, error) {
	u, err := service.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, fmt.Errorf("no user found for %q: %w", email, err)
	}
	return u.ID, nil
}

// fmtTime renders an optional timestamp for table output.
func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}

// resolveProjectIDRemote resolves a project name to its ID via GET
// /api/v1/projects, for commands running in remote mode. Mirrors
// internal/cli/project/env.go's resolveProjectContext, which does the
// identical by-name lookup for the project package; duplicated here rather
// than shared because that helper is unexported outside internal/cli/project.
func resolveProjectIDRemote(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var resp struct {
		Projects []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &resp); err != nil {
		return 0, fmt.Errorf("failed to list projects: %w", err)
	}
	for _, p := range resp.Projects {
		if p.Name == name {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}

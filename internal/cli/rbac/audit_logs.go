package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var auditLogsCmd = &cobra.Command{
	Use:   "audit-logs",
	Short: "View RBAC audit logs",
	Long:  "View audit logs for RBAC operations (role assignments, removals, permission grants).",
	RunE:  runAuditLogs,
}

var (
	auditLimit  int
	auditOffset int
)

func init() {
	auditLogsCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of logs to retrieve")
	auditLogsCmd.Flags().IntVar(&auditOffset, "offset", 0, "Number of logs to skip")
}

func runAuditLogs(cmd *cobra.Command, args []string) error {
	if auditLimit < 1 {
		auditLimit = 50
	}
	page := (auditOffset / auditLimit) + 1

	ctx := context.Background()
	if rc, ok := common.NewRemoteClient(); ok {
		return runAuditLogsRemote(ctx, rc, page, auditLimit)
	}
	return runAuditLogsEmbedded(ctx, page, auditLimit)
}

// ── Remote mode ─────────────────────────────────────────────────────────────

type remoteAuditLog struct {
	ID           uint   `json:"id"`
	Action       string `json:"action"`
	ActorUserID  *uint  `json:"actor_user_id"`
	TargetUserID *uint  `json:"target_user_id"`
	GroupID      *uint  `json:"group_id"`
	RoleID       *uint  `json:"role_id"`
	PermissionID *uint  `json:"permission_id"`
	ProjectID    *uint  `json:"project_id"`
	Details      string `json:"details"`
	CreatedAt    string `json:"created_at"`
}

func runAuditLogsRemote(ctx context.Context, rc *common.RemoteClient, page, pageSize int) error {
	var resp struct {
		Logs  []remoteAuditLog `json:"logs"`
		Total int64            `json:"total"`
	}
	path := fmt.Sprintf("/api/v1/audit/rbac-logs?page=%d&page_size=%d", page, pageSize)
	if err := rc.Get(ctx, path, &resp); err != nil {
		return fmt.Errorf("failed to retrieve RBAC audit logs: %w", err)
	}
	if len(resp.Logs) == 0 {
		fmt.Println("No RBAC audit logs found")
		return nil
	}
	fmt.Printf("RBAC audit logs (showing %d of %d):\n", len(resp.Logs), resp.Total)
	for _, e := range resp.Logs {
		printAuditEntry(e.CreatedAt, e.Action, e.ActorUserID, e.TargetUserID, e.GroupID, e.RoleID, e.PermissionID, e.ProjectID, e.Details)
	}
	return nil
}

// ── Embedded mode ───────────────────────────────────────────────────────────

func runAuditLogsEmbedded(ctx context.Context, page, pageSize int) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	entries, total, err := service.ListRBACAuditLogs(ctx, page, pageSize)
	if err != nil {
		return fmt.Errorf("failed to retrieve RBAC audit logs: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("No RBAC audit logs found")
		return nil
	}
	fmt.Printf("RBAC audit logs (showing %d of %d):\n", len(entries), total)
	for _, e := range entries {
		printAuditEntry(e.CreatedAt.UTC().Format(time.RFC3339), e.Action, e.ActorUserID, e.TargetUserID, e.GroupID, e.RoleID, e.PermissionID, e.ProjectID, e.Details)
	}
	return nil
}

// ── Shared formatting ───────────────────────────────────────────────────────

func printAuditEntry(when, action string, actor, target, group, role, perm, project *uint, details string) {
	fmt.Printf("  [%s] %s", when, action)
	if actor != nil {
		fmt.Printf(" by user %d", *actor)
	}
	if target != nil {
		fmt.Printf(" → user %d", *target)
	}
	if group != nil {
		fmt.Printf(" → group %d", *group)
	}
	if role != nil {
		fmt.Printf(" role %d", *role)
	}
	if perm != nil {
		fmt.Printf(" permission %d", *perm)
	}
	if project != nil && *project != 0 {
		fmt.Printf(" @ project %d", *project)
	}
	if details != "" {
		fmt.Printf(" (%s)", details)
	}
	fmt.Println()
}

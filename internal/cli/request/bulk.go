// bulk.go — CLI commands for bulk approve/reject of access requests and
// CRUD for rejection-reason templates (ADR-024 extension).
package request

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

// bulkInitService is the function used by bulk run-commands to obtain a core
// service. It is a package-level variable so tests can replace it with one
// that returns a pre-seeded or intentionally-broken service without forking the
// production code path.
var bulkInitService = common.InitializeCoreService

// ── bulk-approve ──────────────────────────────────────────────────────────────

var (
	bulkApproveIDs string
	bulkApproveBy  string
)

var bulkApproveCmd = &cobra.Command{
	Use:   "bulk-approve",
	Short: "Approve multiple pending access requests at once",
	Long: "Approve several pending access requests in a single call (ADR-024 extension).\n" +
		"Provide a comma-separated list of request IDs with --ids.\n" +
		"The --by flag is required: it names the reviewer (email) whose authority is\n" +
		"verified before any approvals are recorded.",
	RunE: runBulkApprove,
}

func init() {
	bulkApproveCmd.Flags().StringVar(&bulkApproveIDs, "ids", "", "Comma-separated list of access request IDs (required)")
	bulkApproveCmd.Flags().StringVar(&bulkApproveBy, "by", "", "Reviewer email address (required, for audit)")
	_ = bulkApproveCmd.MarkFlagRequired("ids")
	_ = bulkApproveCmd.MarkFlagRequired("by")
}

func runBulkApprove(cmd *cobra.Command, args []string) error {
	ids, err := parseIDList(bulkApproveIDs)
	if err != nil {
		return fmt.Errorf("--ids: %w", err)
	}
	service, err := bulkInitService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	approverID, err := resolveUserID(ctx, service, bulkApproveBy)
	if err != nil {
		return err
	}

	result, err := service.BulkApproveAccessRequests(ctx, ids, approverID)
	if err != nil {
		return fmt.Errorf("bulk approve failed: %w", err)
	}

	fmt.Printf("Approved %d request(s), %d failure(s).\n", len(result.Approved), len(result.Failed))
	for _, id := range result.Approved {
		fmt.Printf("  ✓ request %d approved\n", id)
	}
	for _, f := range result.Failed {
		fmt.Printf("  ✗ request %d: %s\n", f.RequestID, f.Error)
	}
	return nil
}

// ── bulk-reject ───────────────────────────────────────────────────────────────

var (
	bulkRejectIDs    string
	bulkRejectBy     string
	bulkRejectReason string
)

var bulkRejectCmd = &cobra.Command{
	Use:   "bulk-reject",
	Short: "Reject multiple pending access requests at once",
	Long: "Reject several pending access requests in a single call (ADR-024 extension).\n" +
		"All rejected requests share the same --reason.\n" +
		"The --by flag is required: it names the reviewer (email) whose authority is\n" +
		"verified before any rejections are recorded.",
	RunE: runBulkReject,
}

func init() {
	bulkRejectCmd.Flags().StringVar(&bulkRejectIDs, "ids", "", "Comma-separated list of access request IDs (required)")
	bulkRejectCmd.Flags().StringVar(&bulkRejectBy, "by", "", "Reviewer email address (required, for audit)")
	bulkRejectCmd.Flags().StringVar(&bulkRejectReason, "reason", "", "Rejection reason shared across all requests (required)")
	_ = bulkRejectCmd.MarkFlagRequired("ids")
	_ = bulkRejectCmd.MarkFlagRequired("by")
	_ = bulkRejectCmd.MarkFlagRequired("reason")
}

func runBulkReject(cmd *cobra.Command, args []string) error {
	ids, err := parseIDList(bulkRejectIDs)
	if err != nil {
		return fmt.Errorf("--ids: %w", err)
	}
	service, err := bulkInitService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	approverID, err := resolveUserID(ctx, service, bulkRejectBy)
	if err != nil {
		return err
	}

	result, err := service.BulkRejectAccessRequests(ctx, ids, approverID, bulkRejectReason)
	if err != nil {
		return fmt.Errorf("bulk reject failed: %w", err)
	}

	fmt.Printf("Rejected %d request(s), %d failure(s).\n", len(result.Rejected), len(result.Failed))
	for _, id := range result.Rejected {
		fmt.Printf("  ✓ request %d rejected\n", id)
	}
	for _, f := range result.Failed {
		fmt.Printf("  ✗ request %d: %s\n", f.RequestID, f.Error)
	}
	return nil
}

// ── rejection-reason-templates ────────────────────────────────────────────────

var rejectionTemplatesCmd = &cobra.Command{
	Use:   "rejection-templates",
	Short: "Manage rejection-reason templates",
}

var (
	tmplName     string
	tmplReason   string
	tmplBy       string
	tmplListBy   string
	tmplDeleteBy string
)

var tmplListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all rejection-reason templates",
	RunE:  runTmplList,
}

var tmplAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new rejection-reason template",
	RunE:  runTmplAdd,
}

var tmplDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a rejection-reason template by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runTmplDelete,
}

func init() {
	tmplAddCmd.Flags().StringVar(&tmplName, "name", "", "Short label for the template (required)")
	tmplAddCmd.Flags().StringVar(&tmplReason, "reason", "", "Template rejection text (required)")
	tmplAddCmd.Flags().StringVar(&tmplBy, "by", "", "Creator email address (required, for audit)")
	_ = tmplAddCmd.MarkFlagRequired("name")
	_ = tmplAddCmd.MarkFlagRequired("reason")
	_ = tmplAddCmd.MarkFlagRequired("by")

	tmplListCmd.Flags().StringVar(&tmplListBy, "by", "", "Acting admin email address (required, for authorization)")
	_ = tmplListCmd.MarkFlagRequired("by")

	tmplDeleteCmd.Flags().StringVar(&tmplDeleteBy, "by", "", "Acting admin email address (required, for authorization and audit)")
	_ = tmplDeleteCmd.MarkFlagRequired("by")

	rejectionTemplatesCmd.AddCommand(tmplListCmd)
	rejectionTemplatesCmd.AddCommand(tmplAddCmd)
	rejectionTemplatesCmd.AddCommand(tmplDeleteCmd)
}

func runTmplList(cmd *cobra.Command, args []string) error {
	service, err := bulkInitService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	viewerID, err := resolveUserID(ctx, service, tmplListBy)
	if err != nil {
		return err
	}
	if err := requireTemplateAuthority(ctx, service, viewerID); err != nil {
		return err
	}

	templates, err := service.ListRejectionReasonTemplates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}
	if len(templates) == 0 {
		fmt.Println("No rejection-reason templates defined.")
		return nil
	}
	for _, t := range templates {
		fmt.Printf("  id=%-4d  name=%-30s  reason=%s\n", t.ID, t.Name, t.Reason)
	}
	return nil
}

func runTmplAdd(cmd *cobra.Command, args []string) error {
	service, err := bulkInitService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	creatorID, err := resolveUserID(ctx, service, tmplBy)
	if err != nil {
		return err
	}
	if err := requireTemplateAuthority(ctx, service, creatorID); err != nil {
		return err
	}

	t, err := service.CreateRejectionReasonTemplate(ctx, creatorID, tmplName, tmplReason)
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}
	fmt.Printf("Template created: id=%d name=%s\n", t.ID, t.Name)
	return nil
}

func runTmplDelete(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid template ID %q: %w", args[0], err)
	}
	service, err := bulkInitService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	deleterID, err := resolveUserID(ctx, service, tmplDeleteBy)
	if err != nil {
		return err
	}
	if err := requireTemplateAuthority(ctx, service, deleterID); err != nil {
		return err
	}

	if err := service.DeleteRejectionReasonTemplate(ctx, deleterID, uint(id)); err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}
	fmt.Printf("Template %d deleted.\n", id)
	return nil
}

// requireTemplateAuthority verifies that actorID — the user resolved from
// --by — actually holds the authority the equivalent HTTP routes require for
// rejection-reason-template management: POST/GET/DELETE
// /rejection-reason-templates are all gated on a global roles.assign (see
// router.go; unlike access-request review, templates are not project-scoped,
// so the check here uses the global Scope{}). The local CLI has no
// session/middleware to enforce this, so --by resolving ANY email — with zero
// authority check — would let an operator add, list, or delete rejection
// reason templates by naming an arbitrary or unprivileged account.
// CreateRejectionReasonTemplate/ListRejectionReasonTemplates/
// DeleteRejectionReasonTemplate themselves do not check permissions (the HTTP
// handler's job is done by router middleware), so this must be verified here,
// at the CLI entrypoint, before the resolved actor is credited with the
// action. Sibling of requireReviewAuthority/requireInviteAuthority (#264/#491).
func requireTemplateAuthority(ctx context.Context, svc *core.KeyorixCore, actorID uint) error {
	ok, err := svc.Authorize(ctx, actorID, "roles.assign", core.Scope{})
	if err != nil {
		return fmt.Errorf("failed to verify --by authority: %w", err)
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold roles.assign; refusing to attribute this action to them")
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseIDList parses a comma-separated string of uint IDs (e.g. "1,2,3").
func parseIDList(s string) ([]uint, error) {
	parts := strings.Split(strings.TrimSpace(s), ",")
	ids := make([]uint, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid ID %q: must be a positive integer", p)
		}
		ids = append(ids, uint(n))
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one ID is required")
	}
	return ids, nil
}

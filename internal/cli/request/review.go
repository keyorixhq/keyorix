package request

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	reviewID      uint
	reviewAction  string
	reviewRole    string
	reviewReason  string
	reviewBy      string
	reviewTTL     string
	reviewProject string
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Approve or reject a pending access request",
	Long: "Resolve a pending access request (admin-driven, ADR-024).\n" +
		"Approving grants the role at the project scope (--role overrides the suggested role);\n" +
		"rejecting records a --reason.",
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().UintVar(&reviewID, "id", 0, "Access request ID (required)")
	reviewCmd.Flags().StringVar(&reviewAction, "action", "", "approve | reject (required)")
	reviewCmd.Flags().StringVar(&reviewRole, "role", "", "Role to grant on approve (defaults to the suggested role)")
	reviewCmd.Flags().StringVar(&reviewReason, "reason", "", "Reason on reject")
	reviewCmd.Flags().StringVar(&reviewTTL, "ttl", "", "Time-bound the granted role on approve (Go duration, e.g. 4h); empty = permanent")
	reviewCmd.Flags().StringVar(&reviewBy, "by", "", "Reviewer email address (required, for audit)")
	reviewCmd.Flags().StringVar(&reviewProject, "project", "", "Project name (required when a remote server is configured; embedded mode resolves the request's project from the row itself)")
	_ = reviewCmd.MarkFlagRequired("id")
	_ = reviewCmd.MarkFlagRequired("action")
	_ = reviewCmd.MarkFlagRequired("by")
}

func runReview(cmd *cobra.Command, args []string) error { // NOSONAR -- cognitive complexity 31, suppress go:S3776
	if reviewID == 0 {
		return fmt.Errorf("--id is required")
	}
	if reviewAction != "approve" && reviewAction != "reject" {
		return fmt.Errorf("--action must be approve or reject")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runReviewRemote(ctx, rc)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	approverID, err := resolveUserID(ctx, service, reviewBy)
	if err != nil {
		return err
	}

	// The approve/reject core methods are project-scoped (cross-project guard);
	// the embedded CLI admin operates on the request's own project.
	existing, err := service.Storage().GetAccessRequest(ctx, reviewID)
	if err != nil {
		return fmt.Errorf("access request %d not found", reviewID)
	}
	projectID := existing.ProjectID

	if err := requireReviewAuthority(ctx, service, approverID, projectID); err != nil {
		return err
	}

	switch reviewAction {
	case "approve":
		// A secret-scoped request (SecretID set) grants no role at all — it can't go
		// through ApproveAccessRequestWithExpiry, whose entire body is about granting
		// one (see classification_gate.go's doc comment for why that function isn't
		// reused here). Route it to the narrower approval instead.
		if existing.SecretID != nil {
			if reviewRole != "" || reviewTTL != "" {
				return fmt.Errorf("--role and --ttl do not apply to a secret-scoped request (id %d) — it grants no role", reviewID)
			}
			req, err := service.ApproveSecretAccessRequest(ctx, reviewID, approverID)
			if err != nil {
				return fmt.Errorf("failed to approve secret access request: %w", err)
			}
			fmt.Printf("Secret access request %d approved for %s to read secret %d.\n",
				req.ID, userLabel(ctx, service, req.UserID), *req.SecretID)
			return nil
		}
		var ttl time.Duration
		if reviewTTL != "" {
			ttl, err = time.ParseDuration(reviewTTL)
			if err != nil || ttl < 0 {
				return fmt.Errorf("--ttl must be a non-negative Go duration (e.g. 4h)")
			}
		}
		req, err := service.ApproveAccessRequestWithExpiry(ctx, projectID, reviewID, approverID, 0, reviewRole, ttl)
		if err != nil {
			return fmt.Errorf("failed to approve access request: %w", err)
		}
		// Under dual control the request may still be pending more approvals.
		if req.State != "approved" {
			fmt.Printf("Approval recorded for access request %d (%d of %d) — more approvals needed before the role is granted.\n",
				req.ID, req.ApprovalsReceived, req.RequiredApprovals)
			return nil
		}
		grantNote := "permanently"
		if ttl > 0 {
			grantNote = fmt.Sprintf("for %s (time-bound)", ttl)
		}
		fmt.Printf("Access request %d approved: granted role %q to %s %s.\n",
			req.ID, req.GrantedRole, userLabel(ctx, service, req.UserID), grantNote)
	case "reject":
		req, err := service.RejectAccessRequest(ctx, projectID, reviewID, approverID, 0, reviewReason)
		if err != nil {
			return fmt.Errorf("failed to reject access request: %w", err)
		}
		fmt.Printf("Access request %d rejected.\n", req.ID)
	}
	return nil
}

// runReviewRemote resolves and approves/rejects the request. A project/role
// request goes through PUT /api/v1/projects/{id}/access-requests/{requestId},
// gated server-side on roles.assign scoped to the project -- the SAME
// authority requireReviewAuthority enforces manually in embedded mode. A
// secret-scoped request (SecretID set) instead goes through PUT
// /api/v1/secret-access-requests/{requestId}, gated on admin authority at the
// request's own project (classification_gate.go's ApproveSecretAccessRequest/
// RejectSecretAccessRequest). --by is not consulted for either shape: the
// server determines the approver from the caller's own bearer token, not from
// any --by value in the request body.
//
// --project is required here (unlike embedded mode, which reads the request's
// ProjectID straight off the row) to first FIND the request -- there is no
// human-facing GET-by-ID-alone lookup for a project/role request this CLI can
// use to discover it -- see fetchAccessRequest's doc comment for why this
// deliberately does not scan every project to find it. A secret-scoped
// request's own resolve endpoint carries no project ID, but --project is
// still needed up front since the request's shape isn't known until after
// this initial lookup.
func runReviewRemote(ctx context.Context, rc *common.RemoteClient) error {
	if reviewProject == "" {
		return fmt.Errorf("--project is required when a remote server is configured (PUT " +
			".../projects/{id}/access-requests/{requestId} is project-scoped in its URL; embedded mode can " +
			"resolve this from the request row directly, remote mode cannot without it)")
	}
	projectID, err := resolveProjectIDByName(ctx, rc, reviewProject)
	if err != nil {
		return err
	}

	existing, err := fetchAccessRequest(ctx, rc, projectID, reviewID)
	if err != nil {
		return err
	}
	requesterLabel := remoteUserLabel(ctx, rc, existing.UserID)
	fmt.Printf("Resolved access request %d in project %q: requester %s, state=%s.\n",
		reviewID, reviewProject, requesterLabel, existing.State)

	// A secret-scoped request (SecretID set) grants no role at all -- resolve it
	// through PUT /api/v1/secret-access-requests/{requestId} instead
	// (classification_gate.go's ApproveSecretAccessRequest/RejectSecretAccessRequest),
	// gated on admin authority at the request's own project rather than
	// roles.assign -- classification_gate.go's own doc comment explains why the
	// weaker project/role family's bar doesn't fit a grant that carries no role
	// at all. Forwarding to the generic PUT below instead would either be
	// refused with a confusing "a role to grant is required" (approve) or
	// succeed under a weaker bar than this family's own endpoint enforces
	// (reject) -- neither is right now that a real remote equivalent exists.
	if existing.SecretID != nil {
		if reviewRole != "" || reviewTTL != "" {
			return fmt.Errorf("--role and --ttl do not apply to a secret-scoped request (id %d) -- it grants no role", reviewID)
		}
		body := map[string]interface{}{"action": reviewAction, "reason": reviewReason}
		path := fmt.Sprintf("/api/v1/secret-access-requests/%d", reviewID)
		if err := rc.Put(ctx, path, body, nil); err != nil {
			return fmt.Errorf("failed to %s secret access request: %w", reviewAction, err)
		}
		switch reviewAction {
		case "approve":
			fmt.Printf("Secret access request %d approved for %s to read secret %d.\n",
				reviewID, requesterLabel, *existing.SecretID)
		case "reject":
			fmt.Printf("Secret access request %d rejected.\n", reviewID)
		}
		return nil
	}

	var ttl time.Duration
	if reviewTTL != "" {
		ttl, err = time.ParseDuration(reviewTTL)
		if err != nil || ttl < 0 {
			return fmt.Errorf("--ttl must be a non-negative Go duration (e.g. 4h)")
		}
	}

	body := map[string]interface{}{
		"action":       reviewAction,
		"granted_role": reviewRole,
		"reason":       reviewReason,
		"grant_ttl":    reviewTTL,
	}
	path := fmt.Sprintf("/api/v1/projects/%d/access-requests/%d", projectID, reviewID)
	if err := rc.Put(ctx, path, body, nil); err != nil {
		return fmt.Errorf("failed to %s access request: %w", reviewAction, err)
	}

	// The PUT response carries no body (sendSuccess(w, nil, ...)), so re-fetch
	// to report the ACTUAL resulting state truthfully instead of assuming the
	// action fully completed -- under dual control an approve may still be
	// pending more approvals, which this must say plainly, not report as done.
	updated, err := fetchAccessRequest(ctx, rc, projectID, reviewID)
	if err != nil {
		return fmt.Errorf("access request %d was %sd, but re-fetching its state to confirm failed: %w",
			reviewID, reviewAction, err)
	}
	switch reviewAction {
	case "approve":
		if updated.State != "approved" {
			fmt.Printf("Approval recorded for access request %d (%d of %d) — more approvals needed before the role is granted.\n",
				updated.ID, updated.ApprovalsReceived, updated.RequiredApprovals)
			return nil
		}
		grantNote := "permanently"
		if ttl > 0 {
			grantNote = fmt.Sprintf("for %s (time-bound)", ttl)
		}
		fmt.Printf("Access request %d approved: granted role %q to %s %s.\n",
			updated.ID, updated.GrantedRole, requesterLabel, grantNote)
	case "reject":
		fmt.Printf("Access request %d rejected.\n", updated.ID)
	}
	return nil
}

// requireReviewAuthority verifies that actorID — the user resolved from --by —
// actually holds the authority the equivalent HTTP route requires for this
// exact operation: PUT .../projects/{id}/access-requests/{requestId} is gated
// on roles.assign scoped to the project (see router.go). The local CLI has no
// session/middleware to enforce this, so --by resolving ANY email — with zero
// authority check — would let an operator attribute an approval/rejection to
// an arbitrary or unprivileged account purely for what appears in the audit
// trail (#264/#491). ApproveAccessRequestWithExpiry/RejectAccessRequest
// themselves do not check permissions (the HTTP handler's job is done by
// router middleware), so this must be verified here, at the CLI entrypoint,
// before the resolved actor is credited with the action.
func requireReviewAuthority(ctx context.Context, svc *core.KeyorixCore, actorID, projectID uint) error {
	ok, err := svc.Authorize(ctx, actorID, "roles.assign", core.Scope{ProjectID: projectID})
	if err != nil {
		return common.ByAuthorityUnavailableError(err,
			"run PUT /api/v1/projects/{id}/access-requests/{requestId} directly against the hub instead, "+
				"authenticated with your own real session (e.g. via 'keyorix connect'), since the hub, not "+
				"this shared credential, decides who may approve or reject")
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold roles.assign at project %d; refusing to attribute this review to them", projectID)
	}
	return nil
}

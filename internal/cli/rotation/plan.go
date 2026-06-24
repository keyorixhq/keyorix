// plan.go — the `keyorix rotation plan` CLI (ADR-053): print a project's automated
// rotation plan — its overdue/due-soon secrets batched into dependency-safe waves and
// prioritised by urgency, each annotated with why. Talks to
// GET /api/v1/projects/{id}/rotation-plan (scoped by the caller's secrets.read
// permission server-side). With --all-projects it prints the deployment-wide roll-up
// (every project's plan, most pressing first) via GET /api/v1/rotation-plan.
package rotation

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

type plannedRotation struct {
	SecretID    uint     `json:"secret_id"`
	SecretName  string   `json:"secret_name"`
	Status      string   `json:"status"`
	DaysOverdue int      `json:"days_overdue"`
	RiskBand    string   `json:"risk_band"`
	AutoRotate  bool     `json:"auto_rotate"`
	Reasons     []string `json:"reasons"`
}

type rotationWave struct {
	Index   int               `json:"index"`
	Secrets []plannedRotation `json:"secrets"`
}

type rotationPlanView struct {
	ProjectID    uint           `json:"project_id"`
	TotalSecrets int            `json:"total_secrets"`
	OverdueCount int            `json:"overdue_count"`
	DueSoonCount int            `json:"due_soon_count"`
	Waves        []rotationWave `json:"waves"`
}

// deploymentPlanView mirrors core.DeploymentRotationPlan — the install-wide roll-up of
// every project's plan. Rotation dependencies are per-project, so this is a roll-up of
// per-project plans (most overdue first), not a single global wave order.
type deploymentPlanView struct {
	ProjectsScanned  int                `json:"projects_scanned"`
	ProjectsWithWork int                `json:"projects_with_work"`
	TotalSecrets     int                `json:"total_secrets"`
	OverdueCount     int                `json:"overdue_count"`
	DueSoonCount     int                `json:"due_soon_count"`
	Projects         []rotationPlanView `json:"projects"`
}

var planAllProjects bool

var planCmd = &cobra.Command{
	Use:   "plan [project-id]",
	Short: "Print an automated rotation plan (dependency-safe waves, by urgency)",
	Long: `Print the rotation plan for a project: its overdue and due-soon secrets, batched
into dependency-safe waves (rotate a wave at a time, top to bottom; within a wave the
most urgent first) and annotated with why each is due and what it must follow (ADR-053).

With --all-projects, print the deployment-wide roll-up instead: every project's plan
aggregated into install-wide totals, most pressing project first. Dependencies are
per-project, so each project keeps its own wave order.`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		if planAllProjects {
			if len(args) > 0 {
				return fmt.Errorf("--all-projects takes no project-id argument")
			}
			plan, err := fetchDeploymentRotationPlan(context.Background(), c)
			if err != nil {
				return err
			}
			printDeploymentPlan(plan)
			return nil
		}

		if len(args) != 1 {
			return fmt.Errorf("provide a project id, or use --all-projects for the deployment-wide plan")
		}
		projectID, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
		if err != nil || projectID == 0 {
			return fmt.Errorf("invalid project id %q", args[0])
		}
		plan, err := fetchRotationPlan(context.Background(), c, uint(projectID))
		if err != nil {
			return err
		}
		if len(plan.Waves) == 0 {
			fmt.Println("Nothing to rotate — no policy-covered secret in this project is overdue or due soon.")
			return nil
		}
		printProjectPlan(plan, "")
		return nil
	},
}

// printProjectPlan prints one project's plan: a header line, then its waves. indent is
// prefixed to every line so the same renderer serves both the single-project view (no
// indent) and each project block in the deployment-wide view.
func printProjectPlan(plan *rotationPlanView, indent string) {
	fmt.Printf("%sRotation plan for project %d — %d to rotate (%d overdue, %d due soon), %d wave(s):\n",
		indent, plan.ProjectID, plan.TotalSecrets, plan.OverdueCount, plan.DueSoonCount, len(plan.Waves))
	for _, w := range plan.Waves {
		fmt.Printf("\n%sWave %d  (safe to rotate together):\n", indent, w.Index+1)
		for _, s := range w.Secrets {
			fmt.Printf("%s  %-26s %-9s %s%s\n", indent, s.SecretName, statusLabel(s), riskLabel(s.RiskBand), autoRotateLabel(s.AutoRotate))
			if len(s.Reasons) > 0 {
				fmt.Printf("%s      ↳ %s\n", indent, strings.Join(s.Reasons, " · "))
			}
		}
	}
}

// printDeploymentPlan prints the install-wide roll-up: a summary line then each project's
// plan, most pressing first.
func printDeploymentPlan(plan *deploymentPlanView) {
	if plan.ProjectsWithWork == 0 {
		fmt.Printf("Nothing to rotate — no policy-covered secret is overdue or due soon across %d project(s).\n", plan.ProjectsScanned)
		return
	}
	fmt.Printf("Deployment rotation plan — %d to rotate (%d overdue, %d due soon) across %d of %d project(s):\n",
		plan.TotalSecrets, plan.OverdueCount, plan.DueSoonCount, plan.ProjectsWithWork, plan.ProjectsScanned)
	for i := range plan.Projects {
		fmt.Println()
		printProjectPlan(&plan.Projects[i], "  ")
	}
}

func statusLabel(s plannedRotation) string {
	if s.Status == "overdue" {
		return fmt.Sprintf("%dd over", s.DaysOverdue)
	}
	return fmt.Sprintf("%dd left", -s.DaysOverdue)
}

func riskLabel(band string) string {
	if band == "" {
		return ""
	}
	return band + " risk"
}

func autoRotateLabel(auto bool) string {
	if auto {
		return "  (self-rotating)"
	}
	return ""
}

// fetchRotationPlan is split out for httptest-backed tests.
func fetchRotationPlan(ctx context.Context, c *common.RemoteClient, projectID uint) (*rotationPlanView, error) {
	var v rotationPlanView
	if err := c.Get(ctx, fmt.Sprintf("/api/v1/projects/%d/rotation-plan", projectID), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// fetchDeploymentRotationPlan is split out for httptest-backed tests.
func fetchDeploymentRotationPlan(ctx context.Context, c *common.RemoteClient) (*deploymentPlanView, error) {
	var v deploymentPlanView
	if err := c.Get(ctx, "/api/v1/rotation-plan", &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func init() {
	planCmd.Flags().BoolVar(&planAllProjects, "all-projects", false, "Plan rotation across every project (deployment-wide roll-up)")
	RotationCmd.AddCommand(planCmd)
}

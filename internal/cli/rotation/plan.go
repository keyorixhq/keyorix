// plan.go — the `keyorix rotation plan` CLI (ADR-053): print a project's automated
// rotation plan — its overdue/due-soon secrets batched into dependency-safe waves and
// prioritised by urgency, each annotated with why. Talks to
// GET /api/v1/projects/{id}/rotation-plan (scoped by the caller's secrets.read
// permission server-side).
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

var planCmd = &cobra.Command{
	Use:   "plan <project-id>",
	Short: "Print a project's automated rotation plan (dependency-safe waves, by urgency)",
	Long: `Print the rotation plan for a project: its overdue and due-soon secrets, batched
into dependency-safe waves (rotate a wave at a time, top to bottom; within a wave the
most urgent first) and annotated with why each is due and what it must follow (ADR-053).`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		projectID, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
		if err != nil || projectID == 0 {
			return fmt.Errorf("invalid project id %q", args[0])
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		plan, err := fetchRotationPlan(context.Background(), c, uint(projectID))
		if err != nil {
			return err
		}
		if len(plan.Waves) == 0 {
			fmt.Println("Nothing to rotate — no policy-covered secret in this project is overdue or due soon.")
			return nil
		}
		fmt.Printf("Rotation plan for project %d — %d to rotate (%d overdue, %d due soon), %d wave(s):\n",
			plan.ProjectID, plan.TotalSecrets, plan.OverdueCount, plan.DueSoonCount, len(plan.Waves))
		for _, w := range plan.Waves {
			fmt.Printf("\nWave %d  (safe to rotate together):\n", w.Index+1)
			for _, s := range w.Secrets {
				fmt.Printf("  %-26s %-9s %s%s\n", s.SecretName, statusLabel(s), riskLabel(s.RiskBand), autoRotateLabel(s.AutoRotate))
				if len(s.Reasons) > 0 {
					fmt.Printf("      ↳ %s\n", strings.Join(s.Reasons, " · "))
				}
			}
		}
		return nil
	},
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

func init() {
	RotationCmd.AddCommand(planCmd)
}

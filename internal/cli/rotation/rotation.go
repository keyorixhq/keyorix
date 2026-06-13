// Package rotation provides the `keyorix rotation` CLI — manage secret-rotation
// policies (credential-rotation hygiene, a NIS2 / ISO A.5.15 control) from the
// terminal: list, create, inspect and delete policies, and see which policy-
// covered secrets are overdue or approaching their rotation deadline. All commands
// talk to the server's REST API under /api/v1/rotation-policies (scoped by the
// caller's secrets.read / secrets.write permission, server-side).
package rotation

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// RotationCmd is the root `keyorix rotation` command.
var RotationCmd = &cobra.Command{
	Use:     "rotation",
	Aliases: []string{"rotation-policy", "rotate"},
	Short:   "Manage secret-rotation policies and see rotation posture",
}

var (
	cName     string
	cDesc     string
	cScope    string
	cProject  int
	cEnv      int
	cInterval int
	cAlert    int
	cNotify   bool

	lProject int
	lEnv     int

	sProject int
)

func init() {
	createCmd.Flags().StringVar(&cName, "name", "", "Policy name (required)")
	createCmd.Flags().StringVar(&cDesc, "description", "", "Policy description")
	createCmd.Flags().StringVar(&cScope, "scope", "", "Scope: project | environment (required)")
	createCmd.Flags().IntVar(&cProject, "project-id", 0, "Target project (required when --scope project)")
	createCmd.Flags().IntVar(&cEnv, "environment-id", 0, "Target environment (required when --scope environment)")
	createCmd.Flags().IntVar(&cInterval, "interval-days", 0, "Rotation interval in days, 1–365 (required)")
	createCmd.Flags().IntVar(&cAlert, "alert-days-before", 7, "Warn this many days before the deadline (0–90)")
	createCmd.Flags().BoolVar(&cNotify, "notify-on-breach", true, "Notify when a covered secret goes overdue")

	listCmd.Flags().IntVar(&lProject, "project-id", 0, "Filter by project")
	listCmd.Flags().IntVar(&lEnv, "environment-id", 0, "Filter by environment")

	statusCmd.Flags().IntVar(&sProject, "project-id", 0, "Limit to a single project")

	RotationCmd.AddCommand(listCmd, createCmd, showCmd, deleteCmd, statusCmd)
}

func client() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

// policyView mirrors a RotationPolicy. The model has no JSON tags so the server
// emits PascalCase keys; encoding/json decodes case-insensitively, so these tags
// match.
type policyView struct {
	ID              uint   `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Scope           string `json:"scope"`
	ProjectID       *uint  `json:"project_id"`
	EnvironmentID   *uint  `json:"environment_id"`
	IntervalDays    int    `json:"interval_days"`
	AlertDaysBefore int    `json:"alert_days_before"`
	NotifyOnBreach  bool   `json:"notify_on_breach"`
	IsActive        bool   `json:"is_active"`
	CreatedBy       string `json:"created_by"`
}

// evalView mirrors a RotationPolicyEvaluation (snake_case json tags on the server).
type evalView struct {
	PolicyName    string `json:"policy_name"`
	SecretID      uint   `json:"secret_id"`
	SecretName    string `json:"secret_name"`
	ProjectID     uint   `json:"project_id"`
	DaysOverdue   int    `json:"days_overdue"`
	IsOverdue     bool   `json:"is_overdue"`
	IsApproaching bool   `json:"is_approaching"`
}

func scopeTarget(p policyView) string {
	if p.Scope == "project" && p.ProjectID != nil {
		return fmt.Sprintf("project=%d", *p.ProjectID)
	}
	if p.Scope == "environment" && p.EnvironmentID != nil {
		return fmt.Sprintf("env=%d", *p.EnvironmentID)
	}
	return p.Scope
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List rotation policies",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		q := url.Values{}
		if lProject > 0 {
			q.Set("project_id", strconv.Itoa(lProject))
		}
		if lEnv > 0 {
			q.Set("environment_id", strconv.Itoa(lEnv))
		}
		path := "/api/v1/rotation-policies"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var policies []policyView
		if err := c.Get(context.Background(), path, &policies); err != nil {
			return err
		}
		if len(policies) == 0 {
			fmt.Println("No rotation policies.")
			return nil
		}
		fmt.Printf("%-5s %-24s %-14s %-9s %-7s %s\n", "ID", "NAME", "TARGET", "INTERVAL", "ACTIVE", "ALERT")
		for _, p := range policies {
			fmt.Printf("%-5d %-24s %-14s %-9s %-7t %dd\n",
				p.ID, p.Name, scopeTarget(p), fmt.Sprintf("%dd", p.IntervalDays), p.IsActive, p.AlertDaysBefore)
		}
		return nil
	},
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a rotation policy",
	RunE: func(_ *cobra.Command, _ []string) error {
		if strings.TrimSpace(cName) == "" {
			return fmt.Errorf("--name is required")
		}
		if cScope != "project" && cScope != "environment" {
			return fmt.Errorf("--scope must be 'project' or 'environment'")
		}
		if cInterval < 1 || cInterval > 365 {
			return fmt.Errorf("--interval-days must be between 1 and 365")
		}
		if cScope == "project" && cProject == 0 {
			return fmt.Errorf("--project-id is required when --scope project")
		}
		if cScope == "environment" && cEnv == 0 {
			return fmt.Errorf("--environment-id is required when --scope environment")
		}

		body := map[string]any{
			"name":              cName,
			"scope":             cScope,
			"interval_days":     cInterval,
			"alert_days_before": cAlert,
			"notify_on_breach":  cNotify,
		}
		if cDesc != "" {
			body["description"] = cDesc
		}
		if cProject > 0 {
			body["project_id"] = cProject
		}
		if cEnv > 0 {
			body["environment_id"] = cEnv
		}

		c, err := client()
		if err != nil {
			return err
		}
		var p policyView
		if err := c.Post(context.Background(), "/api/v1/rotation-policies", body, &p); err != nil {
			return err
		}
		fmt.Printf("Created rotation policy #%d %q (%s, every %dd, alert %dd before).\n",
			p.ID, p.Name, scopeTarget(p), p.IntervalDays, p.AlertDaysBefore)
		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a rotation policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid policy id: %s", args[0])
		}
		c, err := client()
		if err != nil {
			return err
		}
		var p policyView
		if err := c.Get(context.Background(), fmt.Sprintf("/api/v1/rotation-policies/%d", id), &p); err != nil {
			return err
		}
		fmt.Printf("id:               %d\n", p.ID)
		fmt.Printf("name:             %s\n", p.Name)
		if p.Description != "" {
			fmt.Printf("description:      %s\n", p.Description)
		}
		fmt.Printf("target:           %s\n", scopeTarget(p))
		fmt.Printf("interval:         %d days\n", p.IntervalDays)
		fmt.Printf("alert before:     %d days\n", p.AlertDaysBefore)
		fmt.Printf("notify on breach: %t\n", p.NotifyOnBreach)
		fmt.Printf("active:           %t\n", p.IsActive)
		fmt.Printf("created by:       %s\n", p.CreatedBy)
		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a rotation policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid policy id: %s", args[0])
		}
		c, err := client()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/rotation-policies/%d", id)); err != nil {
			return err
		}
		fmt.Printf("Rotation policy %d deleted.\n", id)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show policy-covered secrets that are overdue or approaching rotation",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		path := "/api/v1/rotation-policies/evaluate"
		if sProject > 0 {
			path += "?project_id=" + strconv.Itoa(sProject)
		}
		var evals []evalView
		if err := c.Get(context.Background(), path, &evals); err != nil {
			return err
		}
		overdue, approaching := 0, 0
		for _, e := range evals {
			if e.IsOverdue {
				overdue++
			} else if e.IsApproaching {
				approaching++
			}
		}
		if overdue == 0 && approaching == 0 {
			fmt.Println("All policy-covered secrets are within their rotation window.")
			return nil
		}
		fmt.Printf("%-6s %-26s %-9s %-10s %s\n", "SECRET", "NAME", "PROJECT", "STATUS", "DAYS")
		for _, e := range evals {
			var status, days string
			switch {
			case e.IsOverdue:
				status, days = "OVERDUE", fmt.Sprintf("%d over", e.DaysOverdue)
			case e.IsApproaching:
				status, days = "approaching", fmt.Sprintf("%d left", -e.DaysOverdue)
			default:
				continue
			}
			fmt.Printf("%-6d %-26s %-9d %-10s %s\n", e.SecretID, e.SecretName, e.ProjectID, status, days)
		}
		fmt.Printf("\n%d overdue, %d approaching.\n", overdue, approaching)
		return nil
	},
}

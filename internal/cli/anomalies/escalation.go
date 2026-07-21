// escalation.go — CLI subcommands for managing alert escalation policies.
// Usage:
//
//	keyorix anomaly escalation list
//	keyorix anomaly escalation create --name X --min-severity medium --after-minutes 30 --channels 1,2
//	keyorix anomaly escalation delete <id>
//	keyorix anomaly escalation run
package anomalies

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// escalationCmd is the "anomaly escalation" subcommand group.
var escalationCmd = &cobra.Command{
	Use:   "escalation",
	Short: "Manage alert escalation policies",
}

var escalationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List alert escalation policies",
	RunE:  runEscalationList,
}

var escalationCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an alert escalation policy",
	RunE:  runEscalationCreate,
}

var escalationDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an alert escalation policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runEscalationDelete,
}

var escalationRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Trigger the alert escalation job immediately",
	RunE:  runEscalationRun,
}

var (
	flagEscalationName         string
	flagEscalationMinSeverity  string
	flagEscalationAfterMinutes int
	flagEscalationChannels     string
)

func init() {
	escalationCreateCmd.Flags().StringVar(&flagEscalationName, "name", "", "Policy name (required)")
	escalationCreateCmd.Flags().StringVar(&flagEscalationMinSeverity, "min-severity", "medium", "Minimum severity to escalate: low|medium|high|critical")
	escalationCreateCmd.Flags().IntVar(&flagEscalationAfterMinutes, "after-minutes", 30, "Escalate if unacknowledged for this many minutes")
	escalationCreateCmd.Flags().StringVar(&flagEscalationChannels, "channels", "", "Comma-separated NotificationChannel IDs")

	escalationCmd.AddCommand(escalationListCmd)
	escalationCmd.AddCommand(escalationCreateCmd)
	escalationCmd.AddCommand(escalationDeleteCmd)
	escalationCmd.AddCommand(escalationRunCmd)

	AnomaliesCmd.AddCommand(escalationCmd)
}

// escalationPolicy mirrors the API wire shape for decoding.
type escalationPolicy struct {
	ID                   float64 `json:"id"`
	Name                 string  `json:"name"`
	MinSeverity          string  `json:"min_severity"`
	EscalateAfterMinutes float64 `json:"escalate_after_minutes"`
	ChannelIDs           string  `json:"channel_ids"`
	Enabled              bool    `json:"enabled"`
}

type escalationListResponse struct {
	Policies []escalationPolicy `json:"policies"`
}

func runEscalationList(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runEscalationListRemote(rc)
}

func runEscalationListRemote(rc *common.RemoteClient) error {
	var result escalationListResponse
	if err := rc.Get(context.Background(), "/api/v1/alert-escalation-policies", &result); err != nil {
		return err
	}
	if len(result.Policies) == 0 {
		fmt.Println("No alert escalation policies found.")
		return nil
	}
	fmt.Printf("Alert Escalation Policies (%d)\n", len(result.Policies))
	fmt.Println("================================")
	for _, p := range result.Policies {
		enabled := ""
		if !p.Enabled {
			enabled = " [disabled]"
		}
		fmt.Printf("[%.0f] %s — min_severity=%s, after=%d min, channels=%q%s\n",
			p.ID, p.Name, p.MinSeverity, int(p.EscalateAfterMinutes), p.ChannelIDs, enabled)
	}
	return nil
}

func runEscalationCreate(cmd *cobra.Command, args []string) error {
	if flagEscalationName == "" {
		return fmt.Errorf("--name is required")
	}
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runEscalationCreateRemote(rc)
}

func runEscalationCreateRemote(rc *common.RemoteClient) error {
	body := map[string]interface{}{
		"name":                   flagEscalationName,
		"min_severity":           flagEscalationMinSeverity,
		"escalate_after_minutes": flagEscalationAfterMinutes,
		"channel_ids":            flagEscalationChannels,
		"enabled":                true,
	}
	var created escalationPolicy
	if err := rc.Post(context.Background(), "/api/v1/alert-escalation-policies", body, &created); err != nil {
		return err
	}
	fmt.Printf("Created alert escalation policy %.0f: %s\n", created.ID, created.Name)
	return nil
}

func runEscalationDelete(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %s", args[0])
	}
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runEscalationDeleteRemote(rc, id)
}

func runEscalationDeleteRemote(rc *common.RemoteClient, id uint64) error {
	path := fmt.Sprintf("/api/v1/alert-escalation-policies/%d", id)
	if err := rc.Delete(context.Background(), path); err != nil {
		return err
	}
	fmt.Printf("Deleted alert escalation policy %d.\n", id)
	return nil
}

func runEscalationRun(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runEscalationRunRemote(rc)
}

type escalationRunResult struct {
	Evaluated int `json:"evaluated"`
	Escalated int `json:"escalated"`
	Skipped   int `json:"skipped"`
}

func runEscalationRunRemote(rc *common.RemoteClient) error {
	var result escalationRunResult
	if err := rc.Post(context.Background(), "/api/v1/system/admin/jobs/run-alert-escalation", map[string]interface{}{}, &result); err != nil {
		return err
	}
	fmt.Printf("Alert escalation run complete: evaluated=%d, escalated=%d, skipped=%d\n",
		result.Evaluated, result.Escalated, result.Skipped)
	return nil
}

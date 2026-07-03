package anomalies

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var AnomaliesCmd = &cobra.Command{
	Use:   "anomalies",
	Short: "Manage anomaly detection alerts",
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List anomaly alerts",
	RunE:  runList,
}

var acknowledgeCmd = &cobra.Command{
	Use:   "acknowledge <id>",
	Short: "Acknowledge an anomaly alert",
	Args:  cobra.ExactArgs(1),
	RunE:  runAcknowledge,
}

var flagUnacknowledged bool

func init() {
	listCmd.Flags().BoolVar(&flagUnacknowledged, "unacknowledged", false, "Show only unacknowledged alerts")
	AnomaliesCmd.AddCommand(listCmd)
	AnomaliesCmd.AddCommand(acknowledgeCmd)
}

// anomalyAlert mirrors the alert shape returned by GET /api/v1/audit/anomalies.
type anomalyAlert struct {
	ID           uint   `json:"ID"`
	SecretName   string `json:"SecretName"`
	AlertType    string `json:"AlertType"`
	Severity     string `json:"Severity"`
	Description  string `json:"Description"`
	AccessedBy   string `json:"AccessedBy"`
	IPAddress    string `json:"IPAddress"`
	DetectedAt   string `json:"DetectedAt"`
	Acknowledged bool   `json:"Acknowledged"`
}

type anomalyListResponse struct {
	Alerts []anomalyAlert `json:"alerts"`
	Total  int            `json:"total"`
}

func runList(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runListRemote(rc)
}

func runListRemote(rc *common.RemoteClient) error {
	path := "/api/v1/audit/anomalies"
	if flagUnacknowledged {
		path += "?unacknowledged=true"
	}
	var result anomalyListResponse
	if err := rc.Get(context.Background(), path, &result); err != nil {
		return err
	}
	if len(result.Alerts) == 0 {
		fmt.Println("No anomaly alerts found.")
		return nil
	}
	fmt.Printf("Anomaly Alerts (%d total)\n", result.Total)
	fmt.Println("======================")
	for _, a := range result.Alerts {
		ack := ""
		if a.Acknowledged {
			ack = " [ACK]"
		}
		fmt.Printf("[%d] %s | %s | %s%s\n", a.ID, a.Severity, a.AlertType, a.DetectedAt[:16], ack)
		fmt.Printf("    Secret: %s | User: %s | IP: %s\n", a.SecretName, a.AccessedBy, a.IPAddress)
		fmt.Printf("    %s\n\n", a.Description)
	}
	return nil
}

func runAcknowledge(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid alert ID: %s", args[0])
	}
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return runAcknowledgeRemote(rc, id)
}

func runAcknowledgeRemote(rc *common.RemoteClient, id uint64) error {
	path := fmt.Sprintf("/api/v1/audit/anomalies/%d/acknowledge", id)
	if err := rc.Post(context.Background(), path, map[string]interface{}{}, nil); err != nil {
		return err
	}
	fmt.Printf("Alert %d acknowledged.\n", id)
	return nil
}

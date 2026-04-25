package anomalies

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
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

func runList(cmd *cobra.Command, args []string) error {
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	url := cfg.Client.Endpoint + "/api/v1/audit/anomalies"
	if flagUnacknowledged {
		url += "?unacknowledged=true"
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Client.Auth.GetAPIKey())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Alerts []struct {
				ID           uint   `json:"ID"`
				SecretName   string `json:"SecretName"`
				AlertType    string `json:"AlertType"`
				Severity     string `json:"Severity"`
				Description  string `json:"Description"`
				AccessedBy   string `json:"AccessedBy"`
				IPAddress    string `json:"IPAddress"`
				DetectedAt   string `json:"DetectedAt"`
				Acknowledged bool   `json:"Acknowledged"`
			} `json:"alerts"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	alerts := result.Data.Alerts
	if len(alerts) == 0 {
		fmt.Println("No anomaly alerts found.")
		return nil
	}
	fmt.Printf("Anomaly Alerts (%d total)\n", result.Data.Total)
	fmt.Println("======================")
	for _, a := range alerts {
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
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	url := fmt.Sprintf("%s/api/v1/audit/anomalies/%d/acknowledge", cfg.Client.Endpoint, id)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Client.Auth.GetAPIKey())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	fmt.Printf("Alert %d acknowledged.\n", id)
	return nil
}

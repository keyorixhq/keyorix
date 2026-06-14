// Package compliance provides `keyorix compliance` — the deployment's controls-
// posture report for auditors (ISO 27001 / SOC 2 / NIS2 / DORA). Talks to
// GET /api/v1/compliance/posture (gated by system.read).
package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// ComplianceCmd is the `keyorix compliance` command.
var ComplianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Deployment controls-posture report (ISO 27001 / SOC 2 / NIS2 / DORA)",
}

type posture struct {
	GeneratedAt    string `json:"generated_at"`
	AuditIntegrity struct {
		ChainVerified bool   `json:"chain_verified"`
		ChainedEvents int64  `json:"chained_events"`
		Checkpointed  bool   `json:"checkpointed"`
		Reason        string `json:"reason"`
	} `json:"audit_integrity"`
	AccessGovernance struct {
		Projects                 int `json:"projects"`
		ProjectsWithOpenCampaign int `json:"projects_with_open_campaign"`
		ProjectsNeverReviewed    int `json:"projects_never_reviewed"`
		OpenCampaigns            int `json:"open_campaigns"`
		PendingItems             int `json:"pending_items"`
		DormantRoleGrants        int `json:"dormant_role_grants"`
		SoDViolations            int `json:"sod_violations"`
	} `json:"access_governance"`
	Rotation struct {
		CoveredSecrets int `json:"covered_secrets"`
		Overdue        int `json:"overdue"`
		DueSoon        int `json:"due_soon"`
	} `json:"rotation"`
	Identity struct {
		ActiveUsers           int `json:"active_users"`
		UsersWithSecondFactor int `json:"users_with_second_factor"`
		SecondFactorPercent   int `json:"second_factor_percent"`
	} `json:"identity"`
	EmergencyAccess struct {
		ActiveActivations int `json:"active_activations"`
		TotalActivations  int `json:"total_activations"`
	} `json:"emergency_access"`
	Classification struct {
		TotalSecrets int `json:"total_secrets"`
		Public       int `json:"public"`
		Internal     int `json:"internal"`
		Confidential int `json:"confidential"`
		Restricted   int `json:"restricted"`
		Unclassified int `json:"unclassified"`
	} `json:"classification"`
	Anomalies struct {
		Unacknowledged   int `json:"unacknowledged"`
		HighSeverityOpen int `json:"high_severity_open"`
	} `json:"anomalies"`
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var reportCmd = &cobra.Command{
	Use:          "report",
	Short:        "Print the deployment's controls-posture report",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var p posture
		if err := c.Get(context.Background(), "/api/v1/compliance/posture", &p); err != nil {
			return err
		}
		fmt.Printf("Compliance posture — %s\n\n", p.GeneratedAt)

		fmt.Println("Audit integrity (ADR-029)")
		fmt.Printf("  chain verified : %s (%d chained events)\n", yesNo(p.AuditIntegrity.ChainVerified), p.AuditIntegrity.ChainedEvents)
		fmt.Printf("  checkpointed   : %s\n", yesNo(p.AuditIntegrity.Checkpointed))
		if p.AuditIntegrity.Reason != "" {
			fmt.Printf("  note           : %s\n", p.AuditIntegrity.Reason)
		}

		fmt.Println("\nAccess governance (ISO A.5.18)")
		fmt.Printf("  projects                  : %d\n", p.AccessGovernance.Projects)
		fmt.Printf("  with an open campaign     : %d\n", p.AccessGovernance.ProjectsWithOpenCampaign)
		fmt.Printf("  never reviewed            : %d\n", p.AccessGovernance.ProjectsNeverReviewed)
		fmt.Printf("  open campaigns / pending  : %d / %d\n", p.AccessGovernance.OpenCampaigns, p.AccessGovernance.PendingItems)
		fmt.Printf("  dormant role grants       : %d\n", p.AccessGovernance.DormantRoleGrants)
		fmt.Printf("  separation-of-duties viol.: %d\n", p.AccessGovernance.SoDViolations)

		fmt.Println("\nRotation hygiene (ISO A.5.15)")
		fmt.Printf("  covered secrets : %d\n", p.Rotation.CoveredSecrets)
		fmt.Printf("  overdue/due-soon: %d / %d\n", p.Rotation.Overdue, p.Rotation.DueSoon)

		fmt.Println("\nIdentity (second factor)")
		fmt.Printf("  active users        : %d\n", p.Identity.ActiveUsers)
		fmt.Printf("  with second factor  : %d (%d%%)\n", p.Identity.UsersWithSecondFactor, p.Identity.SecondFactorPercent)

		fmt.Println("\nEmergency access (break-glass)")
		fmt.Printf("  active / total activations : %d / %d\n", p.EmergencyAccess.ActiveActivations, p.EmergencyAccess.TotalActivations)

		fmt.Println("\nData classification (ISO A.5.12)")
		fmt.Printf("  total secrets : %d\n", p.Classification.TotalSecrets)
		fmt.Printf("  restricted / confidential : %d / %d\n", p.Classification.Restricted, p.Classification.Confidential)
		fmt.Printf("  internal / public         : %d / %d\n", p.Classification.Internal, p.Classification.Public)
		fmt.Printf("  unclassified              : %d\n", p.Classification.Unclassified)

		fmt.Println("\nAccess anomalies (NIS2 detection)")
		fmt.Printf("  open / high-severity : %d / %d\n", p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen)
		return nil
	},
}

var exportOutput string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the auditor evidence pack (posture + supporting records) as JSON",
	Long: `Export a timestamped evidence pack — the posture plus the records that
substantiate it (the audit-chain anchor, access-review campaigns, the break-glass
register, and overdue rotations) — as JSON, for an auditor to archive. Writes to
stdout by default, or to --output FILE.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var raw json.RawMessage
		if err := c.Get(context.Background(), "/api/v1/compliance/evidence", &raw); err != nil {
			return err
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, raw, "", "  "); err != nil {
			pretty.Write(raw) // fall back to the raw bytes if indent fails
		}
		pretty.WriteByte('\n')
		if exportOutput != "" {
			if err := os.WriteFile(exportOutput, pretty.Bytes(), 0o600); err != nil {
				return fmt.Errorf("failed to write %s: %w", exportOutput, err)
			}
			fmt.Printf("Evidence pack written to %s.\n", exportOutput)
			return nil
		}
		_, _ = os.Stdout.Write(pretty.Bytes())
		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "Write the evidence pack to a file instead of stdout")
	ComplianceCmd.AddCommand(reportCmd, exportCmd)
}

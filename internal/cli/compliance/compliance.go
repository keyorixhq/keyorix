// Package compliance provides `keyorix compliance` — the deployment's controls-
// posture report for auditors (ISO 27001 / SOC 2 / NIS2 / DORA). Talks to
// GET /api/v1/compliance/posture (gated by system.read).
package compliance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
		ProjectsOverdue          int `json:"projects_overdue"`
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
		TotalSecrets   int `json:"total_secrets"`
		Public         int `json:"public"`
		Internal       int `json:"internal"`
		Confidential   int `json:"confidential"`
		Restricted     int `json:"restricted"`
		Unclassified   int `json:"unclassified"`
		DynamicConfigs struct {
			Total        int `json:"total"`
			Restricted   int `json:"restricted"`
			Confidential int `json:"confidential"`
			Internal     int `json:"internal"`
			Public       int `json:"public"`
			Unclassified int `json:"unclassified"`
		} `json:"dynamic_configs"`
	} `json:"classification"`
	Anomalies struct {
		Unacknowledged   int `json:"unacknowledged"`
		HighSeverityOpen int `json:"high_severity_open"`
	} `json:"anomalies"`
	LegalHold struct {
		Active bool   `json:"active"`
		Reason string `json:"reason"`
	} `json:"legal_hold"`
	Retention struct {
		Enabled                    bool `json:"enabled"`
		AnomalyAlertsDays          int  `json:"anomaly_alerts_days"`
		ClosedAccessReviewsDays    int  `json:"closed_access_reviews_days"`
		BreakGlassDays             int  `json:"break_glass_days"`
		ResolvedAccessRequestsDays int  `json:"resolved_access_requests_days"`
	} `json:"retention"`
}

// retDays renders a retention window: a day count, or "keep" when 0 (disabled).
func retDays(d int) string {
	if d <= 0 {
		return "keep"
	}
	return fmt.Sprintf("%dd", d)
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
		fmt.Printf("  overdue for recert        : %d\n", p.AccessGovernance.ProjectsOverdue)
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
		dc := p.Classification.DynamicConfigs
		fmt.Printf("  dynamic configs (total / restricted / unclassified) : %d / %d / %d\n", dc.Total, dc.Restricted, dc.Unclassified)

		fmt.Println("\nAccess anomalies (NIS2 detection)")
		fmt.Printf("  open / high-severity : %d / %d\n", p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen)

		fmt.Println("\nLegal hold (ISO A.5.34)")
		if p.LegalHold.Active {
			fmt.Printf("  ACTIVE — purges blocked (%s)\n", p.LegalHold.Reason)
		} else {
			fmt.Println("  none — purges run normally")
		}

		fmt.Println("\nData retention (ISO A.5.33 / GDPR)")
		if p.Retention.Enabled {
			fmt.Printf("  anomaly alerts          : %s\n", retDays(p.Retention.AnomalyAlertsDays))
			fmt.Printf("  closed access reviews   : %s\n", retDays(p.Retention.ClosedAccessReviewsDays))
			fmt.Printf("  break-glass register    : %s\n", retDays(p.Retention.BreakGlassDays))
			fmt.Printf("  resolved access requests: %s\n", retDays(p.Retention.ResolvedAccessRequestsDays))
		} else {
			fmt.Println("  not configured — compliance records kept indefinitely")
		}
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

// controlMatrix mirrors GET /api/v1/compliance/controls.
type controlMatrix struct {
	GeneratedAt string `json:"generated_at"`
	Summary     struct {
		Total         int `json:"total"`
		Pass          int `json:"pass"`
		Gap           int `json:"gap"`
		NotConfigured int `json:"not_configured"`
	} `json:"summary"`
	Controls []struct {
		Name       string `json:"name"`
		Area       string `json:"area"`
		Status     string `json:"status"`
		Detail     string `json:"detail"`
		Frameworks struct {
			ISO27001 []string `json:"iso_27001"`
			SOC2     []string `json:"soc2"`
			NIS2     []string `json:"nis2"`
			DORA     []string `json:"dora"`
		} `json:"frameworks"`
	} `json:"controls"`
}

func statusMark(s string) string {
	switch s {
	case "pass":
		return "PASS"
	case "gap":
		return "GAP "
	default:
		return "n/a "
	}
}

func joinRefs(refs ...[]string) string {
	var all []string
	for _, r := range refs {
		all = append(all, r...)
	}
	if len(all) == 0 {
		return "—"
	}
	out := all[0]
	for _, r := range all[1:] {
		out += ", " + r
	}
	return out
}

var controlsCmd = &cobra.Command{
	Use:          "controls",
	Short:        "Control matrix — controls mapped to ISO 27001 / SOC 2 / NIS2 / DORA with status",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var m controlMatrix
		if err := c.Get(context.Background(), "/api/v1/compliance/controls", &m); err != nil {
			return err
		}
		fmt.Printf("Control matrix — %s\n", m.GeneratedAt)
		fmt.Printf("  %d controls: %d pass, %d gap, %d not-configured\n\n", m.Summary.Total, m.Summary.Pass, m.Summary.Gap, m.Summary.NotConfigured)
		for _, ctrl := range m.Controls {
			fmt.Printf("[%s] %s (%s)\n", statusMark(ctrl.Status), ctrl.Name, ctrl.Area)
			fmt.Printf("        %s\n", ctrl.Detail)
			fmt.Printf("        ISO: %s | SOC2: %s | NIS2: %s | DORA: %s\n",
				joinRefs(ctrl.Frameworks.ISO27001), joinRefs(ctrl.Frameworks.SOC2),
				joinRefs(ctrl.Frameworks.NIS2), joinRefs(ctrl.Frameworks.DORA))
		}
		return nil
	},
}

var (
	verifyFile string
	verifySig  string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an exported evidence pack against its detached signature",
	Long: `Verify the authenticity of an archived evidence pack. Reads the pack file and
its signature (default <file>.sig) and asks the server to recompute the HMAC with its
DEK-derived signing key — proving the pack was produced by this deployment and has
not been modified. Requires server-side encryption (the signing key is DEK-derived).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if verifyFile == "" {
			return fmt.Errorf("--file is required")
		}
		sigPath := verifySig
		if sigPath == "" {
			sigPath = verifyFile + ".sig"
		}
		data, err := os.ReadFile(verifyFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", verifyFile, err)
		}
		sig, err := os.ReadFile(sigPath) // #nosec G304 -- operator-supplied path
		if err != nil {
			return fmt.Errorf("failed to read signature %s: %w", sigPath, err)
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		body := map[string]string{
			"data_b64":  base64.StdEncoding.EncodeToString(data),
			"signature": strings.TrimSpace(string(sig)),
		}
		var res struct {
			Valid          bool   `json:"valid"`
			KeyVersion     string `json:"key_version"`
			CurrentVersion string `json:"current_version"`
			Reason         string `json:"reason"`
		}
		if err := c.Post(context.Background(), "/api/v1/compliance/evidence/verify", body, &res); err != nil {
			return err
		}
		if res.Valid {
			fmt.Printf("VALID — %s is authentic and unmodified (key version %s).\n", verifyFile, res.KeyVersion)
			return nil
		}
		fmt.Printf("NOT VERIFIED — %s\n", res.Reason)
		return fmt.Errorf("evidence pack failed verification")
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "Write the evidence pack to a file instead of stdout")
	verifyCmd.Flags().StringVar(&verifyFile, "file", "", "Path to the evidence pack JSON to verify (required)")
	verifyCmd.Flags().StringVar(&verifySig, "sig", "", "Path to the signature file (default <file>.sig)")
	ComplianceCmd.AddCommand(reportCmd, controlsCmd, exportCmd, verifyCmd)
}

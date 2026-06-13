// campaign.go — `keyorix access-review campaign …`: manage periodic
// access-recertification campaigns (ISO 27001 A.5.18). Open snapshots the current
// access review into items; decide attests/revokes each; close freezes the cycle
// as evidence. Talks to /api/v1/projects/{id}/access-review/campaigns (reads need
// roles.read, mutations roles.assign, at the project scope).
package accessreview

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

type campaignView struct {
	ID        uint   `json:"id"`
	ProjectID uint   `json:"project_id"`
	Name      string `json:"name"`
	State     string `json:"state"`
}

type progressView struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Attested int `json:"attested"`
	Revoked  int `json:"revoked"`
}

type itemView struct {
	ID            uint       `json:"id"`
	PrincipalType string     `json:"principal_type"`
	PrincipalName string     `json:"principal_name"`
	Email         string     `json:"email"`
	Source        string     `json:"source"`
	RoleName      string     `json:"role_name"`
	AccessLevel   string     `json:"access_level"`
	SecretName    string     `json:"secret_name"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	Decision      string     `json:"decision"`
}

var (
	cProject  int
	cCampaign int
	cItem     int
	cName     string
	cAction   string
	cReason   string
	cForce    bool
)

var campaignCmd = &cobra.Command{
	Use:   "campaign",
	Short: "Manage access-review campaigns (periodic recertification cycles, A.5.18)",
	Long: `Run periodic access recertification as a tracked campaign: open snapshots the
project's current access into reviewable items, decide attests or revokes each, and
close freezes the cycle as audit evidence.`,
}

func campaignBase(project int) string {
	return "/api/v1/projects/" + strconv.Itoa(project) + "/access-review/campaigns"
}

func progressStr(p progressView) string {
	return fmt.Sprintf("%d total — %d pending, %d attested, %d revoked", p.Total, p.Pending, p.Attested, p.Revoked)
}

var campaignOpenCmd = &cobra.Command{
	Use:          "open",
	Short:        "Open a new access-review campaign (snapshots current access)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cProject <= 0 {
			return fmt.Errorf("--project-id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Campaign campaignView `json:"campaign"`
			Progress progressView `json:"progress"`
		}
		if err := c.Post(context.Background(), campaignBase(cProject), map[string]string{"name": cName}, &out); err != nil {
			return err
		}
		fmt.Printf("Opened campaign %d (%q) for project %d — %s.\n", out.Campaign.ID, out.Campaign.Name, cProject, progressStr(out.Progress))
		fmt.Printf("Review items: keyorix access-review campaign show --project-id %d --campaign-id %d\n", cProject, out.Campaign.ID)
		return nil
	},
}

var campaignListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List a project's access-review campaigns",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cProject <= 0 {
			return fmt.Errorf("--project-id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Campaigns []struct {
				Campaign campaignView `json:"campaign"`
				Progress progressView `json:"progress"`
			} `json:"campaigns"`
			Count int `json:"count"`
		}
		if err := c.Get(context.Background(), campaignBase(cProject), &out); err != nil {
			return err
		}
		if out.Count == 0 {
			fmt.Printf("No access-review campaigns for project %d.\n", cProject)
			return nil
		}
		fmt.Printf("Access-review campaigns — project %d:\n\n", cProject)
		fmt.Printf("%-5s %-8s %-28s %s\n", "ID", "STATE", "NAME", "PROGRESS")
		for _, c := range out.Campaigns {
			fmt.Printf("%-5d %-8s %-28s %s\n", c.Campaign.ID, c.Campaign.State, truncate(c.Campaign.Name, 28), progressStr(c.Progress))
		}
		return nil
	},
}

var campaignShowCmd = &cobra.Command{
	Use:          "show",
	Short:        "Show a campaign and its items (snapshot + decisions)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cProject <= 0 || cCampaign <= 0 {
			return fmt.Errorf("--project-id and --campaign-id are required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Campaign campaignView `json:"campaign"`
			Items    []itemView   `json:"items"`
			Progress progressView `json:"progress"`
		}
		if err := c.Get(context.Background(), campaignBase(cProject)+"/"+strconv.Itoa(cCampaign), &out); err != nil {
			return err
		}
		fmt.Printf("Campaign %d (%q) — %s — %s\n\n", out.Campaign.ID, out.Campaign.Name, out.Campaign.State, progressStr(out.Progress))
		if len(out.Items) == 0 {
			fmt.Println("No items.")
			return nil
		}
		fmt.Printf("%-6s %-10s %-13s %-22s %-7s %-11s %s\n", "ITEM", "DECISION", "SOURCE", "PRINCIPAL", "ACCESS", "LAST-USED", "DETAIL")
		for _, it := range out.Items {
			principal := it.PrincipalName
			if it.PrincipalType == "user" && it.Email != "" {
				principal = fmt.Sprintf("%s <%s>", it.PrincipalName, it.Email)
			}
			detail := "secret=" + it.SecretName
			if it.Source == "role" {
				detail = "role=" + it.RoleName
			}
			fmt.Printf("%-6d %-10s %-13s %-22s %-7s %-11s %s\n", it.ID, it.Decision, it.Source, truncate(principal, 22), it.AccessLevel, lastUsedLabel(it.PrincipalType, it.LastUsedAt), detail)
		}
		return nil
	},
}

var campaignDecideCmd = &cobra.Command{
	Use:          "decide",
	Short:        "Decide on one campaign item: attest (keep) or revoke",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cProject <= 0 || cCampaign <= 0 || cItem <= 0 {
			return fmt.Errorf("--project-id, --campaign-id and --item-id are required")
		}
		if cAction != "attest" && cAction != "revoke" {
			return fmt.Errorf("--action must be attest or revoke")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		path := fmt.Sprintf("%s/%d/items/%d/decide", campaignBase(cProject), cCampaign, cItem)
		var out struct{}
		if err := c.Post(context.Background(), path, map[string]string{"action": cAction, "reason": cReason}, &out); err != nil {
			return err
		}
		fmt.Printf("Item %d %sed in campaign %d.\n", cItem, cAction, cCampaign)
		return nil
	},
}

var campaignCloseCmd = &cobra.Command{
	Use:          "close",
	Short:        "Close a campaign (freeze as evidence); refuses pending items unless --force",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if cProject <= 0 || cCampaign <= 0 {
			return fmt.Errorf("--project-id and --campaign-id are required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		path := fmt.Sprintf("%s/%d/close", campaignBase(cProject), cCampaign)
		var out struct {
			Campaign campaignView `json:"campaign"`
			Progress progressView `json:"progress"`
		}
		if err := c.Post(context.Background(), path, map[string]bool{"force": cForce}, &out); err != nil {
			return err
		}
		fmt.Printf("Closed campaign %d — %s.\n", out.Campaign.ID, progressStr(out.Progress))
		return nil
	},
}

func init() {
	campaignOpenCmd.Flags().IntVar(&cProject, "project-id", 0, "Project to review (required)")
	campaignOpenCmd.Flags().StringVar(&cName, "name", "", "Campaign name (e.g. \"Q4 2026 access recertification\")")

	campaignListCmd.Flags().IntVar(&cProject, "project-id", 0, "Project (required)")

	campaignShowCmd.Flags().IntVar(&cProject, "project-id", 0, "Project (required)")
	campaignShowCmd.Flags().IntVar(&cCampaign, "campaign-id", 0, "Campaign to show (required)")

	campaignDecideCmd.Flags().IntVar(&cProject, "project-id", 0, "Project (required)")
	campaignDecideCmd.Flags().IntVar(&cCampaign, "campaign-id", 0, "Campaign (required)")
	campaignDecideCmd.Flags().IntVar(&cItem, "item-id", 0, "Item to decide (required)")
	campaignDecideCmd.Flags().StringVar(&cAction, "action", "", "attest | revoke (required)")
	campaignDecideCmd.Flags().StringVar(&cReason, "reason", "", "Optional reviewer note")

	campaignCloseCmd.Flags().IntVar(&cProject, "project-id", 0, "Project (required)")
	campaignCloseCmd.Flags().IntVar(&cCampaign, "campaign-id", 0, "Campaign to close (required)")
	campaignCloseCmd.Flags().BoolVar(&cForce, "force", false, "Close even if items remain pending")

	campaignCmd.AddCommand(campaignOpenCmd, campaignListCmd, campaignShowCmd, campaignDecideCmd, campaignCloseCmd)
	AccessReviewCmd.AddCommand(campaignCmd)
}

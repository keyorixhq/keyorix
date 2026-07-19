package compliance

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var digestSend bool

// digestResponse mirrors the JSON payload from GET /api/v1/compliance/digest.
type digestResponse struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// digestSendResponse mirrors the JSON payload from POST /api/v1/compliance/digest/send.
type digestSendResponse struct {
	Sent bool `json:"sent"`
}

var digestCmd = &cobra.Command{
	Use:   "digest",
	Short: "Print the compliance digest, or broadcast it to notification channels (--send)",
	Long: `Print the on-demand compliance digest (the same title + body that is normally
broadcast on a schedule to Slack/Teams/webhook/email channels), or trigger an
immediate broadcast to the configured notification channels with --send.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if digestSend {
			var res digestSendResponse
			if err := c.Post(context.Background(), "/api/v1/compliance/digest/send", nil, &res); err != nil {
				return err
			}
			if res.Sent {
				fmt.Println("Compliance digest broadcast to notification channels.")
			} else {
				fmt.Println("No notification channels configured — digest not sent.")
			}
			return nil
		}
		var d digestResponse
		if err := c.Get(context.Background(), "/api/v1/compliance/digest", &d); err != nil {
			return err
		}
		fmt.Println(d.Title)
		fmt.Println()
		fmt.Print(d.Body)
		return nil
	},
}

func init() {
	digestCmd.Flags().BoolVar(&digestSend, "send", false, "Broadcast the digest to configured notification channels instead of printing it")
	ComplianceCmd.AddCommand(digestCmd)
}

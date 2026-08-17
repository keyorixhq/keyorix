package compliance

import (
	"context"
	"fmt"
	"strings"

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
		// #G69: title/body are server-rendered today, but this is auditor-
		// facing evidence output and any future free text folded into the
		// digest (event descriptions, control names, etc.) must not be able
		// to embed terminal escape sequences that overwrite or hide prior
		// output. Body sanitizes line-by-line rather than as a single blob so
		// its intentional multi-line formatting survives.
		fmt.Println(common.SanitizeForTerminal(d.Title))
		fmt.Println()
		fmt.Print(sanitizeDigestBody(d.Body))
		return nil
	},
}

// sanitizeDigestBody applies common.SanitizeForTerminal per line so the
// digest body's intentional newlines (formatting, not attacker-controlled)
// survive while any CR/ANSI/other control bytes within a line are stripped.
func sanitizeDigestBody(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lines[i] = common.SanitizeForTerminal(line)
	}
	return strings.Join(lines, "\n")
}

func init() {
	digestCmd.Flags().BoolVar(&digestSend, "send", false, "Broadcast the digest to configured notification channels instead of printing it")
	ComplianceCmd.AddCommand(digestCmd)
}

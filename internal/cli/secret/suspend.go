package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	suspendID     uint
	suspendReason string
	resumeID      uint
)

var suspendCmd = &cobra.Command{
	Use:   "suspend",
	Short: "Suspend a secret — block value reads without deleting it",
	Long: `Freeze a secret: value reads are refused until it is resumed. Versions, shares,
and the audit trail are preserved. Useful for incident response on a suspected-
compromised secret. Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if suspendID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runSuspendRemote(c, suspendID, suspendReason)
	},
}

var resumeCmd = &cobra.Command{
	Use:          "resume",
	Short:        "Resume a suspended secret — restore value reads",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if resumeID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runResumeRemote(c, resumeID)
	},
}

// runSuspendRemote POSTs the suspend request (split out for httptest-backed tests).
func runSuspendRemote(c *common.RemoteClient, id uint, reason string) error {
	body := map[string]interface{}{}
	if reason != "" {
		body["reason"] = reason
	}
	var out struct{}
	if err := c.Post(context.Background(), "/api/v1/secrets/"+strconv.Itoa(int(id))+"/suspend", body, &out); err != nil {
		return err
	}
	fmt.Printf("✓ Secret %d suspended — value reads are now blocked.\n", id)
	return nil
}

// runResumeRemote POSTs the resume request.
func runResumeRemote(c *common.RemoteClient, id uint) error {
	var out struct{}
	if err := c.Post(context.Background(), "/api/v1/secrets/"+strconv.Itoa(int(id))+"/resume", map[string]interface{}{}, &out); err != nil {
		return err
	}
	fmt.Printf("✓ Secret %d resumed — value reads are restored.\n", id)
	return nil
}

func init() {
	suspendCmd.Flags().UintVar(&suspendID, "id", 0, "Secret ID (required)")
	suspendCmd.Flags().StringVar(&suspendReason, "reason", "", "Optional reason recorded in the audit event")
	resumeCmd.Flags().UintVar(&resumeID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(suspendCmd)
	SecretCmd.AddCommand(resumeCmd)
}

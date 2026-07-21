// token.go — machine identity token management commands (ADR-030).
//
// Commands:
//
//	keyorix machine token issue  <name|id> --name <label> [--expires-in-days N] [--classification C] [--project P]
//	keyorix machine token revoke <name|id> <token-id>     [--project P] [--force]
//	keyorix machine token list   <name|id>                [--project P]
package machine

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// tokenCmd is the parent "machine token" subcommand group.
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage machine identity tokens",
	Long:  "Issue, list, and revoke bearer tokens for a machine identity (ADR-030).",
}

const tokenProjectFlagUsage = "Project name (defaults to the active project)" // #nosec G101 -- flag usage string, not a credential

// ── flag variables ────────────────────────────────────────────────────────────

var (
	tokenProjectName    string
	tokenIssueName       string
	tokenIssueExpiryDays int
	tokenIssueClass      string
	tokenRevokeForce     bool
)

// ── issue ─────────────────────────────────────────────────────────────────────

var issueCmd = &cobra.Command{
	Use:          "issue <name|id>",
	Short:        "Issue a new bearer token for a machine identity",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runTokenIssue,
}

func runTokenIssue(cmd *cobra.Command, args []string) error {
	if tokenIssueName == "" {
		return fmt.Errorf("--name is required")
	}
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(tokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		body := map[string]interface{}{
			"name":           tokenIssueName,
			"expires_in_days": tokenIssueExpiryDays,
			"classification": tokenIssueClass,
		}
		var resp struct {
			Token     string  `json:"token"`
			ID        uint    `json:"id"`
			Prefix    string  `json:"prefix"`
			ExpiresAt *string `json:"expires_at"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", projectID, m.ID)
		if err := rc.Post(ctx, path, body, &resp); err != nil {
			return fmt.Errorf("failed to issue machine token: %w", err)
		}
		printIssuedToken(resp.Token, resp.ID, resp.Prefix, resp.ExpiresAt)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	var expiresAt *time.Time
	if tokenIssueExpiryDays > 0 {
		t := time.Now().AddDate(0, 0, tokenIssueExpiryDays)
		expiresAt = &t
	}
	result, err := svc.IssueMachineToken(ctx, projectID, m.ID, tokenIssueName, expiresAt, tokenIssueClass, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to issue machine token: %w", err)
	}
	var expiresStr *string
	if result.Credential.ExpiresAt != nil {
		s := result.Credential.ExpiresAt.Format("2006-01-02")
		expiresStr = &s
	}
	printIssuedToken(result.PlainToken, result.Credential.ID, result.Credential.TokenPrefix, expiresStr)
	return nil
}

func printIssuedToken(token string, id uint, prefix string, expiresAt *string) {
	fmt.Println("Machine token issued. Copy it now — it will not be shown again.")
	fmt.Println()
	fmt.Printf("Token:   %s\n", token)
	fmt.Printf("ID:      %d\n", id)
	fmt.Printf("Prefix:  %s\n", prefix)
	if expiresAt != nil && *expiresAt != "" {
		fmt.Printf("Expires: %s\n", *expiresAt)
	} else {
		fmt.Println("Expires: never")
	}
}

// ── list ──────────────────────────────────────────────────────────────────────

var listTokensCmd = &cobra.Command{
	Use:          "list <name|id>",
	Short:        "List tokens for a machine identity",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runTokenList,
}

// tokenListRow is the DTO shape returned by the server for each token entry.
type tokenListRow struct {
	ID         uint    `json:"id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	LastUsedAt *string `json:"last_used_at"`
	ExpiresAt  *string `json:"expires_at"`
	Revoked    bool    `json:"revoked"`
}

func runTokenList(_ *cobra.Command, args []string) error {
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(tokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		var resp struct {
			Tokens []tokenListRow `json:"tokens"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", projectID, m.ID)
		if err := rc.Get(ctx, path, &resp); err != nil {
			return fmt.Errorf("failed to list machine tokens: %w", err)
		}
		printTokenTable(resp.Tokens)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	creds, err := svc.ListMachineTokens(ctx, projectID, m.ID)
	if err != nil {
		return fmt.Errorf("failed to list machine tokens: %w", err)
	}
	rows := make([]tokenListRow, 0, len(creds))
	for _, c := range creds {
		row := tokenListRow{
			ID:      c.ID,
			Name:    c.Name,
			Prefix:  c.TokenPrefix,
			Revoked: c.Revoked,
		}
		if c.LastUsedAt != nil {
			s := c.LastUsedAt.Format("2006-01-02 15:04")
			row.LastUsedAt = &s
		}
		if c.ExpiresAt != nil {
			s := c.ExpiresAt.Format("2006-01-02")
			row.ExpiresAt = &s
		}
		rows = append(rows, row)
	}
	printTokenTable(rows)
	return nil
}

func printTokenTable(rows []tokenListRow) {
	if len(rows) == 0 {
		fmt.Println("No tokens found.")
		return
	}
	fmt.Printf("%-6s %-22s %-20s %-18s %-12s %s\n", "ID", "NAME", "PREFIX", "LAST USED", "EXPIRES", "REVOKED")
	for _, r := range rows {
		lastUsed := "-"
		if r.LastUsedAt != nil && *r.LastUsedAt != "" {
			lastUsed = *r.LastUsedAt
		}
		expires := "never"
		if r.ExpiresAt != nil && *r.ExpiresAt != "" {
			expires = *r.ExpiresAt
		}
		revoked := "false"
		if r.Revoked {
			revoked = "true"
		}
		fmt.Printf("%-6d %-22s %-20s %-18s %-12s %s\n", r.ID, r.Name, r.Prefix, lastUsed, expires, revoked)
	}
}

// ── revoke ────────────────────────────────────────────────────────────────────

var revokeTokenCmd = &cobra.Command{
	Use:          "revoke <name|id> <token-id>",
	Short:        "Revoke a machine identity token",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE:         runTokenRevoke,
}

func runTokenRevoke(cmd *cobra.Command, args []string) error {
	tokenIDStr := args[1]
	tokenID, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid token ID %q: must be a numeric ID", tokenIDStr)
	}

	ctx := context.Background()
	_, projectID, err := resolveProjectContext(tokenProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	if !tokenRevokeForce {
		fmt.Printf("Revoke token %d? [y/N]: ", tokenID)
		reader := bufio.NewReader(cmd.InOrStdin())
		input, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(input)) != "y" {
			fmt.Println("Revoke aborted.")
			return nil
		}
	}

	if rc, ok := common.NewRemoteClient(); ok {
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens/%d", projectID, m.ID, tokenID)
		if err := rc.Delete(ctx, path); err != nil {
			return fmt.Errorf("failed to revoke machine token: %w", err)
		}
		fmt.Println("Machine token revoked.")
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	if _, err := svc.RevokeMachineToken(ctx, projectID, m.ID, uint(tokenID), 0); err != nil {
		return fmt.Errorf("failed to revoke machine token: %w", err)
	}
	fmt.Println("Machine token revoked.")
	return nil
}

// ── init ──────────────────────────────────────────────────────────────────────

func init() {
	// issue flags
	issueCmd.Flags().StringVar(&tokenProjectName, "project", "", tokenProjectFlagUsage)
	issueCmd.Flags().StringVar(&tokenIssueName, "name", "", "Token label (required)")
	issueCmd.Flags().IntVar(&tokenIssueExpiryDays, "expires-in-days", 0, "Token lifetime in days (0 = never expires)")
	issueCmd.Flags().StringVar(&tokenIssueClass, "classification", "", "Data classification: public | internal | confidential | restricted")

	// list flags
	listTokensCmd.Flags().StringVar(&tokenProjectName, "project", "", tokenProjectFlagUsage)

	// revoke flags
	revokeTokenCmd.Flags().StringVar(&tokenProjectName, "project", "", tokenProjectFlagUsage)
	revokeTokenCmd.Flags().BoolVar(&tokenRevokeForce, "force", false, "Skip the confirmation prompt")

	// register subcommands under "machine token"
	tokenCmd.AddCommand(issueCmd)
	tokenCmd.AddCommand(listTokensCmd)
	tokenCmd.AddCommand(revokeTokenCmd)

	// register "machine token" under the root "machine" command
	MachineCmd.AddCommand(tokenCmd)
}

// Package pat provides the `keyorix pat` CLI — self-service Personal Access Tokens
// (ADR-027/ADR-042) from the terminal: create a (optionally least-privilege-scoped)
// token, list your tokens, and revoke one. All commands talk to the server's REST
// API under /api/v1/auth/tokens (self-scoped to the authenticated caller); the raw
// token is shown exactly once, on create.
package pat

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// PATCmd is the root `keyorix pat` command.
var PATCmd = &cobra.Command{
	Use:     "pat",
	Aliases: []string{"token", "tokens"},
	Short:   "Create and manage personal access tokens",
}

var (
	flagName    string
	flagExpires string
	flagScopes  []string
	flagProject int
	flagEnv     int
)

func init() {
	createCmd.Flags().StringVar(&flagName, "name", "", "Token name (required)")
	createCmd.Flags().StringVar(&flagExpires, "expires", "", "Expiry (RFC3339 or YYYY-MM-DD; omit = never)")
	createCmd.Flags().StringArrayVar(&flagScopes, "scope", nil, "Least-privilege permission (repeatable; e.g. --scope secrets.read). Omit = inherit all your permissions")
	createCmd.Flags().IntVar(&flagProject, "project-id", 0, "Confine the token to a single project (0 = any)")
	createCmd.Flags().IntVar(&flagEnv, "environment-id", 0, "Confine the token to a single environment (0 = any; only with --project-id)")
	PATCmd.AddCommand(createCmd, listCmd, revokeCmd)
}

func client() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

type patView struct {
	ID               uint     `json:"id"`
	Name             string   `json:"name"`
	TokenPrefix      string   `json:"token_prefix"`
	Revoked          bool     `json:"revoked"`
	CreatedAt        string   `json:"created_at"`
	ExpiresAt        *string  `json:"expires_at"`
	LastUsedAt       *string  `json:"last_used_at"`
	Scopes           []string `json:"scopes"`
	ProjectScope     uint     `json:"project_scope"`
	EnvironmentScope uint     `json:"environment_scope"`
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a personal access token (the raw token is shown once)",
	RunE: func(_ *cobra.Command, _ []string) error {
		if strings.TrimSpace(flagName) == "" {
			return fmt.Errorf("--name is required")
		}
		if flagEnv > 0 && flagProject == 0 {
			return fmt.Errorf("--environment-id requires --project-id (an environment belongs to a project)")
		}
		body := map[string]any{"name": flagName}
		if flagExpires != "" {
			exp, err := normalizeExpiry(flagExpires)
			if err != nil {
				return err
			}
			body["expires_at"] = exp
		}
		if len(flagScopes) > 0 {
			body["scopes"] = flagScopes
		}
		if flagProject > 0 {
			body["project_scope"] = flagProject
		}
		if flagEnv > 0 {
			body["environment_scope"] = flagEnv
		}

		c, err := client()
		if err != nil {
			return err
		}
		var out struct {
			Token string  `json:"token"`
			Pat   patView `json:"pat"`
		}
		if err := c.Post(context.Background(), "/api/v1/auth/tokens", body, &out); err != nil {
			return err
		}
		fmt.Println("Token created — copy it now, it will not be shown again:")
		fmt.Printf("  %s\n", out.Token)
		fmt.Printf("  id:    %d\n  name:  %s\n  scope: %s\n", out.Pat.ID, out.Pat.Name, describeScope(out.Pat))
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List your personal access tokens",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var tokens []patView
		if err := c.Get(context.Background(), "/api/v1/auth/tokens", &tokens); err != nil {
			return err
		}
		if len(tokens) == 0 {
			fmt.Println("You have no personal access tokens.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tPREFIX\tCREATED\tLAST USED\tEXPIRES\tREVOKED\tSCOPE") //nolint:errcheck
		for _, t := range tokens {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%t\t%s\n", //nolint:errcheck
				t.ID, t.Name, t.TokenPrefix+"…",
				patDate(&t.CreatedAt), patDate(t.LastUsedAt), patDate(t.ExpiresAt),
				t.Revoked, describeScope(t))
		}
		_ = w.Flush() // #nosec G104
		return nil
	},
}

// patDate renders an optional RFC3339 timestamp as a compact date for the list, or
// "never" when absent (a token never used / non-expiring).
func patDate(s *string) string {
	if s == nil || *s == "" {
		return "never"
	}
	if t, err := time.Parse(time.RFC3339, *s); err == nil {
		return t.Format("2006-01-02")
	}
	return *s
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke one of your tokens",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid token id: %s", args[0])
		}
		c, err := client()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/auth/tokens/%d", id)); err != nil {
			return err
		}
		fmt.Printf("Token %d revoked.\n", id)
		return nil
	},
}

// normalizeExpiry accepts an RFC3339 timestamp or a bare YYYY-MM-DD date (treated
// as start-of-day UTC) and returns an RFC3339 string for the API.
func normalizeExpiry(v string) (string, error) {
	if strings.Contains(v, "T") {
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			return "", fmt.Errorf("invalid --expires %q (want RFC3339 or YYYY-MM-DD): %w", v, err)
		}
		return v, nil
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil {
		return "", fmt.Errorf("invalid --expires %q (want RFC3339 or YYYY-MM-DD): %w", v, err)
	}
	return d.UTC().Format(time.RFC3339), nil
}

// describeScope renders a one-line summary of a token's least-privilege restriction.
func describeScope(t patView) string {
	if len(t.Scopes) == 0 && t.ProjectScope == 0 && t.EnvironmentScope == 0 {
		return "full access"
	}
	parts := make([]string, 0, 3)
	if t.ProjectScope > 0 {
		parts = append(parts, fmt.Sprintf("project=%d", t.ProjectScope))
	}
	if t.EnvironmentScope > 0 {
		parts = append(parts, fmt.Sprintf("env=%d", t.EnvironmentScope))
	}
	if len(t.Scopes) > 0 {
		parts = append(parts, strings.Join(t.Scopes, ","))
	}
	return strings.Join(parts, " ")
}

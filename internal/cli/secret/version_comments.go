package secret

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// versionCommentCmd is the "secret version comment" parent command.
var versionCommentCmd = &cobra.Command{
	Use:   "comment",
	Short: "Manage secret version comments",
	Long:  "Add, list, or delete free-text comments on a specific secret version.",
}

// ── add ──────────────────────────────────────────────────────────────────────

var versionCommentAddCmd = &cobra.Command{
	Use:   "add <secret-id> <version-id> <comment>",
	Short: "Add a comment to a secret version",
	Long: `Add a free-text comment to a specific secret version.

Examples:
  keyorix secret version comment add 42 7 "Rotated after incident"
  keyorix secret version comment add 42 7 "Initial value set"`,
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}
		comment := args[2]
		if comment == "" {
			return fmt.Errorf("comment cannot be empty")
		}

		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		path := fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments", secretID, versionID)
		var result struct {
			ID        uint      `json:"id"`
			Comment   string    `json:"comment"`
			Username  string    `json:"username"`
			CreatedAt time.Time `json:"created_at"`
		}
		if err := c.Post(context.Background(), path, map[string]string{"comment": comment}, &result); err != nil {
			return fmt.Errorf("failed to add comment: %w", err)
		}
		fmt.Printf("Comment added (id=%d) by %s at %s\n", result.ID, result.Username, result.CreatedAt.Format(time.RFC3339))
		return nil
	},
}

// ── list ─────────────────────────────────────────────────────────────────────

var versionCommentListCmd = &cobra.Command{
	Use:   "list <secret-id> <version-id>",
	Short: "List comments on a secret version",
	Long: `List all comments on a specific secret version, oldest first.

Examples:
  keyorix secret version comment list 42 7`,
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}

		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		path := fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments", secretID, versionID)
		var result struct {
			Comments []struct {
				ID        uint      `json:"id"`
				Username  string    `json:"username"`
				Comment   string    `json:"comment"`
				CreatedAt time.Time `json:"created_at"`
			} `json:"comments"`
			Total int `json:"total"`
		}
		if err := c.Get(context.Background(), path, &result); err != nil {
			return fmt.Errorf("failed to list comments: %w", err)
		}

		if result.Total == 0 {
			fmt.Println("No comments found.")
			return nil
		}

		fmt.Printf("Comments for secret %s, version %s (%d total):\n", args[0], args[1], result.Total)
		for _, cmt := range result.Comments {
			fmt.Printf("  [%d] %s (%s): %s\n", cmt.ID, cmt.Username, cmt.CreatedAt.Format("2006-01-02 15:04:05"), cmt.Comment)
		}
		return nil
	},
}

// ── delete ────────────────────────────────────────────────────────────────────

var versionCommentDeleteCmd = &cobra.Command{
	Use:   "delete <secret-id> <version-id> <comment-id>",
	Short: "Delete a comment from a secret version",
	Long: `Delete a comment from a specific secret version by comment ID.

Examples:
  keyorix secret version comment delete 42 7 3`,
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		versionID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid version ID %q: %w", args[1], err)
		}
		commentID, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid comment ID %q: %w", args[2], err)
		}

		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		path := fmt.Sprintf("/api/v1/secrets/%d/versions/%d/comments/%d", secretID, versionID, commentID)
		if err := c.Delete(context.Background(), path); err != nil {
			return fmt.Errorf("failed to delete comment: %w", err)
		}
		fmt.Printf("Comment %d deleted.\n", commentID)
		return nil
	},
}

func init() {
	versionCommentCmd.AddCommand(versionCommentAddCmd)
	versionCommentCmd.AddCommand(versionCommentListCmd)
	versionCommentCmd.AddCommand(versionCommentDeleteCmd)

	// Attach to "secret version comment ..." via the versions parent command.
	// Since there is no existing "secret version" parent, we register directly
	// under versionsCmd (which is "secret versions") by adding a "comment"
	// sibling under SecretCmd instead, following the pattern
	// "keyorix secret version comment <...>".
	SecretCmd.AddCommand(versionCommentCmd)
}

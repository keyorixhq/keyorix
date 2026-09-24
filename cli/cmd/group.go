// group.go ports `keyorix group` (docs/cli-split-inventory.md §2.2, PR 3): group
// CRUD and membership management, REST only. Same flags, output, and exit codes as
// the old CLI's internal/cli/group package's remote-mode branch (ADR-108 Decision A
// removes local mode entirely -- every command here is the "remote" branch of its
// old-CLI counterpart; the confirmation prompt on `group delete` is ported unchanged).
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups",
	Long:  "Create, read, update, delete, list groups and manage membership.",
}

func init() {
	rootCmd.AddCommand(groupCmd)
}

// groupAPIClient resolves the stored credentials and builds a client plus the
// resolved server URL, the shared pre-flight every group subcommand needs (the
// server URL is echoed in several of this package's status messages, matching
// the old CLI's remote-mode output).
func groupAPIClient() (*apiclient.ClientWithResponses, string, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, "", fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, "", err
	}
	client, err := newAPIClient(serverURL, token)
	return client, serverURL, err
}

// ── create ──────────────────────────────────────────────────────────────────────

var (
	groupCreateName        string
	groupCreateDescription string
)

var groupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE:  runGroupCreate,
}

func init() {
	groupCreateCmd.Flags().StringVar(&groupCreateName, "name", "", "Group name (required)")
	groupCreateCmd.Flags().StringVar(&groupCreateDescription, "description", "", "Description")
	groupCmd.AddCommand(groupCreateCmd)
}

func runGroupCreate(cmd *cobra.Command, args []string) error {
	if groupCreateName == "" {
		return fmt.Errorf("name is required (use --name)")
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	fmt.Printf("Creating group %q on %s...\n", groupCreateName, serverURL)

	body := apiclient.CreateGroupJSONRequestBody{Name: groupCreateName}
	if groupCreateDescription != "" {
		body.Description = &groupCreateDescription
	}
	resp, err := client.CreateGroupWithResponse(context.Background(), body)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return fmt.Errorf("failed to create group: HTTP %d", resp.StatusCode())
	}
	g := *resp.JSON201.Data
	fmt.Printf("Group created: id=%d name=%s\n", derefInt(g.Id), derefStr(g.Name))
	return nil
}

// ── get ─────────────────────────────────────────────────────────────────────────

var groupGetID int

var groupGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a group by id",
	RunE:  runGroupGet,
}

func init() {
	groupGetCmd.Flags().IntVar(&groupGetID, "id", 0, "Group ID (required)")
	groupCmd.AddCommand(groupGetCmd)
}

func runGroupGet(cmd *cobra.Command, args []string) error {
	if groupGetID == 0 {
		return fmt.Errorf("group id is required (use --id)")
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetGroupWithResponse(context.Background(), groupGetID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to get group: HTTP %d", resp.StatusCode())
	}
	g := *resp.JSON200.Data
	fmt.Printf("ID: %d\nName: %s\nDescription: %s\n", derefInt(g.Id), derefStr(g.Name), derefStr(g.Description))
	return nil
}

// ── update ──────────────────────────────────────────────────────────────────────

var (
	groupUpdateID          int
	groupUpdateName        string
	groupUpdateDescription string
)

var groupUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a group",
	RunE:  runGroupUpdate,
}

func init() {
	groupUpdateCmd.Flags().IntVar(&groupUpdateID, "id", 0, "Group ID (required)")
	groupUpdateCmd.Flags().StringVar(&groupUpdateName, "name", "", "New name")
	groupUpdateCmd.Flags().StringVar(&groupUpdateDescription, "description", "", "New description")
	groupCmd.AddCommand(groupUpdateCmd)
}

func runGroupUpdate(cmd *cobra.Command, args []string) error {
	if groupUpdateID == 0 {
		return fmt.Errorf("group id is required (use --id)")
	}
	if groupUpdateName == "" && groupUpdateDescription == "" {
		return fmt.Errorf("provide at least one of --name or --description")
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	fmt.Printf("Updating group %d on %s...\n", groupUpdateID, serverURL)

	body := apiclient.UpdateGroupJSONRequestBody{}
	if groupUpdateName != "" {
		body.Name = &groupUpdateName
	}
	if groupUpdateDescription != "" {
		body.Description = &groupUpdateDescription
	}
	resp, err := client.UpdateGroupWithResponse(context.Background(), groupUpdateID, body)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to update group: HTTP %d", resp.StatusCode())
	}
	g := *resp.JSON200.Data
	fmt.Printf("Group updated: id=%d name=%s\n", derefInt(g.Id), derefStr(g.Name))
	return nil
}

// ── delete ──────────────────────────────────────────────────────────────────────

var (
	groupDeleteID    int
	groupDeleteForce bool
)

var groupDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a group",
	RunE:  runGroupDelete,
}

func init() {
	groupDeleteCmd.Flags().IntVar(&groupDeleteID, "id", 0, "Group ID (required)")
	groupDeleteCmd.Flags().BoolVar(&groupDeleteForce, "force", false, "Skip the confirmation prompt")
	groupCmd.AddCommand(groupDeleteCmd)
}

// runGroupDelete mirrors the old CLI's confirm-then-delete flow: the group's
// name is fetched first (best-effort -- an unreachable/erroring GET just falls
// back to an id-only label) so the confirmation prompt and the final result
// both name the actual target.
func runGroupDelete(cmd *cobra.Command, args []string) error {
	if groupDeleteID == 0 {
		return fmt.Errorf("group id is required (use --id)")
	}
	client, serverURL, err := groupAPIClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	label := fmt.Sprintf("group %d", groupDeleteID)
	if resp, gerr := client.GetGroupWithResponse(ctx, groupDeleteID); gerr == nil && resp.JSON200 != nil && resp.JSON200.Data != nil {
		g := *resp.JSON200.Data
		label = fmt.Sprintf("group %d (%s)", derefInt(g.Id), derefStr(g.Name))
	}

	if !groupDeleteForce {
		if !confirmYesNo(fmt.Sprintf("Delete %s on %s? This cannot be undone.", label, serverURL)) {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	fmt.Printf("Deleting %s on %s...\n", label, serverURL)
	resp, err := client.DeleteGroupWithResponse(ctx, groupDeleteID)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	if resp.StatusCode() != 204 {
		return fmt.Errorf("failed to delete group: HTTP %d", resp.StatusCode())
	}
	fmt.Printf("Deleted %s.\n", label)
	return nil
}

// confirmYesNo prompts on stdin and reports whether the operator typed "y"/"yes"
// (case-insensitive). Anything else -- including a blank line -- is treated as
// "no", so an accidental Enter never confirms a destructive action.
func confirmYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (yes/no): ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

// ── list ────────────────────────────────────────────────────────────────────────

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	RunE:  runGroupList,
}

func init() {
	groupCmd.AddCommand(groupListCmd)
}

func runGroupList(cmd *cobra.Command, args []string) error {
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListGroupsWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to list groups: HTTP %d", resp.StatusCode())
	}
	groups := derefGroupSlice(resp.JSON200.Data.Groups)
	fmt.Printf("%-6s %-25s %s\n", "ID", "NAME", "DESCRIPTION")
	for _, g := range groups {
		fmt.Printf("%-6d %-25s %s\n", derefInt(g.Id), cliout.SanitizeForTerminal(derefStr(g.Name)), cliout.SanitizeForTerminal(derefStr(g.Description)))
	}
	return nil
}

// ── members ─────────────────────────────────────────────────────────────────────

var groupMembersID int

var groupMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List members of a group",
	RunE:  runGroupMembers,
}

func init() {
	groupMembersCmd.Flags().IntVar(&groupMembersID, "id", 0, "Group ID (required)")
	groupCmd.AddCommand(groupMembersCmd)
}

func runGroupMembers(cmd *cobra.Command, args []string) error {
	if groupMembersID == 0 {
		return fmt.Errorf("group id is required (use --id)")
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.GetGroupMembersWithResponse(context.Background(), groupMembersID)
	if err != nil {
		return fmt.Errorf("failed to list members: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("failed to list members: HTTP %d", resp.StatusCode())
	}
	members := derefUserSummarySlice(resp.JSON200.Data.Members)
	fmt.Printf("Group %d — %d member(s)\n", groupMembersID, len(members))
	fmt.Printf("%-6s %-20s %-30s\n", "ID", "USERNAME", "EMAIL")
	for _, u := range members {
		fmt.Printf("%-6d %-20s %-30s\n", derefInt(u.Id), cliout.SanitizeForTerminal(derefStr(u.Username)), cliout.SanitizeForTerminal(derefStr(u.Email)))
	}
	return nil
}

// ── add-member ──────────────────────────────────────────────────────────────────

var (
	groupAddMemberGroupID   int
	groupAddMemberUserID    int
	groupAddMemberProjectID int
)

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a user to a group",
	RunE:  runGroupAddMember,
}

func init() {
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberGroupID, "group-id", 0, "Group ID (required)")
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberUserID, "user-id", 0, "User ID (required)")
	groupAddMemberCmd.Flags().IntVar(&groupAddMemberProjectID, "project", 0, "Scope membership to a project (0 = global)")
	groupCmd.AddCommand(groupAddMemberCmd)
}

func runGroupAddMember(cmd *cobra.Command, args []string) error {
	if groupAddMemberGroupID == 0 || groupAddMemberUserID == 0 {
		return fmt.Errorf("--group-id and --user-id are required")
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	body := apiclient.AddGroupMemberJSONRequestBody{UserId: groupAddMemberUserID}
	if groupAddMemberProjectID != 0 {
		body.ProjectId = &groupAddMemberProjectID
	}
	resp, err := client.AddGroupMemberWithResponse(context.Background(), groupAddMemberGroupID, body)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("failed to add member: HTTP %d", resp.StatusCode())
	}
	fmt.Printf("User %d added to group %d (project %d).\n", groupAddMemberUserID, groupAddMemberGroupID, groupAddMemberProjectID)
	return nil
}

// ── remove-member ───────────────────────────────────────────────────────────────

var (
	groupRemoveMemberGroupID   int
	groupRemoveMemberUserID    int
	groupRemoveMemberProjectID int
)

var groupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a user from a group",
	RunE:  runGroupRemoveMember,
}

func init() {
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberGroupID, "group-id", 0, "Group ID (required)")
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberUserID, "user-id", 0, "User ID (required)")
	groupRemoveMemberCmd.Flags().IntVar(&groupRemoveMemberProjectID, "project", 0, "Scope membership to a project (0 = global)")
	groupCmd.AddCommand(groupRemoveMemberCmd)
}

func runGroupRemoveMember(cmd *cobra.Command, args []string) error {
	if groupRemoveMemberGroupID == 0 || groupRemoveMemberUserID == 0 {
		return fmt.Errorf("--group-id and --user-id are required")
	}
	client, _, err := groupAPIClient()
	if err != nil {
		return err
	}
	var params *apiclient.RemoveGroupMemberParams
	if groupRemoveMemberProjectID != 0 {
		params = &apiclient.RemoveGroupMemberParams{ProjectId: &groupRemoveMemberProjectID}
	}
	resp, err := client.RemoveGroupMemberWithResponse(context.Background(), groupRemoveMemberGroupID, groupRemoveMemberUserID, params)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	if resp.StatusCode() != 204 {
		return fmt.Errorf("failed to remove member: HTTP %d", resp.StatusCode())
	}
	fmt.Printf("User %d removed from group %d (project %d).\n", groupRemoveMemberUserID, groupRemoveMemberGroupID, groupRemoveMemberProjectID)
	return nil
}

// ── shared helpers ──────────────────────────────────────────────────────────────

func derefGroupSlice(s *[]apiclient.Group) []apiclient.Group {
	if s == nil {
		return nil
	}
	return *s
}

func derefUserSummarySlice(s *[]apiclient.UserSummary) []apiclient.UserSummary {
	if s == nil {
		return nil
	}
	return *s
}

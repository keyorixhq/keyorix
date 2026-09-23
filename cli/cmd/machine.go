// machine.go ports `keyorix machine` (docs/cli-split-inventory.md §2.3, PR 2):
// project-scoped machine identity management (ADR-023/030/031), REST only. Same
// flags, output, and exit codes as the old CLI's internal/cli/machine package minus
// its local/embedded-mode branch (ADR-108 Decision A removes local mode entirely --
// every command here is the "remote" branch of its old-CLI counterpart).
//
// Unlike the old CLI, this one has no "active project" concept yet (that lives in
// the `project` command group, ported in a later Phase 3 PR per docs/cli-split-
// inventory.md §7) -- every command requires --project or KEYORIX_PROJECT.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine identities",
	Long:  "Commands for listing, creating, and managing the lifecycle of project machine identities (CI, k8s, services, automation).",
}

func init() {
	rootCmd.AddCommand(machineCmd)
}

// machineAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every machine subcommand needs.
func machineAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

// resolveMachineProjectID resolves a project name (flag or KEYORIX_PROJECT) to its
// numeric ID via GET /api/v1/projects.
func resolveMachineProjectID(client *apiclient.ClientWithResponses, flagValue string) (string, int, error) {
	name := flagValue
	if name == "" {
		name = os.Getenv("KEYORIX_PROJECT")
	}
	if name == "" {
		return "", 0, fmt.Errorf("no project given: pass --project or set KEYORIX_PROJECT")
	}
	resp, err := client.ListProjectsWithResponse(context.Background(), nil)
	if err != nil {
		return "", 0, fmt.Errorf("failed to list projects: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Projects == nil {
		return "", 0, fmt.Errorf("failed to list projects: HTTP %d", resp.StatusCode())
	}
	for _, p := range *resp.JSON200.Data.Projects {
		if p.Name != nil && *p.Name == name {
			return name, derefInt(p.Id), nil
		}
	}
	return "", 0, fmt.Errorf("project %q not found", name)
}

// fetchMachineIdentities lists a project's machine identities.
func fetchMachineIdentities(client *apiclient.ClientWithResponses, projectID int) ([]apiclient.MachineIdentity, error) {
	resp, err := client.ListMachineIdentitiesWithResponse(context.Background(), projectID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.MachineIdentities == nil {
		if resp.StatusCode() != 200 {
			return nil, fmt.Errorf("failed to list machine identities: HTTP %d", resp.StatusCode())
		}
		return nil, nil
	}
	return *resp.JSON200.Data.MachineIdentities, nil
}

// findMachineByRef finds a machine identity in a project by numeric ID or name.
//
// A ref that parses as a valid numeric ID is ALWAYS resolved as an ID lookup -- it
// never falls through to a Name match, even if no identity has that ID (G78, ported
// unchanged from the old CLI: a purely numeric Name could otherwise shadow the
// intended machine and get resolved instead).
func findMachineByRef(client *apiclient.ClientWithResponses, projectID int, ref string) (apiclient.MachineIdentity, error) {
	identities, err := fetchMachineIdentities(client, projectID)
	if err != nil {
		return apiclient.MachineIdentity{}, fmt.Errorf("failed to list machine identities: %w", err)
	}
	if id, err := strconv.Atoi(ref); err == nil {
		for _, m := range identities {
			if derefInt(m.Id) == id {
				return m, nil
			}
		}
		return apiclient.MachineIdentity{}, fmt.Errorf("machine identity %q not found in project", ref)
	}
	for _, m := range identities {
		if derefStr(m.Name) == ref {
			return m, nil
		}
	}
	return apiclient.MachineIdentity{}, fmt.Errorf("machine identity %q not found in project", ref)
}

// ── create ──────────────────────────────────────────────────────────────────────

var (
	machineCreateProjectName    string
	machineCreateName           string
	machineCreateType           string
	machineCreateDescription    string
	machineCreateClassification string
)

var machineCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a machine identity in a project",
	RunE:  runMachineCreate,
}

func init() {
	machineCreateCmd.Flags().StringVar(&machineCreateProjectName, "project", "", "Project name")
	machineCreateCmd.Flags().StringVar(&machineCreateName, "name", "", "Machine identity name (required)")
	machineCreateCmd.Flags().StringVar(&machineCreateType, "type", "other", "Identity type: ci | k8s | service | automation | other | node")
	machineCreateCmd.Flags().StringVar(&machineCreateDescription, "description", "", "Description")
	machineCreateCmd.Flags().StringVar(&machineCreateClassification, "classification", "", "Data classification: public | internal | confidential | restricted")
	machineCmd.AddCommand(machineCreateCmd)
}

func runMachineCreate(cmd *cobra.Command, args []string) error {
	if machineCreateName == "" {
		return fmt.Errorf("--name is required")
	}
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineCreateProjectName)
	if err != nil {
		return err
	}

	body := apiclient.CreateMachineIdentityJSONRequestBody{
		Name:         machineCreateName,
		IdentityType: &machineCreateType,
	}
	if machineCreateDescription != "" {
		body.Description = &machineCreateDescription
	}
	if machineCreateClassification != "" {
		body.Classification = &machineCreateClassification
	}
	resp, err := client.CreateMachineIdentityWithResponse(context.Background(), projectID, body)
	if err != nil {
		return fmt.Errorf("failed to create machine identity: %w", err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.MachineIdentity == nil {
		return fmt.Errorf("failed to create machine identity: HTTP %d", resp.StatusCode())
	}
	m := *resp.JSON201.Data.MachineIdentity
	fmt.Printf("Machine identity created: id=%d name=%q type=%s state=%s\n",
		derefInt(m.Id), derefStr(m.Name), derefStr(m.IdentityType), string(derefState(m.State)))
	return nil
}

// ── list ────────────────────────────────────────────────────────────────────────

var machineListProjectName string

var machineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List machine identities in a project",
	RunE:  runMachineList,
}

func init() {
	machineListCmd.Flags().StringVar(&machineListProjectName, "project", "", "Project name")
	machineCmd.AddCommand(machineListCmd)
}

func runMachineList(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	projectName, projectID, err := resolveMachineProjectID(client, machineListProjectName)
	if err != nil {
		return err
	}
	identities, err := fetchMachineIdentities(client, projectID)
	if err != nil {
		return fmt.Errorf("failed to list machine identities: %w", err)
	}
	if len(identities) == 0 {
		fmt.Printf("No machine identities found for project %q.\n", projectName)
		return nil
	}
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "ID", "NAME", "TYPE", "STATE", "DESCRIPTION")
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "-----", "------------------------", "------------", "----------", "-----------")
	for _, m := range identities {
		desc := derefStr(m.Description)
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-5d %-24s %-12s %-10s %s\n", derefInt(m.Id), cliout.SanitizeForTerminal(derefStr(m.Name)), derefStr(m.IdentityType), string(derefState(m.State)), cliout.SanitizeForTerminal(desc))
	}
	return nil
}

// ── describe ────────────────────────────────────────────────────────────────────

var machineDescribeProjectName string

var machineDescribeCmd = &cobra.Command{
	Use:   "describe <name|id>",
	Short: "Show details of a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineDescribe,
}

func init() {
	machineDescribeCmd.Flags().StringVar(&machineDescribeProjectName, "project", "", "Project name")
	machineCmd.AddCommand(machineDescribeCmd)
}

func runMachineDescribe(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineDescribeProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("ID:          %d\n", derefInt(m.Id))
	fmt.Printf("Name:        %s\n", cliout.SanitizeForTerminal(derefStr(m.Name)))
	fmt.Printf("Type:        %s\n", derefStr(m.IdentityType))
	fmt.Printf("State:       %s\n", string(derefState(m.State)))
	fmt.Printf("Project ID:  %d\n", derefInt(m.ProjectId))
	if desc := derefStr(m.Description); desc != "" {
		fmt.Printf("Description: %s\n", cliout.SanitizeForTerminal(desc))
	}
	if m.LastSeenAt != nil {
		fmt.Printf("Last seen:   %s\n", m.LastSeenAt.Format("2006-01-02 15:04:05 MST"))
	}
	if m.RevokedAt != nil {
		fmt.Printf("Revoked at:  %s\n", m.RevokedAt.Format("2006-01-02 15:04:05 MST"))
	}
	return nil
}

func derefState(s *apiclient.MachineIdentityState) apiclient.MachineIdentityState {
	if s == nil {
		return ""
	}
	return *s
}

// binding.go — `keyorix machine binding` — manage a machine identity's OIDC
// federation bindings (ADR-031). A binding maps an external token's (issuer, subject)
// to the machine, so a Kubernetes projected SA token or any OIDC JWT can authenticate
// as that machine with no stored credential. Like the rest of the machine CLI these
// work in both remote and local modes and resolve a project from --project / the
// active project; the machine is addressed by numeric ID or name.
package machine

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	bindingProjectName string
	bindingIssuer      string
	bindingSubject     string
)

var bindingCmd = &cobra.Command{
	Use:   "binding",
	Short: "Manage a machine identity's OIDC federation bindings (ADR-031)",
	Long:  "Bind external OIDC principals (issuer + subject) to a machine identity so workloads can authenticate with a platform-issued JWT instead of a stored secret.",
}

var bindingAddCmd = &cobra.Command{
	Use:   "add <machine>",
	Short: "Bind an OIDC (issuer, subject) to a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runBindingAdd,
}

var bindingListCmd = &cobra.Command{
	Use:   "list <machine>",
	Short: "List a machine identity's OIDC bindings",
	Args:  cobra.ExactArgs(1),
	RunE:  runBindingList,
}

var bindingRmCmd = &cobra.Command{
	Use:   "rm <machine> <binding-id>",
	Short: "Remove an OIDC binding from a machine identity",
	Args:  cobra.ExactArgs(2),
	RunE:  runBindingRm,
}

func init() {
	for _, c := range []*cobra.Command{bindingAddCmd, bindingListCmd, bindingRmCmd} {
		c.Flags().StringVar(&bindingProjectName, "project", "", "Project name (defaults to the active project)")
	}
	bindingAddCmd.Flags().StringVar(&bindingIssuer, "issuer", "", "OIDC issuer (the token's iss claim) (required)")
	bindingAddCmd.Flags().StringVar(&bindingSubject, "subject", "", "OIDC subject (the token's sub claim) (required)")
	bindingCmd.AddCommand(bindingAddCmd, bindingListCmd, bindingRmCmd)
	MachineCmd.AddCommand(bindingCmd)
}

// bindingRow is the display shape, unifying the remote (JSON) and local (model) forms.
type bindingRow struct {
	ID        uint      `json:"id"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	CreatedAt time.Time `json:"created_at"`
}

// fetchBindingsRemote lists a machine's OIDC bindings over the HTTP API.
func fetchBindingsRemote(ctx context.Context, rc *common.RemoteClient, projectID, machineID uint) ([]bindingRow, error) {
	var resp struct {
		Bindings []bindingRow `json:"bindings"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings", projectID, machineID)
	if err := rc.Get(ctx, path, &resp); err != nil {
		return nil, err
	}
	return resp.Bindings, nil
}

func runBindingAdd(cmd *cobra.Command, args []string) error {
	if bindingIssuer == "" || bindingSubject == "" {
		return fmt.Errorf("--issuer and --subject are required")
	}
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(bindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		body := map[string]string{"issuer": bindingIssuer, "subject": bindingSubject}
		var resp bindingRow
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings", projectID, m.ID)
		if err := rc.Post(ctx, path, body, &resp); err != nil {
			return fmt.Errorf("failed to create OIDC binding: %w", err)
		}
		fmt.Printf("OIDC binding created: id=%d issuer=%q subject=%q → machine %q\n", resp.ID, resp.Issuer, resp.Subject, m.Name)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	// Local mode has no authenticated user; #150: record the operator-asserted
	// KEYORIX_CLI_ACTOR if set, otherwise the existing anonymous (0) creator.
	b, err := svc.CreateOIDCBinding(ctx, projectID, m.ID, bindingIssuer, bindingSubject, common.ResolveActorID())
	if err != nil {
		return fmt.Errorf("failed to create OIDC binding: %w", err)
	}
	fmt.Printf("OIDC binding created: id=%d issuer=%q subject=%q → machine %q\n", b.ID, b.Issuer, b.Subject, m.Name)
	return nil
}

func runBindingList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(bindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	var rows []bindingRow
	if rc, ok := common.NewRemoteClient(); ok {
		rows, err = fetchBindingsRemote(ctx, rc, projectID, m.ID)
		if err != nil {
			return fmt.Errorf("failed to list OIDC bindings: %w", err)
		}
	} else {
		svc, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		bindings, err := svc.ListOIDCBindings(ctx, projectID, m.ID)
		if err != nil {
			return fmt.Errorf("failed to list OIDC bindings: %w", err)
		}
		for _, b := range bindings {
			rows = append(rows, bindingRow{ID: b.ID, Issuer: b.Issuer, Subject: b.Subject, CreatedAt: b.CreatedAt})
		}
	}

	if len(rows) == 0 {
		fmt.Printf("No OIDC bindings for machine %q.\n", m.Name)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tISSUER\tSUBJECT\tCREATED AT") //nolint:errcheck
	for _, b := range rows {
		created := "—"
		if !b.CreatedAt.IsZero() {
			created = b.CreatedAt.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", b.ID, b.Issuer, b.Subject, created) //nolint:errcheck
	}
	_ = w.Flush() // #nosec G104
	return nil
}

func runBindingRm(cmd *cobra.Command, args []string) error {
	bindingID, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid binding ID %q: must be a number", args[1])
	}
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(bindingProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings/%d", projectID, m.ID, bindingID)
		if err := rc.Delete(ctx, path); err != nil {
			return fmt.Errorf("failed to remove OIDC binding: %w", err)
		}
		fmt.Printf("OIDC binding %d removed from machine %q.\n", bindingID, m.Name)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	// #150: record the operator-asserted KEYORIX_CLI_ACTOR if set.
	if err := svc.DeleteOIDCBinding(ctx, projectID, m.ID, uint(bindingID), common.ResolveActorID()); err != nil {
		return fmt.Errorf("failed to remove OIDC binding: %w", err)
	}
	fmt.Printf("OIDC binding %d removed from machine %q.\n", bindingID, m.Name)
	return nil
}

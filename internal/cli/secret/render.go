package secret

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var renderOutput string
var renderProjectName string

var renderCmd = &cobra.Command{
	Use:   "render [template-file]",
	Short: "Render a template, expanding ${secret:<environment>/<name>} references",
	Long: `Render a template file (or stdin) to stdout (or --output), replacing each
${secret:<environment>/<name>} placeholder with that secret's current value.

References are resolved within a single project (--project, KEYORIX_PROJECT, or
the active project — required). Only secrets you can read there are resolved; a
missing or forbidden reference fails the render without writing partial output.
Useful for generating a .env or config file from live Keyorix secrets.

Examples:
  keyorix secret render app.env.tpl -o app.env --project my-project
  cat app.env.tpl | keyorix secret render --project my-project`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runRender,
}

func init() {
	renderCmd.Flags().StringVarP(&renderOutput, "output", "o", "", "Write to this file instead of stdout")
	renderCmd.Flags().StringVar(&renderProjectName, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
	SecretCmd.AddCommand(renderCmd)
}

func runRender(_ *cobra.Command, args []string) error {
	var tmpl []byte
	var err error
	if len(args) == 1 && args[0] != "-" {
		tmpl, err = os.ReadFile(args[0]) // #nosec G304 -- operator-provided template path
		if err != nil {
			return fmt.Errorf("read template: %w", err)
		}
	} else {
		tmpl, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read template from stdin: %w", err)
		}
	}

	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	fmt.Fprintf(os.Stderr, "Rendering via remote server: %s\n", rc.Endpoint)

	projectName, err := common.ResolveProject(renderProjectName)
	if err != nil {
		return err
	}

	ctx := context.Background()
	projectID, err := common.ResolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}

	out, err := renderRemote(ctx, rc, projectID, string(tmpl))
	if err != nil {
		return err
	}

	if renderOutput != "" {
		// #G26: os.WriteFile follows a symlink at renderOutput and truncates whatever it
		// points to — createSecureOutputFile (export.go) refuses that (O_EXCL+O_NOFOLLOW).
		f, err := createSecureOutputFile(renderOutput)
		if err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		_, werr := f.Write([]byte(out))
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("write output: %w", werr)
		}
		if cerr != nil {
			return fmt.Errorf("write output: %w", cerr)
		}
		fmt.Printf("✓ Rendered to %s\n", renderOutput)
		return nil
	}
	fmt.Print(out)
	return nil
}

// renderRemote calls the project-scoped server-side template renderer
// (POST /api/v1/projects/{id}/secrets/render), which resolves every
// ${secret:<environment>/<name>} reference within projectID under the
// caller's own read permissions — the environment name is looked up within
// THIS project only, so a same-named environment/secret in another project
// can never be substituted. Split out from the command so it can be
// exercised against an httptest server.
func renderRemote(ctx context.Context, rc *common.RemoteClient, projectID uint, tmpl string) (string, error) {
	var resp struct {
		Rendered string `json:"rendered"`
	}
	body := map[string]string{"template": tmpl}
	path := fmt.Sprintf("/api/v1/projects/%d/secrets/render", projectID)
	if err := rc.Post(ctx, path, body, &resp); err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	return resp.Rendered, nil
}

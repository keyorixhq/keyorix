package secret

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/secrettemplate"
	"github.com/spf13/cobra"
)

var renderOutput string

var renderCmd = &cobra.Command{
	Use:   "render [template-file]",
	Short: "Render a template, expanding ${secret:<environment>/<name>} references",
	Long: `Render a template file (or stdin) to stdout (or --output), replacing each
${secret:<environment>/<name>} placeholder with that secret's current value.

Only secrets you can read are resolved; a missing or forbidden reference fails the
render without writing partial output. Useful for generating a .env or config file
from live Keyorix secrets.

Examples:
  keyorix secret render app.env.tpl -o app.env
  cat app.env.tpl | keyorix secret render`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runRender,
}

func init() {
	renderCmd.Flags().StringVarP(&renderOutput, "output", "o", "", "Write to this file instead of stdout")
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

	ctx := context.Background()
	// A template with zero ${secret:...} references never calls the resolver,
	// so renderWith below would otherwise report success without ever making a
	// network call — indistinguishable from a genuinely-reached server. Ping
	// unconditionally so an unreachable/misconfigured remote is caught before
	// anything is written, regardless of what the template actually contains.
	if err := rc.Ping(ctx); err != nil {
		return fmt.Errorf("remote server unreachable: %w", err)
	}

	out, err := renderWith(ctx, rc, string(tmpl))
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

// renderWith expands the template using a resolver backed by the remote client. Split
// out from the command so it can be exercised against an httptest server.
func renderWith(ctx context.Context, rc *common.RemoteClient, tmpl string) (string, error) {
	return secrettemplate.Render(tmpl, keyorixResolver(ctx, rc))
}

// keyorixResolver resolves "<environment>/<name>" to the secret's value over the API:
// list the environment's secrets to find the id (exact, case-insensitive name match),
// then read the value. The name segment may contain slashes (path-like names).
func keyorixResolver(ctx context.Context, rc *common.RemoteClient) secrettemplate.Resolver {
	return func(ref string) (string, error) {
		env, name, err := splitSecretRef(ref)
		if err != nil {
			return "", err
		}
		var list struct {
			Secrets []struct {
				ID   uint   `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
		}
		path := fmt.Sprintf("/api/v1/secrets?environment=%s&page_size=1000&page=1", url.QueryEscape(env))
		if err := rc.Get(ctx, path, &list); err != nil {
			return "", fmt.Errorf("list secrets in %q: %w", env, err)
		}
		var id uint
		for _, s := range list.Secrets {
			if strings.EqualFold(s.Name, name) {
				id = s.ID
				break
			}
		}
		if id == 0 {
			return "", fmt.Errorf("secret %q not found in environment %q", name, env)
		}
		var vb struct {
			Value string `json:"value"`
		}
		if err := rc.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), &vb); err != nil {
			return "", fmt.Errorf("read value: %w", err)
		}
		return vb.Value, nil
	}
}

// splitSecretRef splits "<environment>/<name>"; the name may contain further slashes.
func splitSecretRef(ref string) (env, name string, err error) {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid reference %q: expected \"<environment>/<name>\"", ref)
	}
	return ref[:i], ref[i+1:], nil
}

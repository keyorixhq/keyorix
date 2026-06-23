package dynamic

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// adminDSNEnv lets operators supply the privileged admin connection string out of
// band (CI, scripts) instead of the interactive hidden prompt — never as a flag,
// so it cannot land in shell history or process listings.
const adminDSNEnv = "KEYORIX_DYNAMIC_ADMIN_DSN"

var (
	cfgName       string
	cfgProjectID  int
	cfgEnvID      int
	cfgBackend    string
	cfgTemplate   string
	cfgDefaultTTL int
	cfgMaxTTL     int
)

var createConfigCmd = &cobra.Command{
	Use:   "create",
	Short: "Register a new dynamic-secret target config",
	Long: `Register a target database/store Keyorix can mint on-demand credentials for.

The admin DSN — a privileged connection string used only to create and drop the
short-lived users — is read from the ` + adminDSNEnv + ` environment variable, or
prompted for with hidden input. It is never accepted as a flag (so it cannot land
in shell history); the server encrypts it at rest and never returns it.

For the cloud-IAM backends (aws-sts, gcp, azure, kubernetes) the "admin DSN" is
instead a small JSON config and the issued credential is a short-lived cloud token,
not a username/password:
  aws-sts:    {"role_arn":"...","region":"...","duration_seconds":3600} (optional
              creation template = an inline STS session policy)
  gcp:        {"service_account":"sa@project.iam.gserviceaccount.com","scopes":[...]}
  azure:      {"scopes":["https://management.azure.com/.default"]}
  kubernetes: {"namespace":"app","service_account":"my-app","audiences":["https://svc"]}
              (mints a ServiceAccount token via TokenRequest; add
              "api_server"/"ca_cert"/"token" to target an out-of-cluster API server)
Cloud credentials for the mint call come from the ambient identity (AWS chain /
GCP ADC / Azure DefaultAzureCredential / in-cluster ServiceAccount), never from
Keyorix config.

Examples:
  keyorix dynamic-secret create --name app-db --project-id 1 --backend postgres \
    --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};'
  keyorix dynamic-secret create --name cache --project-id 1 --backend redis \
    --creation-template '~app:* +@read'
  # cloud: paste the JSON config at the hidden prompt
  keyorix dynamic-secret create --name aws-readonly --project-id 1 --backend aws-sts
  keyorix dynamic-secret create --name gcp-token   --project-id 1 --backend gcp
  keyorix dynamic-secret create --name k8s-token   --project-id 1 --backend kubernetes`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if cfgName == "" || cfgProjectID == 0 || cfgBackend == "" {
			return fmt.Errorf("--name, --project-id and --backend are required")
		}
		adminDSN, err := readAdminDSN()
		if err != nil {
			return err
		}
		c, err := client()
		if err != nil {
			return err
		}
		body := map[string]any{
			"name":                cfgName,
			"project_id":          cfgProjectID,
			"environment_id":      cfgEnvID,
			"backend_type":        cfgBackend,
			"admin_dsn":           adminDSN,
			"creation_template":   cfgTemplate,
			"default_ttl_seconds": cfgDefaultTTL,
			"max_ttl_seconds":     cfgMaxTTL,
		}
		var out configView
		if err := c.Post(context.Background(), "/api/v1/dynamic-secrets/configs", body, &out); err != nil {
			return err
		}
		fmt.Printf("Created dynamic-secret config #%d (%s, %s).\n", out.ID, out.Name, out.BackendType)
		fmt.Printf("Issue a credential with: keyorix dynamic-secret issue %d\n", out.ID)
		return nil
	},
}

// readAdminDSN resolves the admin DSN from the environment, falling back to a
// hidden interactive prompt. It is never read from a flag.
func readAdminDSN() (string, error) {
	if v := strings.TrimSpace(os.Getenv(adminDSNEnv)); v != "" {
		return v, nil
	}
	fmt.Printf("Admin DSN for the %s target (input hidden): ", cfgBackend)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read admin DSN (set %s for non-interactive use): %w", adminDSNEnv, err)
	}
	dsn := strings.TrimSpace(string(b))
	if dsn == "" {
		return "", fmt.Errorf("admin DSN is required")
	}
	return dsn, nil
}

func init() {
	f := createConfigCmd.Flags()
	f.StringVar(&cfgName, "name", "", "Config name (required)")
	f.IntVar(&cfgProjectID, "project-id", 0, "Project ID (required)")
	f.IntVar(&cfgEnvID, "environment-id", 0, "Environment ID (0 = project-wide)")
	f.StringVar(&cfgBackend, "backend", "", "Backend: postgres | mysql | mongodb | redis | aws-sts | gcp | azure | kubernetes (required)")
	f.StringVar(&cfgTemplate, "creation-template", "", "Backend-specific grant/role/ACL template ({{name}} for SQL)")
	f.IntVar(&cfgDefaultTTL, "default-ttl", 0, "Default lease TTL in seconds (0 = server default)")
	f.IntVar(&cfgMaxTTL, "max-ttl", 0, "Max lease TTL ceiling in seconds (0 = no ceiling)")
	DynamicSecretCmd.AddCommand(createConfigCmd)
}

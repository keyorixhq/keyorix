// templates.go — CLI commands for secret template management.
//
// Commands:
//
//	keyorix secret template list                                — list all templates
//	keyorix secret template get <name>                         — get a template by name
//	keyorix secret template create --name X ...               — create a template
//	keyorix secret template delete <name>                      — delete a template
package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	tmplName           string
	tmplClassification string
	tmplTags           string
	tmplDescription    string
	tmplDescPattern    string
	tmplRotationDays   int
)

// templateCmd is the root "template" sub-command under "secret".
var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage secret templates",
	Long:  "Commands for creating, listing, getting and deleting reusable secret templates.",
}

var templateListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List all secret templates",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runTemplateList(context.Background(), c)
	},
}

func runTemplateList(ctx context.Context, c *common.RemoteClient) error {
	var result struct {
		Templates []*models.SecretTemplate `json:"templates"`
	}
	if err := c.Get(ctx, "/api/v1/secret-templates", &result); err != nil {
		return fmt.Errorf("list templates: %w", err)
	}
	if len(result.Templates) == 0 {
		fmt.Println("No templates found.")
		return nil
	}
	for _, t := range result.Templates {
		fmt.Printf("%-4d  %-30s  %s\n", t.ID, t.Name, t.Description)
	}
	return nil
}

var templateGetCmd = &cobra.Command{
	Use:          "get <name>",
	Short:        "Get a secret template by name",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runTemplateGet(context.Background(), c, args[0])
	},
}

func runTemplateGet(ctx context.Context, c *common.RemoteClient, name string) error {
	// List all and search by name (the API has GET /{id} by numeric ID only).
	var result struct {
		Templates []*models.SecretTemplate `json:"templates"`
	}
	if err := c.Get(ctx, "/api/v1/secret-templates", &result); err != nil {
		return fmt.Errorf("get template: %w", err)
	}
	for _, t := range result.Templates {
		if t.Name == name {
			out, err := json.MarshalIndent(t, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal template: %w", err)
			}
			fmt.Println(string(out))
			return nil
		}
	}
	return fmt.Errorf("template %q not found", name)
}

var templateCreateCmd = &cobra.Command{
	Use:          "create",
	Short:        "Create a secret template",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if tmplName == "" {
			return fmt.Errorf("--name is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runTemplateCreate(context.Background(), c)
	},
}

func runTemplateCreate(ctx context.Context, c *common.RemoteClient) error {
	body := map[string]interface{}{
		"name":                   tmplName,
		"description":            tmplDescription,
		"default_classification": tmplClassification,
		"default_tags":           tmplTags,
		"description_pattern":    tmplDescPattern,
		"rotation_hint_days":     tmplRotationDays,
	}
	var tmpl models.SecretTemplate
	if err := c.Post(ctx, "/api/v1/secret-templates", body, &tmpl); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	fmt.Printf("Template %q created (ID %d).\n", tmpl.Name, tmpl.ID)
	return nil
}

var templateDeleteCmd = &cobra.Command{
	Use:          "delete <name>",
	Short:        "Delete a secret template by name",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runTemplateDelete(context.Background(), c, args[0])
	},
}

func runTemplateDelete(ctx context.Context, c *common.RemoteClient, name string) error {
	// Resolve name → ID first.
	var result struct {
		Templates []*models.SecretTemplate `json:"templates"`
	}
	if err := c.Get(ctx, "/api/v1/secret-templates", &result); err != nil {
		return fmt.Errorf("list templates: %w", err)
	}
	var id uint
	for _, t := range result.Templates {
		if t.Name == name {
			id = t.ID
			break
		}
	}
	if id == 0 {
		return fmt.Errorf("template %q not found", name)
	}
	if err := c.Delete(ctx, "/api/v1/secret-templates/"+strconv.Itoa(int(id))); err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	fmt.Printf("Template %q deleted.\n", name)
	return nil
}

func init() {
	templateCreateCmd.Flags().StringVar(&tmplName, "name", "", "Template name (required)")
	templateCreateCmd.Flags().StringVar(&tmplClassification, "classification", "", "Default classification (public|internal|confidential|restricted)")
	templateCreateCmd.Flags().StringVar(&tmplTags, "tags", "", "Default tags (comma-separated, e.g. db,prod)")
	templateCreateCmd.Flags().StringVar(&tmplDescription, "description", "", "Template description")
	templateCreateCmd.Flags().StringVar(&tmplDescPattern, "description-pattern", "", "Hint text for the description field")
	templateCreateCmd.Flags().IntVar(&tmplRotationDays, "rotation-hint-days", 0, "Suggested rotation interval in days (informational)")

	templateCmd.AddCommand(templateListCmd)
	templateCmd.AddCommand(templateGetCmd)
	templateCmd.AddCommand(templateCreateCmd)
	templateCmd.AddCommand(templateDeleteCmd)

	SecretCmd.AddCommand(templateCmd)
}

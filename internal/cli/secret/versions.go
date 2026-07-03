package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	versionsID     uint
	versionsFormat string
)

var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List secret versions",
	Long: `List all versions of a secret.

Examples:
  keyorix secret versions --id 123
  keyorix secret versions --id 123 --format json`,
	RunE: runVersions,
}

func init() {
	versionsCmd.Flags().UintVar(&versionsID, "id", 0, "Secret ID (required)")
	versionsCmd.Flags().StringVar(&versionsFormat, "format", "table", "Output format (table, json)")
}

func runVersions(cmd *cobra.Command, args []string) error {
	if versionsID == 0 {
		return fmt.Errorf("secret ID is required (use --id)")
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Create context
	ctx := context.Background()

	// Get secret info
	secret, err := service.GetSecret(ctx, versionsID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Get versions
	versions, err := service.GetSecretVersions(ctx, versionsID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	// Display results
	switch versionsFormat {
	case "json":
		displayVersionsJSON(secret, versions)
	case "table":
		displayVersionsTable(secret, versions)
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", versionsFormat)
	}

	return nil
}

func displayVersionsTable(secret *models.SecretNode, versions []*models.SecretVersion) {
	fmt.Printf("📚 Secret Versions\n")
	fmt.Printf("==================\n")
	fmt.Printf("Secret: %s (ID: %d)\n", secret.Name, secret.ID)
	fmt.Printf("Total Versions: %d\n\n", len(versions))

	if len(versions) == 0 {
		fmt.Printf("No versions found.\n")
		return
	}

	// Table header
	fmt.Printf("%-8s %-10s %-10s %-20s %-15s\n",
		"VERSION", "SIZE", "READS", "CREATED", "ALGORITHM")
	fmt.Printf("%-8s %-10s %-10s %-20s %-15s\n",
		"--------", "----------", "----------", "--------------------", "---------------")

	// Table rows
	for _, version := range versions {
		// Parse encryption metadata to get algorithm
		algorithm := "Unknown"
		if len(version.EncryptionMetadata) > 0 {
			// Try to extract algorithm from JSON metadata
			// This is a simplified approach - in production you'd properly parse JSON
			metaStr := string(version.EncryptionMetadata)
			if strings.Contains(metaStr, "AES-256-GCM") {
				algorithm = "AES-256-GCM"
			}
		}

		fmt.Printf("%-8d %-10s %-10d %-20s %-15s\n",
			version.VersionNumber,
			formatBytes(len(version.EncryptedValue)),
			version.ReadCount,
			version.CreatedAt.Format("2006-01-02 15:04:05"),
			algorithm)
	}

	// Show latest version info
	if len(versions) > 0 {
		latest := versions[len(versions)-1]
		fmt.Printf("\n💡 Latest Version: %d (Created: %s)\n",
			latest.VersionNumber,
			latest.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}

// jsonVersionEntry/jsonVersionsOutput are the `secret versions --format json`
// shape. Built and marshaled via encoding/json (not fmt.Printf string
// interpolation) so a secret name/type containing quotes or control
// characters is correctly escaped rather than able to break out of the JSON
// string and inject arbitrary keys (#354).
type jsonVersionEntry struct {
	ID                 uint            `json:"id"`
	VersionNumber      int             `json:"version_number"`
	SizeBytes          int             `json:"size_bytes"`
	ReadCount          int             `json:"read_count"`
	CreatedAt          string          `json:"created_at"`
	EncryptionMetadata json.RawMessage `json:"encryption_metadata,omitempty"`
}

type jsonVersionsOutput struct {
	Secret struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"secret"`
	TotalVersions int                `json:"total_versions"`
	Versions      []jsonVersionEntry `json:"versions"`
}

func displayVersionsJSON(secret *models.SecretNode, versions []*models.SecretVersion) {
	var out jsonVersionsOutput
	out.Secret.ID = secret.ID
	out.Secret.Name = secret.Name
	out.Secret.Type = secret.Type
	out.TotalVersions = len(versions)
	out.Versions = make([]jsonVersionEntry, 0, len(versions))

	for _, version := range versions {
		entry := jsonVersionEntry{
			ID:            version.ID,
			VersionNumber: version.VersionNumber,
			SizeBytes:     len(version.EncryptedValue),
			ReadCount:     version.ReadCount,
			CreatedAt:     version.CreatedAt.Format(time.RFC3339),
		}
		if len(version.EncryptionMetadata) > 0 {
			entry.EncryptionMetadata = json.RawMessage(version.EncryptionMetadata)
		}
		out.Versions = append(out.Versions, entry)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode JSON output: %v\n", err)
	}
}

func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

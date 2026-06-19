package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var infoID uint

// infoView captures the metadata fields of a secret from the GET (raw model,
// PascalCase JSON). The value is never fetched.
type infoView struct {
	ID             uint   `json:"ID"`
	Name           string `json:"Name"`
	Type           string `json:"Type"`
	Classification string `json:"Classification"`
	Status         string `json:"Status"`
	Description    string `json:"Description"`
	OwnerID        uint   `json:"OwnerID"`
	IsShared       bool   `json:"IsShared"`
	CreatedBy      string `json:"CreatedBy"`
	Expiration     string `json:"Expiration"`
	LastRotatedAt  string `json:"LastRotatedAt"`
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show a secret's metadata (no value)",
	Long: `Print a one-shot summary of a secret's metadata — type, classification, status,
description, owner, expiration, and tags — without retrieving the value. Requires
secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if infoID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		ctx := context.Background()
		v, err := fetchInfo(ctx, c, infoID)
		if err != nil {
			return err
		}
		// Tags are a separate endpoint; best-effort (don't fail the summary on it).
		tags, _ := getSecretTags(ctx, c, infoID)

		line := func(label, val string) {
			if val == "" {
				val = "—"
			}
			fmt.Printf("  %-14s %s\n", label, val)
		}
		fmt.Printf("Secret %d: %s\n", v.ID, v.Name)
		line("type", v.Type)
		line("status", orDefault(v.Status, "active"))
		line("classification", orDefault(v.Classification, "unclassified"))
		line("owner", fmt.Sprintf("user #%d", v.OwnerID))
		line("shared", boolWord(v.IsShared))
		line("created by", v.CreatedBy)
		line("expiration", v.Expiration)
		line("last rotated", v.LastRotatedAt)
		line("tags", strings.Join(tags, ", "))
		line("description", v.Description)
		return nil
	},
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// fetchInfo GETs a secret's metadata (split out for httptest tests).
func fetchInfo(ctx context.Context, c *common.RemoteClient, id uint) (*infoView, error) {
	var v infoView
	if err := c.Get(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id)), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func init() {
	infoCmd.Flags().UintVar(&infoID, "id", 0, "Secret ID (required)")
	SecretCmd.AddCommand(infoCmd)
}

package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	tagsID  uint
	tagsSet string
)

var tagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "List or set a secret's tags",
	Long: `Show a secret's tags, or replace them with --set.

Examples:
  keyorix secret tags --id 42                 # list the secret's tags
  keyorix secret tags --id 42 --set prod,tier1  # replace the tag set
  keyorix secret tags --id 42 --set ""        # clear all tags

Listing requires secrets.read; setting requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if tagsID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		ctx := context.Background()

		// --set provided (even as "") → replace; otherwise list.
		if cmd.Flags().Changed("set") {
			tags := splitTags(tagsSet)
			out, err := setSecretTags(ctx, c, tagsID, tags)
			if err != nil {
				return err
			}
			printTags(out)
			return nil
		}

		out, err := getSecretTags(ctx, c, tagsID)
		if err != nil {
			return err
		}
		printTags(out)
		return nil
	},
}

func printTags(tags []string) {
	if len(tags) == 0 {
		fmt.Println("(no tags)")
		return
	}
	fmt.Println(strings.Join(tags, ", "))
}

// splitTags turns a comma-separated flag value into a trimmed, non-empty slice.
func splitTags(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// getSecretTags GETs the secret's tags (split out for httptest tests).
func getSecretTags(ctx context.Context, c *common.RemoteClient, id uint) ([]string, error) {
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := c.Get(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/tags", &body); err != nil {
		return nil, err
	}
	return body.Tags, nil
}

// setSecretTags PUTs the replacement tag set and returns the stored tags.
func setSecretTags(ctx context.Context, c *common.RemoteClient, id uint, tags []string) ([]string, error) {
	reqBody := map[string][]string{"tags": tags}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := c.Put(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/tags", reqBody, &body); err != nil {
		return nil, err
	}
	return body.Tags, nil
}

func init() {
	tagsCmd.Flags().UintVar(&tagsID, "id", 0, "Secret ID (required)")
	tagsCmd.Flags().StringVar(&tagsSet, "set", "", "Replace the secret's tags with this comma-separated list (\"\" clears)")
	SecretCmd.AddCommand(tagsCmd)
}

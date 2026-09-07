// diff.go — keyorix secret diff <name> <from-version> <to-version>
//
// Compares the metadata of two versions of a secret. Values are never shown —
// only classification, expiry, read count, and the current ACL snapshot.
//
// Remote mode:  resolves <name> to its numeric ID via /api/v1/secrets/by-name,
//
//	then calls GET /api/v1/secrets/{id}/versions/{from}/diff/{to}.
//
// Embedded mode: requires --id instead of a name.
package secret

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	diffID      uint
	diffProject string
	diffEnv     string
)

var diffCmd = &cobra.Command{
	Use:   "diff <name> <from-version> <to-version>",
	Short: "Diff metadata between two versions of a secret",
	Long: `Compare metadata between two versions of a secret.

Values (encrypted ciphertext) are never compared — only classification,
expiry, read count, and the current ACL snapshot.

In remote mode the secret is resolved by name (with optional --project and
--env filters). In embedded mode use --id to supply the numeric secret ID.

Examples:
  keyorix secret diff my-api-key 1 3
  keyorix secret diff db-pass 2 4 --project prod --env staging
  keyorix secret diff ignored 1 3 --id 42   # embedded mode: name is ignored`,
	Args:         cobra.ExactArgs(3),
	SilenceUsage: true,
	RunE:         runDiff,
}

func init() {
	diffCmd.Flags().UintVar(&diffID, "id", 0, "Secret ID (required in embedded mode)")
	diffCmd.Flags().StringVar(&diffProject, "project", "", "Project name filter (remote mode)")
	diffCmd.Flags().StringVar(&diffEnv, "env", "", "Environment name filter (remote mode)")
}

func runDiff(_ *cobra.Command, args []string) error {
	name := args[0]

	fromVersion, err := strconv.Atoi(args[1])
	if err != nil || fromVersion <= 0 {
		return fmt.Errorf("from-version must be a positive integer")
	}
	toVersion, err := strconv.Atoi(args[2])
	if err != nil || toVersion <= 0 {
		return fmt.Errorf("to-version must be a positive integer")
	}

	rc, ok := common.NewRemoteClient()
	if ok {
		return runDiffRemote(rc, name, fromVersion, toVersion)
	}

	// Embedded / local mode: --id is required.
	if diffID == 0 {
		return fmt.Errorf("--id is required in embedded mode (or connect to a server first)")
	}
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	svc := core.NewKeyorixCore(st)
	ctx := context.Background()

	diff, err := svc.DiffSecretVersions(ctx, diffID, fromVersion, toVersion)
	if err != nil {
		return err
	}
	printDiff(diff.SecretName, fromVersion, toVersion, diff.Changes, diff.ACLUserIDs, diff.Degraded)
	return nil
}

// runDiffRemote resolves the secret name to an ID then calls the diff endpoint.
func runDiffRemote(rc *common.RemoteClient, name string, fromVersion, toVersion int) error {
	ctx := context.Background()

	// Resolve name → numeric ID via /api/v1/secrets/by-name.
	byNamePath := buildByNamePath(name, diffProject, diffEnv)
	var nodeResp struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	}
	if err := rc.Get(ctx, byNamePath, &nodeResp); err != nil {
		return fmt.Errorf("secret %q not found: %w", name, err)
	}

	diffPath := fmt.Sprintf("/api/v1/secrets/%d/versions/%d/diff/%d", nodeResp.ID, fromVersion, toVersion)
	var result diffResponse
	if err := rc.Get(ctx, diffPath, &result); err != nil {
		return err
	}

	changes := make([]core.SecretVersionChange, 0, len(result.Changes))
	for _, c := range result.Changes {
		changes = append(changes, core.SecretVersionChange{
			Field:    c.Field,
			OldValue: c.OldValue,
			NewValue: c.NewValue,
		})
	}
	printDiff(result.SecretName, result.FromVersion, result.ToVersion, changes, result.ACLUserIDs, result.Degraded)
	return nil
}

// diffResponse is the shape returned by the diff HTTP endpoint (within the
// data envelope that RemoteClient.Get already strips).
type diffResponse struct {
	SecretName  string `json:"secret_name"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
	Changes     []struct {
		Field    string `json:"field"`
		OldValue string `json:"old_value"`
		NewValue string `json:"new_value"`
	} `json:"changes"`
	ACLUserIDs []uint `json:"acl_user_ids"`
	// Degraded is true when the server's ACL lookup itself failed (#G54) --
	// ACLUserIDs is then an unreliable, possibly-empty placeholder, not an
	// authoritative "no ACL grants" answer. #1600: previously discarded here,
	// so a remote-mode CLI diff under storage.type: remote (where the
	// embedded path's ListSecretACLs is a permanent hard stub, always
	// Degraded) silently reported "No ACL entries" indistinguishably from a
	// genuinely empty ACL list.
	Degraded bool `json:"degraded"`
}

// buildByNamePath constructs the /api/v1/secrets/by-name query path.
func buildByNamePath(name, project, env string) string {
	path := "/api/v1/secrets/by-name?name=" + url.QueryEscape(name)
	if project != "" {
		path += "&project=" + url.QueryEscape(project)
	}
	if env != "" {
		path += "&environment=" + url.QueryEscape(env)
	}
	return path
}

// printDiff renders the diff in human-readable form. degraded is true when the
// server's ACL lookup itself failed (#G54) -- aclUserIDs is then an unreliable,
// possibly-empty placeholder, not an authoritative answer (#1600: this used to
// be silently discarded, so a remote-mode CLI diff reported "No ACL entries"
// indistinguishably from a genuinely empty ACL list).
func printDiff(secretName string, fromV, toV int, changes []core.SecretVersionChange, aclUserIDs []uint, degraded bool) {
	fmt.Printf("Secret: %s  (v%d -> v%d)\n\n", secretName, fromV, toV)

	if len(changes) == 0 {
		fmt.Printf("No metadata changes between v%d and v%d.\n", fromV, toV)
	} else {
		for _, ch := range changes {
			fmt.Printf("  %-20s %q -> %q\n", ch.Field, ch.OldValue, ch.NewValue)
		}
	}
	fmt.Println()

	switch {
	case degraded:
		fmt.Println("ACL (current): unavailable -- the ACL lookup failed, this is NOT a confirmed empty list.")
	case len(aclUserIDs) == 0:
		fmt.Println("No ACL entries (current).")
	default:
		ids := make([]string, len(aclUserIDs))
		for i, id := range aclUserIDs {
			ids[i] = strconv.Itoa(int(id))
		}
		fmt.Printf("ACL (current): users [%s]\n", strings.Join(ids, ", "))
	}
}

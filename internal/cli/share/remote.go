// remote.go — server-backed (remote mode) implementations of the read-path share
// commands. Like the rest of the CLI, `keyorix share` is dual-mode: when remote
// config is present (env or ~/.keyorix/cli.yaml from `keyorix connect`) these go
// through the HTTP API so they operate on the same store the dashboard uses;
// otherwise the embedded direct-DB path runs.
//
// Remote mode is also more correct for sharing: the embedded path has no
// authenticated-user concept, whereas the server resolves the caller from the
// session token.
package share

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func runListRemote(rc *common.RemoteClient, secretID uint) error {
	var resp struct {
		Shares []models.ShareRecord `json:"shares"`
	}
	if err := rc.Get(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/shares", secretID), &resp); err != nil {
		return fmt.Errorf("failed to list shares: %w", err)
	}
	if len(resp.Shares) == 0 {
		fmt.Println("No shares found for this secret.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tRECIPIENT ID\tIS GROUP\tPERMISSION\tCREATED AT\tEXPIRES AT") //nolint:errcheck
	for _, share := range resp.Shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%t\t%s\t%s\t%s\n", //nolint:errcheck
			share.ID, share.SecretID, share.OwnerID, share.RecipientID, share.IsGroup,
			share.Permission, share.CreatedAt.Format("2006-01-02 15:04:05"),
			formatShareExpiry(share.ExpiresAt))
	}
	_ = w.Flush() // #nosec G104
	return nil
}

func runRevokeRemote(rc *common.RemoteClient, shareID uint) error {
	if err := rc.Delete(context.Background(), fmt.Sprintf("/api/v1/shares/%d", shareID)); err != nil {
		return fmt.Errorf("failed to revoke share: %w", err)
	}
	fmt.Printf("Share revoked successfully!\n")
	fmt.Printf("Share ID: %d\n", shareID)
	return nil
}

func runUpdateRemote(rc *common.RemoteClient, shareID uint, permission string, expiresAt *time.Time, clearExpiry bool) error {
	body := struct {
		Permission  string     `json:"permission"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		ClearExpiry bool       `json:"clear_expiry,omitempty"`
	}{
		Permission:  permission,
		ExpiresAt:   expiresAt,
		ClearExpiry: clearExpiry,
	}
	var resp models.ShareRecord
	if err := rc.Put(context.Background(), fmt.Sprintf("/api/v1/shares/%d", shareID), body, &resp); err != nil {
		return fmt.Errorf("failed to update share permission: %w", err)
	}
	fmt.Printf("Share permission updated successfully!\n")
	fmt.Printf("Share ID: %d\n", resp.ID)
	fmt.Printf("Permission: %s\n", resp.Permission)
	fmt.Printf("Expires At: %s\n", formatShareExpiry(resp.ExpiresAt))
	return nil
}

func runSharedSecretsRemote(rc *common.RemoteClient) error {
	var resp struct {
		Secrets []models.SecretNode `json:"secrets"`
	}
	if err := rc.Get(context.Background(), "/api/v1/shared-secrets", &resp); err != nil {
		return fmt.Errorf("failed to list shared secrets: %w", err)
	}
	if len(resp.Secrets) == 0 {
		fmt.Println("No shared secrets found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tPROJECT\tENVIRONMENT\tCREATED BY\tCREATED AT") //nolint:errcheck
	for _, secret := range resp.Secrets {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%s\t%s\n", //nolint:errcheck
			secret.ID, secret.Name, secret.Type, secret.ProjectID, secret.EnvironmentID,
			secret.CreatedBy, secret.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush() // #nosec G104
	return nil
}

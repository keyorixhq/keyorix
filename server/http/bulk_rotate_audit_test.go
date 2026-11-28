package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/require"
)

// TestBulkRotate_EachRotationCommitsItsSecretRotatedRow is the end-to-end proof for
// #4719 (AUDIT-FAILCLOSED-SECRETS-1): REST bulk rotate passed an untagged context, so
// RotateSecret committed every new version with no secret.rotated row, leaving only
// the count-only secret.bulk_rotate_attempted summary. Red on main: zero rows. Now each
// rotated secret has exactly one secret.rotated row, attributed to the caller with the
// request's IP, committed with its version.
func TestBulkRotate_EachRotationCommitsItsSecretRotatedRow(t *testing.T) {
	c, token, srv, projectID, envID := newBulkRotateTestEnv(t)
	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	ids := []uint{
		createBulkTestSecret(t, client, srv.URL, token, "bulk-audit-a", projectID, envID),
		createBulkTestSecret(t, client, srv.URL, token, "bulk-audit-b", projectID, envID),
	}
	for _, id := range ids {
		require.NoError(t, c.SetSecretAutoRotate(ctx, id, core.AutoRotateSpec{Enabled: true}, 0))
	}

	code, out := doBulkRotate(t, client, srv.URL, token, projectID, fmt.Sprintf(`{"secret_ids":[%d,%d]}`, ids[0], ids[1]))
	require.Equal(t, http.StatusOK, code, "%v", out)
	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "%v", out)
	require.Len(t, data["triggered"], 2, "both secrets must rotate: %v", data)

	for _, id := range ids {
		sid := id
		action := "secret.rotated"
		rows, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{SecretID: &sid, Action: &action, Page: 1, PageSize: 10})
		require.NoError(t, err)
		require.Len(t, rows, 1, "secret %d was rotated through REST bulk rotate, so it must have exactly one secret.rotated row", id)
		require.NotNil(t, rows[0].UserID, "the row must name the calling user")
		require.NotEmpty(t, rows[0].IPAddress, "the row must carry the request's IP (the handler tags the context)")
	}
}

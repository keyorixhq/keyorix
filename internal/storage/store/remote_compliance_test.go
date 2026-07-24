package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteComplianceStubs_Unsupported verifies that RemoteStorage's compliance
// posture methods return ErrRemoteUnsupported — they are intentional server-only
// stubs (registered in remote_unsupported_registry_test.go).
func TestRemoteComplianceStubs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("SaveCompliancePostureSnapshot", func(t *testing.T) {
		err := rs.SaveCompliancePostureSnapshot(ctx, &models.CompliancePostureSnapshot{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SaveCompliancePostureSnapshot")
	})

	t.Run("GetPreviousCompliancePostureSnapshot", func(t *testing.T) {
		_, err := rs.GetPreviousCompliancePostureSnapshot(ctx, time.Now())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "GetPreviousCompliancePostureSnapshot")
	})
}

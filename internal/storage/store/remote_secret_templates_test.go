package store_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteSecretTemplateStubs_Unsupported verifies that all six RemoteStorage
// secret-template methods return an error (remoteUnsupported) as documented in
// remote_secret_templates_completeness_test.go.
func TestRemoteSecretTemplateStubs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)
	ctx := context.Background()

	err = rs.CreateSecretTemplate(ctx, nil)
	assert.Error(t, err)

	_, err = rs.GetSecretTemplate(ctx, 1)
	assert.Error(t, err)

	_, err = rs.GetSecretTemplateByName(ctx, "foo")
	assert.Error(t, err)

	_, err = rs.ListSecretTemplates(ctx)
	assert.Error(t, err)

	err = rs.UpdateSecretTemplate(ctx, nil)
	assert.Error(t, err)

	err = rs.DeleteSecretTemplate(ctx, 1)
	assert.Error(t, err)
}

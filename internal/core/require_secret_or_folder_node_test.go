// require_secret_or_folder_node_test.go — ERRLOSS-ACL-1 item 4 (audit finding 7):
// GrantSecretACL's target lookup reports "not found" only for a node that does not
// exist; a GetSecret storage failure is reported as a retrieval failure.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireSecretOrFolderNode_MissingNodeIsNotFound(t *testing.T) {
	t.Parallel()
	c, _ := newACLCore(t)

	err := c.GrantSecretACL(context.Background(), 99, 4242, 42, []string{"secrets.read"})
	require.Error(t, err)
	assert.True(t, storage.IsSecretNotFound(err), "a missing node must be ErrSecretNotFound: %v", err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRequireSecretOrFolderNode_StorageFailureIsNotNotFound(t *testing.T) {
	t.Parallel()
	c, db := newACLCore(t)
	sid := mkACLSecret(t, db, "node-lookup-outage")
	injected := errors.New("driver: bad connection")
	faulty := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: injected,
	})
	c2 := newACLCoreWithStorage(c, faulty)

	err := c2.GrantSecretACL(context.Background(), 99, sid, 42, []string{"secrets.read"})
	require.True(t, faulty.Fired(), "the GetSecret fault must have fired, or this case proves nothing")
	require.Error(t, err)
	assert.ErrorIs(t, err, injected, "the storage failure must propagate")
	assert.False(t, storage.IsSecretNotFound(err))
	assert.NotContains(t, err.Error(), "not found", "a storage failure must not be reported as a missing node")
	assert.Contains(t, err.Error(), i18n.T("ErrorRetrievalFailed", nil))
}

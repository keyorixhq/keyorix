// connect_ownership_untyped_notfound_test.go — ERRSTRING-CLASS-1 item 3: boot-time
// connector ownership resolution treats ONLY the typed "binding does not exist"
// (corestorage.ErrConnectorBindingNotFound) as a first boot. A storage fault whose
// text merely says "not found" must fail the boot for that connector, not mint a
// binding: a first-boot resolution re-pins the connector to a project by NAME, the
// silent reassignment ADR-082 exists to prevent.
package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestResolveConnectorOwnership_UntypedNotFoundTextIsNotFirstBoot(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	ctx := context.Background()
	_, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)

	fs := faultstorage.NewFaultyStorage(st, nil)
	fs.Arm(&faultstorage.FaultSpec{
		Method: "GetConnectorProjectBinding", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("replica lag: connector binding not found in cache"),
	})

	ownership, err := resolveConnectorOwnership(ctx, fs, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "payments"},
	})
	require.True(t, fs.Fired(), "the armed fault must have fired")
	require.Error(t, err, "a storage fault must fail the connector's resolution")
	assert.NotContains(t, ownership, "aws")

	var n int64
	require.NoError(t, db.Model(&models.ConnectorProjectBinding{}).Where("connector = ?", "aws").Count(&n).Error)
	assert.Zero(t, n, "no binding may be minted on the strength of a text match")
}

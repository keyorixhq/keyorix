package core

// #3620 (SCIM-GROUPS-ERR-1): core.GetGroup passes the storage error through with its
// chain intact. The SCIM handlers classify by errors.Is, so a storage failure must stay
// itself (not be flattened into a message, and never become storage.ErrGroupNotFound),
// and a real missing row must keep the typed sentinel.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestGetGroup_StorageErrorKeepsItsChain(t *testing.T) {
	t.Parallel()
	outage := errors.New("db timeout") // NOT storage.ErrGroupNotFound
	ms := new(MockStorage)
	ms.On("GetGroup", mock.Anything, uint(7)).Return(nil, outage)
	c := NewKeyorixCore(ms)

	_, err := c.GetGroup(context.Background(), 7)
	require.Error(t, err)
	assert.ErrorIs(t, err, outage, "the storage error must stay in the chain")
	assert.NotErrorIs(t, err, storage.ErrGroupNotFound, "an outage is not a missing group")
}

func TestGetGroup_MissingRowKeepsTheSentinel(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetGroup", mock.Anything, uint(7)).Return(nil, fmt.Errorf("group not found: %w", storage.ErrGroupNotFound))
	c := NewKeyorixCore(ms)

	_, err := c.GetGroup(context.Background(), 7)
	require.ErrorIs(t, err, storage.ErrGroupNotFound)
}

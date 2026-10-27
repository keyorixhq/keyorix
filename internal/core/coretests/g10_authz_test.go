// g10_authz_test.go — #G10 regression tests: several core-layer functions used to
// perform zero authorization of their own, trusting that the HTTP router (or some other
// caller) had already checked the actor. Per the group's own detection_idea: call each
// function directly (bypassing the HTTP router) with an unauthorized actor, and assert
// every one now refuses.
package coretests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const g10UnauthorizedActor = uint(999)

// errNotFoundForTest is the "no ACL row" answer GetSecretACL gives for a missing row.
var errNotFoundForTest = storage.ErrSecretACLNotFound

func TestListGroupShares_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{})

	_, err := c.ListGroupShares(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "ListSharesByGroup", mock.Anything, mock.Anything)
}

func TestListGroupSharedSecrets_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{})

	_, err := c.ListGroupSharedSecrets(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "ListSharesByGroup", mock.Anything, mock.Anything)
}

func TestGetSecretReadSummary_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5}, nil)
	ms.On("GetSecretACL", mock.Anything, uint(5), g10UnauthorizedActor).Return(nil, errNotFoundForTest).Maybe()
	ms.On("GetSecretAncestors", mock.Anything, uint(5)).Return([]uint{}, nil).Maybe()
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{})

	_, err := c.GetSecretReadSummary(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, core.SecretReadSummaryRequest{SecretID: 5})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission")
	ms.AssertNotCalled(t, "GetSecretReadCounts", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestExportSecretAccessLog_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5}, nil)
	ms.On("GetSecretACL", mock.Anything, uint(5), g10UnauthorizedActor).Return(nil, errNotFoundForTest).Maybe()
	ms.On("GetSecretAncestors", mock.Anything, uint(5)).Return([]uint{}, nil).Maybe()
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{})

	_, _, err := c.ExportSecretAccessLog(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, 5, core.ExportFormatJSON)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "GetAuditLogs", mock.Anything, mock.Anything)
}

func TestReassignOwnedSecrets_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{ProjectID: 3})

	_, err := c.ReassignOwnedSecrets(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, 3, 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
	ms.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
}

func TestGetSecretSharingStatus_RefusesUnauthorizedActor(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	c := core.NewKeyorixCore(ms)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5}, nil)
	ms.On("GetSecretACL", mock.Anything, uint(5), g10UnauthorizedActor).Return(nil, errNotFoundForTest).Maybe()
	ms.On("GetSecretAncestors", mock.Anything, uint(5)).Return([]uint{}, nil).Maybe()
	// The secret IS shared — with someone else (user 4242). Since #2941 the
	// authorization itself reads the share rows (the share term, which finds nothing
	// for this actor), so "ListSharesBySecret was not called" no longer
	// distinguishes "refused before the status read" from "leaked it". The status
	// read resolves each user recipient's name with GetUser; the authorization never
	// does, so GetUser not being called is the leak detector.
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return([]*models.ShareRecord{
		{ID: 1, SecretID: 5, RecipientID: 4242, Permission: "read"},
	}, nil)
	storagetest.StubUnauthorizedPrincipal(ms, g10UnauthorizedActor, core.Scope{})

	_, err := c.GetSecretSharingStatus(context.Background(), core.ActorTypeUser, g10UnauthorizedActor, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission")
	ms.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
}

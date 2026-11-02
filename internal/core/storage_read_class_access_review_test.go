package core

// storage_read_class_access_review_test.go — ERR-FOLD-HANDLERS-1 item 2.
//
// The access-review decide/revoke/attest paths wrapped a storage read FAULT as
// "<ErrorNotFound>: ..." / "group not found: ..." and the handler matched the word
// "not found" in the text. A fault is now ErrStorageReadUnavailable; every true
// not-found matches ErrAccessReviewNotFound (sentinel, not text).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sweepCoreFault arms an error on the 1st, 2nd, ... call of method and runs call once per
// arming until the call count is exhausted. Every fired fault must come back as a retry
// answer, never as ErrAccessReviewNotFound or text saying "not found"; the number of
// fired faults is returned so the caller can require the site was reached.
func sweepCoreFault(t *testing.T, faulty *faultstorage.FaultyStorage, method string, call func() error) (fired int) {
	t.Helper()
	defer faulty.Arm(nil)
	for nth := 1; nth <= 12; nth++ {
		faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindError, Err: assert.AnError})
		err := call()
		if !faulty.Fired() {
			return fired
		}
		fired++
		require.Error(t, err, "%s fault #%d", method, nth)
		assert.NotErrorIs(t, err, ErrAccessReviewNotFound, "%s fault #%d read as a missing target: %v", method, nth, err)
		assert.NotContains(t, err.Error(), "not found", "%s fault #%d", method, nth)
	}
	return fired
}

func TestStorageReadClass_AccessReviewDecide(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
			other := w.project()
			reviewer := w.user()
			member := w.user()
			grp := w.group()
			role := w.role(false)
			secret, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
				Name: w.name("sec"), ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
				IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)
			require.NoError(t, w.core.storage.AssignRole(ctx, reviewer.ID, w.role(true).ID, Scope{ProjectID: p.ID}))
			camp := &models.AccessReviewCampaign{ProjectID: p.ID, Name: "q", State: CampaignStateOpen, CreatedBy: reviewer.ID}
			require.NoError(t, w.db.Create(camp).Error)

			newItem := func(it models.AccessReviewItem) *models.AccessReviewItem {
				it.CampaignID = camp.ID
				it.Decision = ReviewItemPending
				require.NoError(t, w.db.Create(&it).Error)
				return &it
			}
			pending := func(id uint) bool {
				var row models.AccessReviewItem
				require.NoError(t, w.db.First(&row, id).Error)
				return row.Decision == ReviewItemPending
			}

			t.Run("campaign and item lookup", func(t *testing.T) {
				it := newItem(models.AccessReviewItem{PrincipalType: "user", PrincipalID: member.ID, Source: "role", RoleID: role.ID})
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "GetAccessReviewCampaign", func() error {
					_, err := c.GetAccessReviewCampaign(ctx, p.ID, camp.ID)
					return err
				}), 1)
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "GetAccessReviewItem", func() error {
					return c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, it.ID, "attest", "x")
				}), 1)
				assert.True(t, pending(it.ID), "nothing was applied")

				_, errGone := c.GetAccessReviewCampaign(ctx, p.ID, 9_999_999)
				_, errCross := c.GetAccessReviewCampaign(ctx, other.ID, camp.ID)
				assert.ErrorIs(t, errGone, ErrAccessReviewNotFound)
				assert.ErrorIs(t, errCross, ErrAccessReviewNotFound)
				assert.False(t, IsStorageReadUnavailable(errGone))
				errItem := c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, 9_999_999, "attest", "x")
				assert.ErrorIs(t, errItem, ErrAccessReviewNotFound)
			})

			t.Run("revoke group role", func(t *testing.T) {
				it := newItem(models.AccessReviewItem{PrincipalType: "group", PrincipalID: grp.ID, Source: "role", RoleID: role.ID})
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "GetGroup", func() error {
					return c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, it.ID, "revoke", "x")
				}), 1)
				assert.True(t, pending(it.ID), "the revoke was never applied")

				gone := newItem(models.AccessReviewItem{PrincipalType: "group", PrincipalID: 9_999_999, Source: "role", RoleID: role.ID})
				err := c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, gone.ID, "revoke", "x")
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAccessReviewNotFound)
				assert.Contains(t, err.Error(), "group not found")
				assert.False(t, IsStorageReadUnavailable(err))
			})

			t.Run("revoke share", func(t *testing.T) {
				it := newItem(models.AccessReviewItem{PrincipalType: "user", PrincipalID: member.ID, Source: "direct_share", SecretID: secret.ID})
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "GetSecret", func() error {
					return c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, it.ID, "revoke", "x")
				}), 1)
				assert.True(t, pending(it.ID), "the revoke was never applied")

				// The write runs inside a transaction the double cannot fault, so the
				// transaction body is driven directly with the faulty storage as its handle.
				d := AccessReviewDecision{Source: "direct_share", PrincipalType: "user", PrincipalID: member.ID, SecretID: secret.ID}
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "GetSecret", func() error {
					return c.revokeReviewShareOn(ctx, faulty, p.ID, d)
				}), 1)
				assert.GreaterOrEqual(t, sweepCoreFault(t, faulty, "ListSharesBySecret", func() error {
					return c.revokeReviewShareOn(ctx, faulty, p.ID, d)
				}), 1)
				errNoShare := c.revokeReviewShareOn(ctx, faulty, p.ID, d)
				assert.ErrorIs(t, errNoShare, ErrAccessReviewNotFound, "no matching share")
				errGone := c.revokeReviewShareOn(ctx, faulty, p.ID, AccessReviewDecision{Source: "direct_share", PrincipalID: member.ID, SecretID: 9_999_999})
				assert.ErrorIs(t, errGone, ErrAccessReviewNotFound)
				assert.False(t, IsStorageReadUnavailable(errGone))

				gone := newItem(models.AccessReviewItem{PrincipalType: "user", PrincipalID: member.ID, Source: "direct_share", SecretID: 9_999_999})
				err := c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, gone.ID, "revoke", "x")
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrAccessReviewNotFound)
				assert.False(t, IsStorageReadUnavailable(err))
			})
		})
	}
}

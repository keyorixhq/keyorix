package core

// storage_read_class_access_review_reads_test.go — STORAGE-ERR-CLASS-5 item 2.
//
// ERR-FOLD-HANDLERS-1 typed the access-review not-found and classified the target reads
// (campaign, item, group, secret, machine). The reads that are not a verdict on a named
// target were left: the campaign and item listings, the role-assignment scans behind an
// attestation and the report, the share scan behind a revoke or attestation. A fault on
// them answered 500 with a raw "retrieval failed" text, and a fault on the group-membership
// lookup behind the reviewer-independence check read as "you belong to that group" (a 400
// policy refusal). Every fault is now ErrStorageReadUnavailable (503), still fail closed;
// a true not-found stays ErrAccessReviewNotFound (404).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sweepUnavailable arms an error on the 1st, 2nd, ... call of method and runs call once per
// arming. Every fired fault must come back as the storage-unavailable class (503), never a
// plain error, a not-found or a policy refusal. It returns how many faults fired, so the
// caller can require the site was reached.
func sweepUnavailable(t *testing.T, faulty *faultstorage.FaultyStorage, method string, call func() error) (fired int) {
	t.Helper()
	defer faulty.Arm(nil)
	for nth := 1; nth <= 12; nth++ {
		faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindError, Err: assert.AnError})
		err := call()
		if !faulty.Fired() {
			return fired
		}
		fired++
		require.Error(t, err, "%s fault #%d must refuse", method, nth)
		assert.ErrorIs(t, err, ErrStorageReadUnavailable, "%s fault #%d must be the storage-unavailable class: %v", method, nth, err)
		assert.NotErrorIs(t, err, ErrAccessReviewNotFound, "%s fault #%d read as a missing target: %v", method, nth, err)
	}
	return fired
}

func TestStorageReadClass_AccessReviewReads(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
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
			require.NoError(t, w.core.storage.AssignRole(ctx, member.ID, role.ID, Scope{ProjectID: p.ID}))
			camp := &models.AccessReviewCampaign{ProjectID: p.ID, Name: "q", State: CampaignStateOpen, CreatedBy: reviewer.ID}
			require.NoError(t, w.db.Create(camp).Error)
			newItem := func(it models.AccessReviewItem) *models.AccessReviewItem {
				it.CampaignID = camp.ID
				it.Decision = ReviewItemPending
				require.NoError(t, w.db.Create(&it).Error)
				return &it
			}
			groupItem := newItem(models.AccessReviewItem{PrincipalType: "group", PrincipalID: grp.ID, Source: "role", RoleID: role.ID})

			t.Run("campaign and item listings", func(t *testing.T) {
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListAccessReviewCampaigns", func() error {
					_, err := c.ListAccessReviewCampaigns(ctx, p.ID)
					return err
				}), 1)
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListAccessReviewItems", func() error {
					_, err := c.ListAccessReviewCampaigns(ctx, p.ID)
					return err
				}), 1)
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListAccessReviewItems", func() error {
					_, err := c.GetAccessReviewCampaign(ctx, p.ID, camp.ID)
					return err
				}), 1)
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListAccessReviewItems", func() error {
					_, err := c.CloseAccessReviewCampaign(ctx, reviewer.ID, 0, p.ID, camp.ID, false)
					return err
				}), 1)
			})

			t.Run("project report", func(t *testing.T) {
				for _, method := range []string{"ListProjectRoleAssignments", "ListProjectMachineRoleAssignments", "ListSecrets"} {
					assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, method, func() error {
						_, err := c.GenerateProjectAccessReview(ctx, p.ID)
						return err
					}), 1, method)
				}
			})

			t.Run("attestation scans", func(t *testing.T) {
				role := AccessReviewDecision{Source: "role", PrincipalType: "user", PrincipalID: member.ID, RoleID: role.ID}
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListProjectRoleAssignments", func() error {
					return c.AttestAccessReviewGrant(ctx, reviewer.ID, p.ID, role)
				}), 1)
				machine := AccessReviewDecision{Source: "role", PrincipalType: "machine", PrincipalID: 9_999_999, RoleID: role.RoleID}
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListProjectMachineRoleAssignments", func() error {
					return c.AttestAccessReviewGrant(ctx, reviewer.ID, p.ID, machine)
				}), 1)
				share := AccessReviewDecision{Source: "direct_share", PrincipalType: "user", PrincipalID: member.ID, SecretID: secret.ID}
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListSharesBySecret", func() error {
					return c.AttestAccessReviewGrant(ctx, reviewer.ID, p.ID, share)
				}), 1)
				// A true not-found stays a 404: the share was never made.
				errNoShare := c.AttestAccessReviewGrant(ctx, reviewer.ID, p.ID, share)
				assert.ErrorIs(t, errNoShare, ErrAccessReviewNotFound)
				assert.False(t, IsStorageReadUnavailable(errNoShare))
			})

			t.Run("revoke share scan", func(t *testing.T) {
				d := AccessReviewDecision{Source: "direct_share", PrincipalType: "user", PrincipalID: member.ID, SecretID: secret.ID}
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "ListSharesBySecret", func() error {
					return c.revokeReviewShareOn(ctx, faulty, p.ID, d)
				}), 1)
				assert.ErrorIs(t, c.revokeReviewShareOn(ctx, faulty, p.ID, d), ErrAccessReviewNotFound)
			})

			t.Run("reviewer independence group lookup", func(t *testing.T) {
				// A GetUserGroups fault used to read as "you belong to that group": a 400
				// policy refusal. It is still a refusal (the independence cannot be proven),
				// but of the storage-unavailable class.
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "GetUserGroups", func() error {
					return c.DecideAccessReviewItem(ctx, reviewer.ID, p.ID, camp.ID, groupItem.ID, "attest", "x")
				}), 1)
				assert.GreaterOrEqual(t, sweepUnavailable(t, faulty, "GetUserGroups", func() error {
					_, err := c.CloseAccessReviewCampaign(ctx, reviewer.ID, 0, p.ID, camp.ID, true)
					return err
				}), 1)
			})
		})
	}
}

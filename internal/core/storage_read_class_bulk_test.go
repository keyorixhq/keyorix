package core

// storage_read_class_bulk_test.go — STORAGE-ERR-CLASS-1 item 4.
//
// Access-review attestation reported a secret-read fault as "the review is stale,
// re-sync and try again"; bulk delete and bulk rename reported it as the per-item
// "secret not found". A fault is now a distinct "storage temporarily unavailable,
// please retry"; a real not-found and a cross-project secret keep today's text.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStorageReadClass_AccessReviewAndBulk(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			otherProject := w.project()
			env := w.env(p.ID)
			otherEnv := w.env(otherProject.ID)
			actor := w.user()
			require.NoError(t, w.core.storage.AssignRole(ctx, actor.ID, w.role(true).ID, Scope{ProjectID: p.ID}))

			mkSecret := func(projectID, envID uint) *models.SecretNode {
				s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
					Name: w.name("sec"), ProjectID: projectID, EnvironmentID: envID, Type: "password",
					OwnerID: actor.ID, IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
				})
				require.NoError(t, err)
				return s
			}
			exists := func(id uint) bool {
				var n int64
				require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", id).Count(&n).Error)
				return n == 1
			}

			t.Run("access review attestation: owner and share sources", func(t *testing.T) {
				s := mkSecret(p.ID, env.ID)
				for _, d := range []AccessReviewDecision{
					{Source: "owner", PrincipalID: actor.ID, SecretID: s.ID},
					{Source: "direct_share", PrincipalID: actor.ID, SecretID: s.ID},
				} {
					srcFault(faulty, "GetSecret")
					err := c.verifyAccessReviewGrantExists(ctx, p.ID, d)
					require.True(t, faulty.Fired(), d.Source)
					requireReadFault(t, err)
					assert.NotContains(t, err.Error(), "stale", "a fault is not a stale review (%s)", d.Source)
					faulty.Arm(nil)
				}
				// The same attestation without the fault still works (owner source).
				require.NoError(t, c.verifyAccessReviewGrantExists(ctx, p.ID, AccessReviewDecision{Source: "owner", PrincipalID: actor.ID, SecretID: s.ID}))

				// Absent and cross-project secrets keep the stale-review text, identical.
				foreign := mkSecret(otherProject.ID, otherEnv.ID)
				for _, src := range []string{"owner", "direct_share"} {
					errGone := c.verifyAccessReviewGrantExists(ctx, p.ID, AccessReviewDecision{Source: src, PrincipalID: actor.ID, SecretID: 9_999_999})
					errCross := c.verifyAccessReviewGrantExists(ctx, p.ID, AccessReviewDecision{Source: src, PrincipalID: actor.ID, SecretID: foreign.ID})
					require.Error(t, errGone, src)
					require.Error(t, errCross, src)
					assert.Equal(t, errGone.Error(), errCross.Error(), src)
					assert.Contains(t, errGone.Error(), "the review is stale, re-sync and try again")
					assert.False(t, IsStorageReadUnavailable(errGone))
				}
			})

			t.Run("bulk delete", func(t *testing.T) {
				s := mkSecret(p.ID, env.ID)
				foreign := mkSecret(otherProject.ID, otherEnv.ID)
				srcFault(faulty, "GetSecret")
				res, err := c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{s.ID}}, p.ID, "tester", actor.ID, "", "")
				require.NoError(t, err)
				require.True(t, faulty.Fired())
				require.Len(t, res.Failed, 1)
				assert.Equal(t, StorageReadUnavailableMessage, res.Failed[0].Error)
				assert.NotContains(t, res.Failed[0].Error, "not found")
				assert.Empty(t, res.Deleted)
				assert.True(t, exists(s.ID), "the secret was not deleted")

				faulty.Arm(nil)
				res, err = c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{s.ID}}, p.ID, "tester", actor.ID, "", "")
				require.NoError(t, err)
				assert.Equal(t, []uint{s.ID}, res.Deleted, "the retried delete succeeds")

				res, err = c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{9_999_999, foreign.ID}}, p.ID, "tester", actor.ID, "", "")
				require.NoError(t, err)
				require.Len(t, res.Failed, 2)
				assert.Equal(t, "secret not found", res.Failed[0].Error)
				assert.Equal(t, "secret not found", res.Failed[1].Error, "cross-project reads exactly like absent")
				assert.True(t, exists(foreign.ID))
			})

			t.Run("bulk rename", func(t *testing.T) {
				s := mkSecret(p.ID, env.ID)
				foreign := mkSecret(otherProject.ID, otherEnv.ID)
				newName := w.name("renamed")
				srcFault(faulty, "GetSecret")
				rep, err := c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: s.ID, NewName: newName}}, false, "tester", actor.ID, "", "")
				require.NoError(t, err)
				require.True(t, faulty.Fired())
				require.Len(t, rep.Outcomes, 1)
				assert.Equal(t, renameStatusSkipped, rep.Outcomes[0].Status)
				assert.Equal(t, StorageReadUnavailableMessage, rep.Outcomes[0].Reason)
				var row models.SecretNode
				require.NoError(t, w.db.First(&row, s.ID).Error)
				assert.NotEqual(t, newName, row.Name, "the rename was never applied")

				faulty.Arm(nil)
				rep, err = c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: s.ID, NewName: newName}}, false, "tester", actor.ID, "", "")
				require.NoError(t, err)
				assert.Equal(t, 1, rep.Renamed, "the retried rename succeeds")

				rep, err = c.BulkRenameSecrets(ctx, p.ID, []SecretRename{{ID: 9_999_999, NewName: w.name("x")}, {ID: foreign.ID, NewName: w.name("y")}}, false, "tester", actor.ID, "", "")
				require.NoError(t, err)
				require.Len(t, rep.Outcomes, 2)
				assert.Equal(t, "secret not found", rep.Outcomes[0].Reason)
				assert.Equal(t, "secret not found", rep.Outcomes[1].Reason, "cross-project reads exactly like absent")
			})
		})
	}
}

package core

// storage_read_class_fold_handlers_test.go — ERR-FOLD-HANDLERS-1 item 1.
//
// Core sites that folded a storage read FAULT into a not-found / idle / denial
// answer: ResolveSecretRef, GetSecretAccessRequest, AcknowledgeAnomalyAlert, the
// rotation-state text matches, ClassifySecretReadDenial and the uniform-denial
// probe SecretReadVerdictFault. A fault must be ErrStorageReadUnavailable (or an
// error that is not the not-found / idle answer); a true not-found stays what it was.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestFoldHandlers_ResolveSecretRef(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
			s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
				Name: "ref-secret", ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
				IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)
			ref := p.Name + "/" + env.Name + "/" + s.Name

			for _, method := range []string{"ListProjects", "ListEnvironmentsByProject", "GetSecretByName"} {
				faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err := c.ResolveSecretRef(ctx, ref)
				require.True(t, faulty.Fired(), "%s must be reached", method)
				require.Error(t, err, method)
				assert.True(t, IsStorageReadUnavailable(err), "%s fault must be a retry answer, got %v", method, err)
				assert.NotErrorIs(t, err, ErrSecretRefNotFound, method)
			}
			faulty.Arm(nil)

			got, err := c.ResolveSecretRef(ctx, ref)
			require.NoError(t, err)
			assert.Equal(t, s.ID, got.ID)
			_, err = c.ResolveSecretRef(ctx, p.Name+"/"+env.Name+"/absent")
			assert.ErrorIs(t, err, ErrSecretRefNotFound)
			_, err = c.ResolveSecretRef(ctx, "no-such-project/"+env.Name+"/x")
			assert.ErrorIs(t, err, ErrSecretRefNotFound)
		})
	}
}

func TestFoldHandlers_GetSecretAccessRequest(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
			requester := w.user()
			admin := w.user()
			require.NoError(t, w.core.storage.AssignRole(ctx, admin.ID, w.role(true).ID, Scope{ProjectID: p.ID}))
			s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
				Name: w.name("sec"), ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
				IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)
			sid := s.ID
			req := &models.AccessRequest{ProjectID: p.ID, UserID: requester.ID, SecretID: &sid, State: AccessRequestPending, CreatedAt: time.Now()}
			require.NoError(t, w.db.Create(req).Error)

			faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			_, err = c.GetSecretAccessRequest(ctx, req.ID, requester.ID)
			require.True(t, faulty.Fired())
			requireReadFault(t, err)

			// A fault resolving the admin's authority is not a refusal either.
			faulty.Arm(&faultstorage.FaultSpec{Method: "ListUserRoles", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			_, err = c.GetSecretAccessRequest(ctx, req.ID, admin.ID)
			if faulty.Fired() {
				require.Error(t, err)
				assert.True(t, IsStorageReadUnavailable(err), "got %v", err)
			}
			faulty.Arm(nil)

			got, err := c.GetSecretAccessRequest(ctx, req.ID, requester.ID)
			require.NoError(t, err)
			assert.Equal(t, req.ID, got.ID)
			got, err = c.GetSecretAccessRequest(ctx, req.ID, admin.ID)
			require.NoError(t, err)
			assert.Equal(t, req.ID, got.ID)

			// True not-found, and a stranger, are one identical answer.
			_, errGone := c.GetSecretAccessRequest(ctx, 9_999_999, requester.ID)
			_, errStranger := c.GetSecretAccessRequest(ctx, req.ID, w.user().ID)
			require.Error(t, errGone)
			require.Error(t, errStranger)
			assert.Equal(t, errGone.Error(), errStranger.Error())
			assert.False(t, IsStorageReadUnavailable(errGone))
			assert.False(t, IsStorageReadUnavailable(errStranger))
		})
	}
}

func TestFoldHandlers_AcknowledgeAnomalyAlert(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			actor := w.user()
			alert := &models.AnomalyAlert{AlertType: "off_hours", Severity: "low", DetectedAt: time.Now()}
			require.NoError(t, w.core.storage.CreateAnomalyAlert(ctx, alert))

			faulty.Arm(&faultstorage.FaultSpec{Method: "ListAnomalyAlerts", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			err := c.AcknowledgeAnomalyAlert(ctx, actor.ID, alert.ID)
			require.True(t, faulty.Fired())
			requireReadFault(t, err)
			assert.NotErrorIs(t, err, ErrAnomalyAlertNotFound)
			var row models.AnomalyAlert
			require.NoError(t, w.db.First(&row, alert.ID).Error)
			assert.False(t, row.Acknowledged, "nothing was applied")

			// A write fault is not "no such alert" either.
			faulty.Arm(&faultstorage.FaultSpec{Method: "AcknowledgeAnomalyAlert", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("alert not found: driver text")})
			err = c.AcknowledgeAnomalyAlert(ctx, actor.ID, alert.ID)
			require.True(t, faulty.Fired())
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrAnomalyAlertNotFound)

			faulty.Arm(nil)
			require.NoError(t, c.AcknowledgeAnomalyAlert(ctx, actor.ID, alert.ID))
			require.NoError(t, w.db.First(&row, alert.ID).Error)
			assert.True(t, row.Acknowledged)

			err = c.AcknowledgeAnomalyAlert(ctx, actor.ID, 9_999_999)
			assert.ErrorIs(t, err, ErrAnomalyAlertNotFound)
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}
}

func TestFoldHandlers_RotationStateTextMatch(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
			s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
				Name: w.name("sec"), ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
				IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)

			// A fault whose driver text says "not found" must NOT read as "no policy: idle".
			faulty.Arm(&faultstorage.FaultSpec{Method: "GetRotationPolicyBySecret", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("relation rotation_policies not found")})
			info, err := c.GetRotationState(ctx, s.ID)
			require.True(t, faulty.Fired())
			require.Error(t, err, "a read fault is not the idle answer")
			assert.Nil(t, info)

			faulty.Arm(&faultstorage.FaultSpec{Method: "UpdateRotationState", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("lock not found")})
			err = c.SetRotationState(ctx, 1, RotationStateRunningOrFirst(), "")
			require.True(t, faulty.Fired())
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "rotation policy 1 not found", "a write fault is not a missing policy")
			faulty.Arm(nil)

			// A true "no covering policy" stays idle; a missing policy row stays "not found".
			info, err = c.GetRotationState(ctx, s.ID)
			require.NoError(t, err)
			assert.Equal(t, RotationStateIdle, info.State)
			err = c.SetRotationState(ctx, 9_999_999, RotationStateRotating, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rotation policy 9999999 not found")
		})
	}
}

// RotationStateRunningOrFirst keeps the call above readable: any valid state.
func RotationStateRunningOrFirst() string { return RotationStateRotating }

func TestFoldHandlers_SecretReadVerdictFault(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			env := w.env(p.ID)
			owner := w.user()
			stranger := w.user()
			s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
				Name: w.name("sec"), ProjectID: p.ID, EnvironmentID: env.ID, Type: "password",
				OwnerID: owner.ID, IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			require.NoError(t, err)

			// Verdicts: not found and "not allowed" are not faults.
			_, err = c.GetSecretWithPermissionCheck(ctx, 9_999_999, stranger.ID)
			require.Error(t, err)
			assert.NoError(t, SecretReadVerdictFault(err), "not found is a verdict: %v", err)
			_, err = c.GetSecretWithPermissionCheck(ctx, s.ID, stranger.ID)
			require.Error(t, err)
			assert.NoError(t, SecretReadVerdictFault(err), "a refusal is a verdict: %v", err)

			// A failed secondary read (shares, schedule) is a fault, not a verdict.
			require.NoError(t, w.core.storage.AssignRole(ctx, owner.ID, w.role(true).ID, Scope{ProjectID: p.ID}))
			for method, actor := range map[string]uint{"ListSharesBySecret": stranger.ID, "GetSecretAccessSchedule": owner.ID} {
				faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err = c.GetSecretWithPermissionCheck(ctx, s.ID, actor)
				require.True(t, faulty.Fired(), "%s must be reached", method)
				require.Error(t, err, method)
				fault := SecretReadVerdictFault(err)
				require.Error(t, fault, "%s fault must not read as a verdict: %v", method, err)
				assert.True(t, IsStorageReadUnavailable(fault), method)
				assert.ErrorIs(t, fault, assert.AnError, method)
			}
			faulty.Arm(nil)

			assert.NoError(t, SecretReadVerdictFault(nil))
			assert.NoError(t, SecretReadVerdictFault(fmt.Errorf("x: %w", ErrPermissionDenied)))
			assert.NoError(t, SecretReadVerdictFault(ErrAccessOutsideSchedule))

			// A principal with no user id (a machine) is refused by validation: a verdict.
			_, err = c.GetSecretWithPermissionCheck(ctx, s.ID, 0)
			require.Error(t, err)
			assert.NoError(t, SecretReadVerdictFault(err), "validation refusal is a verdict: %v", err)
		})
	}
}

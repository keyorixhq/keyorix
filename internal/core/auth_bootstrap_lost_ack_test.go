package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #3225, PARTIAL-COMMIT-TAILS-NOV-3 item 1: the bootstrap transaction COMMITS (admin,
// catalog, default project, initialised marker) and then reports an error, a lost
// acknowledgement. bootstrapSystemLocked used to answer failure, skip the
// post-commit user.created / project.created rows and the password-history seed,
// and keep the single-use bootstrap token in memory. It now reads the create back
// (userCreateLanded) and finishes the success path.

func lostAckBootstrapCore(t *testing.T, kind faultstorage.FaultKind) (*KeyorixCore, *faultstorage.FaultyStorage, *store.LocalStorage) {
	t.Helper()
	_, st := newBootstrappedCoreNoAdmin(t)
	fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "WithTransaction", NthCall: 1, Kind: kind, Err: errors.New("commit acknowledgement lost"),
	})
	c := NewKeyorixCore(fs)
	c.SetBootstrapToken(retryToken)
	return c, fs, st
}

func bootstrapEventCount(t *testing.T, st storage.Storage, event string) int {
	t.Helper()
	evs, _, err := st.GetAuditLogs(context.Background(), &storage.AuditFilter{Actions: []string{event}})
	require.NoError(t, err)
	return len(evs)
}

func TestBootstrapSystem_LostAckAnswersSuccessAndFinishes(t *testing.T) {
	ctx := context.Background()
	c, fs, st := lostAckBootstrapCore(t, faultstorage.KindEffectThenError)
	require.Positive(t, c.passwordPolicy.HistoryCount, "premise: the default policy keeps password history")

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.True(t, fs.Fired(), "premise: the bootstrap transaction was faulted")
	require.NoError(t, err, "a committed bootstrap must be answered as a success")
	require.NotNil(t, res.User)
	require.NotNil(t, res.Project)
	require.Len(t, res.Environments, len(defaultEnvironmentNames))
	assert.False(t, res.AlreadyInitialized)

	got, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, res.User.ID, got.ID, "the answered admin is the committed one")
	assert.Equal(t, 1, bootstrapEventCount(t, st, EventUserCreated), "user.created is written after the lost ack")
	assert.Equal(t, 1, bootstrapEventCount(t, st, EventProjectCreated), "project.created is written after the lost ack")
	hashes, err := st.RecentPasswordHashes(ctx, got.ID, 5)
	require.NoError(t, err)
	assert.Len(t, hashes, 1, "the initial password seeds the history")
	assert.Empty(t, c.bootstrapToken, "the single-use bootstrap token is cleared")

	// A second claim with the same token is refused: the marker committed and the
	// token is gone. No second admin.
	again, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "intruder", Email: "intruder@example.com", Password: "Kx7!Bootstrap-Pwd2", Token: retryToken,
	})
	require.NoError(t, err)
	assert.True(t, again.AlreadyInitialized)
	_, err = st.GetUserByUsername(ctx, "intruder")
	require.Error(t, err, "a second bootstrap must not create an admin")
}

// A real rollback stays an error and leaves nothing: no admin, no audit row, the
// token still armed so the operator can retry.
func TestBootstrapSystem_RolledBackStaysAnError(t *testing.T) {
	ctx := context.Background()
	c, fs, st := lostAckBootstrapCore(t, faultstorage.KindError)

	_, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.True(t, fs.Fired(), "premise: the bootstrap transaction was faulted")
	require.Error(t, err)
	_, err = st.GetUserByUsername(ctx, "admin")
	require.Error(t, err, "a rolled-back bootstrap leaves no admin")
	assert.Zero(t, bootstrapEventCount(t, st, EventUserCreated))
	assert.Equal(t, retryToken, c.bootstrapToken, "a rolled-back bootstrap stays retryable")

	res, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.NoError(t, err, "the retry bootstraps")
	assert.False(t, res.AlreadyInitialized)
}

// The read-back itself fails after a lost ack: the outcome is unknown, so the error
// stands (fail closed). The admin may exist; whether it does or not, a second
// claim must never produce a second admin: the committed marker refuses it.
func TestBootstrapSystem_LostAckUnreadableOutcomeRefusesSecondClaim(t *testing.T) {
	ctx := context.Background()
	_, st := newBootstrappedCoreNoAdmin(t)
	fs := &lostAckThenReadFailStorage{FaultyStorage: faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "WithTransaction", NthCall: 1, Kind: faultstorage.KindEffectThenError, Err: errors.New("commit acknowledgement lost"),
	})}
	c := NewKeyorixCore(fs)
	c.SetBootstrapToken(retryToken)

	_, err := c.BootstrapSystem(ctx, goodRetryReq())
	require.True(t, fs.Fired() && fs.readFailed, "premise: the commit was faulted and the read-back failed")
	require.ErrorIs(t, err, ErrUserCreateOutcomeUnknown)

	again, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "intruder", Email: "intruder@example.com", Password: "Kx7!Bootstrap-Pwd2", Token: retryToken,
	})
	require.NoError(t, err)
	assert.True(t, again.AlreadyInitialized, "the committed marker refuses a second claim")
	_, err = st.GetUserByUsername(ctx, "intruder")
	require.Error(t, err, "a second bootstrap must not create an admin")
}

// Attacker's view of the window between the two writes: the commit landed (lost
// ack) and the token is not cleared yet. A second claim with the same token that
// arrives while the first is reading its admin back must be refused, and the
// first must still finish as the one bootstrap. The second claim waits for the
// bootstrap lock the first still holds, then meets the committed marker.
func TestBootstrapSystem_LostAckSecondClaimDuringReadBackIsRefused(t *testing.T) {
	ctx := context.Background()
	_, st := newBootstrappedCoreNoAdmin(t)
	paused, resume := make(chan struct{}), make(chan struct{})
	fs := &lostAckThenReadFailStorage{
		FaultyStorage: faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
			Method: "WithTransaction", NthCall: 1, Kind: faultstorage.KindEffectThenError, Err: errors.New("commit acknowledgement lost"),
		}),
		onReadBack: func() { close(paused); <-resume },
	}
	c := NewKeyorixCore(fs)
	c.SetBootstrapToken(retryToken)

	type outcome struct {
		res *BootstrapResult
		err error
	}
	first, second := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		res, err := c.BootstrapSystem(ctx, goodRetryReq())
		first <- outcome{res, err}
	}()
	select {
	case <-paused:
	case o := <-first:
		t.Fatalf("the bootstrap returned without reading its admin back after the lost ack: %v", o.err)
	}
	go func() {
		res, err := c.BootstrapSystem(ctx, &BootstrapRequest{
			Username: "intruder", Email: "intruder@example.com", Password: "Kx7!Bootstrap-Pwd2", Token: retryToken,
		})
		second <- outcome{res, err}
	}()
	close(resume)

	got1, got2 := <-first, <-second
	require.NoError(t, got1.err, "the committed bootstrap is answered as a success")
	assert.False(t, got1.res.AlreadyInitialized)
	require.NoError(t, got2.err)
	assert.True(t, got2.res.AlreadyInitialized, "the second claim is refused")
	_, err := st.GetUserByUsername(ctx, "intruder")
	require.Error(t, err, "a second bootstrap must not create an admin")
	_, total, err := st.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "exactly one admin")
}

// lostAckThenReadFailStorage intercepts the first GetUser after the armed fault
// fired (the read-back): onReadBack, when set, runs before it is answered; without
// it the read-back fails, so one case combines the lost ack with an unreadable
// outcome.
type lostAckThenReadFailStorage struct {
	*faultstorage.FaultyStorage
	onReadBack func()
	readFailed bool
	seen       bool
}

func (s *lostAckThenReadFailStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if s.Fired() && !s.seen {
		s.seen = true
		if s.onReadBack != nil {
			s.onReadBack()
			return s.FaultyStorage.GetUser(ctx, id)
		}
		s.readFailed = true
		return nil, errors.New("connection reset by peer")
	}
	return s.FaultyStorage.GetUser(ctx, id)
}

// GetSessionAuthLiveness forwards the combined session read over this wrapper, so
// the GetUser override is not bypassed on that path (PERF-FIX-7 guard).
func (s *lostAckThenReadFailStorage) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}

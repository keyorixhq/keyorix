package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIAM struct {
	existing  []string // current access key ids for the user
	newID     string
	newSecret string
	createErr error
	deleteErr error // when set, DeleteAccessKey fails (cleanup-failure path)
	deleted   []string
	createdAs string // username passed to CreateAccessKey
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	md := make([]iamtypes.AccessKeyMetadata, 0, len(f.existing))
	for _, id := range f.existing {
		id := id
		md = append(md, iamtypes.AccessKeyMetadata{AccessKeyId: &id, UserName: in.UserName})
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: md}, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.createdAs = aws.ToString(in.UserName)
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String(f.newID), SecretAccessKey: aws.String(f.newSecret), UserName: in.UserName,
	}}, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

func iamWith(fake *fakeIAM, allowed ...string) *AWSIAMExecutor {
	e := NewAWSIAMExecutor("aws", "us-east-1", allowed)
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	return e
}

// TestAWSIAM_Client_LoadDefaultConfigError exercises the awsconfig.LoadDefaultConfig
// error branch inside AWSIAMExecutor.client() when newClient is nil. Pointing
// AWS_CONFIG_FILE at a directory (rather than a file) makes the SDK's shared-config
// read fail deterministically, without any network I/O or real AWS credentials.
func TestAWSIAM_Client_LoadDefaultConfigError(t *testing.T) {
	t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir())

	e := NewAWSIAMExecutor("aws-test", "us-east-1", nil)
	// e.newClient is left nil so the real awsconfig.LoadDefaultConfig path runs.
	cl, err := e.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, cl)
	assert.Contains(t, err.Error(), "aws-iam: load config")
}

func TestAWSIAM_TypeAndName(t *testing.T) {
	e := NewAWSIAMExecutor("prod-aws", "", nil)
	assert.Equal(t, "prod-aws", e.Name())
	assert.Equal(t, "aws-iam", e.Type())
}

func TestAWSIAM_RotateNotSupported(t *testing.T) {
	err := iamWith(&fakeIAM{}, "svc-").Rotate(context.Background(), "svc-app", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

func TestAWSIAM_GenerateUpstream_NoExistingKeys(t *testing.T) {
	fake := &fakeIAM{newID: "AKIANEW", newSecret: "s3cr3t"}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, "svc-app", fake.createdAs)
	assert.Empty(t, fake.deleted, "no prior keys to delete")

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
	assert.Equal(t, "s3cr3t", cred["secret_access_key"])
}

func TestAWSIAM_GenerateUpstream_DeletesPriorKeys(t *testing.T) {
	// One prior key → create new, then delete the prior.
	fake := &fakeIAM{existing: []string{"AKIAOLD"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, []string{"AKIAOLD"}, fake.deleted)
}

func TestAWSIAM_GenerateUpstream_TwoKeysFreesSlotFirst(t *testing.T) {
	// At the 2-key limit → delete oldest (to make room), create, delete the remaining prior.
	fake := &fakeIAM{existing: []string{"AKIA1", "AKIA2"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"AKIA1", "AKIA2"}, fake.deleted, "both prior keys removed; only the new one remains")
}

// TestAWSIAM_GenerateUpstream_PriorDeleteFailureIsSurfaced proves the rotation is
// NOT silently reported as success when a prior (possibly compromised) access key
// cannot be deleted. It must return a *PartialRotationError that still carries the
// new credential (so it can be stored) while surfacing the leftover key.
func TestAWSIAM_GenerateUpstream_PriorDeleteFailureIsSurfaced(t *testing.T) {
	fake := &fakeIAM{existing: []string{"AKIAOLD"}, newID: "AKIANEW", newSecret: "s3cr3t", deleteErr: errors.New("AccessDenied")}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")

	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial, "a cleanup failure must surface as PartialRotationError, not a clean success")
	assert.Contains(t, err.Error(), "AKIAOLD")
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v, "the value is carried on the error, not the return")

	// The new credential is preserved on the error so the caller can still store it.
	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(partial.Value), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
	assert.Equal(t, "s3cr3t", cred["secret_access_key"])
}

// TestAWSIAM_GenerateUpstream_EvictionFallbackToFirstPrior exercises the defensive
// `if victim == "" { victim = prior[0] }` fallback in GenerateUpstream: when
// evictableAccessKey returns "" (all its candidate IDs happen to be the empty
// string — a degenerate value AWS should never actually hand back, but one the
// code must not crash on), the caller must still pick a concrete victim to evict
// rather than leaving `victim` empty and calling DeleteAccessKey with a blank id
// silently succeeding against the wrong "nothing".
func TestAWSIAM_GenerateUpstream_EvictionFallbackToFirstPrior(t *testing.T) {
	// Two prior keys, both reporting an empty-string AccessKeyId: evictableAccessKey
	// still treats a non-nil *string as a candidate (only a nil pointer is skipped),
	// so with no Inactive key and no CreateDate ordering it settles on "" as the
	// victim. That drives the fallback: GenerateUpstream must fall back to prior[0]
	// (also "") rather than leaving victim empty and skipping the eviction call.
	fake := &fakeIAM{existing: []string{"", ""}, newID: "AKIANEW", newSecret: "x"}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Contains(t, fake.deleted, "", "the fallback victim (prior[0], the empty id) must actually be deleted, not silently skipped")

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
}

func TestAWSIAM_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}, "svc-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}).GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeIAM{newID: "x", newSecret: "y"}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "root")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.createdAs, "a disallowed ref never reaches AWS")
	})
	t.Run("create error propagates", func(t *testing.T) {
		fake := &fakeIAM{createErr: errors.New("LimitExceeded")}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "LimitExceeded")
	})
}

// raceFakeIAM is a concurrency-safe, orchestratable fake of a real IAM user's access
// key state — used only by TestAWSIAM_GenerateUpstream_ConcurrentSameRef below to
// deterministically reproduce the g05 unsynchronized-race finding. Unlike fakeIAM
// (whose fields are only ever mutated by one goroutine at a time in every other
// test), this fake must itself be safe under concurrent calls, and provides hooks to
// force a specific interleaving between two concurrent GenerateUpstream calls for
// the SAME ref.
type raceFakeIAM struct {
	mu      sync.Mutex
	keys    []string             // current live access key ids, mutation-guarded by mu
	created map[string]time.Time // id -> CreateDate, so evictableAccessKey picks realistically
	seq     int

	listCalls int
	// aListed is closed the instant the FIRST ListAccessKeys call (call "A") returns
	// its snapshot — the test uses this to know it is now safe to start the second
	// concurrent caller ("B") without risking B racing ahead to be the first Lister.
	aListed chan struct{}
	// createLanded is closed the instant the first CreateAccessKey call's new key is
	// appended to `keys` (i.e. visible to a subsequent List) — letting B's List (the
	// second List call) proceed only once A's new key genuinely exists upstream,
	// exactly the moment a live race would let B observe it.
	createLanded chan struct{}
	// releaseCreate is closed by the test to let the FIRST CreateAccessKey call
	// return control to its caller (A), after B has been allowed to run its entire
	// GenerateUpstream call to completion first. This is what manufactures the
	// dangerous interleaving: A believes it is still mid-rotation while B has
	// already listed, evicted, created, and cleaned up against the same ref.
	releaseCreate chan struct{}
}

func newRaceFakeIAM(seedKeyID string, seedAge time.Duration) *raceFakeIAM {
	return &raceFakeIAM{
		keys:          []string{seedKeyID},
		created:       map[string]time.Time{seedKeyID: time.Now().Add(-seedAge)},
		aListed:       make(chan struct{}),
		createLanded:  make(chan struct{}),
		releaseCreate: make(chan struct{}),
	}
}

func (f *raceFakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	f.mu.Lock()
	n := f.listCalls
	f.listCalls++
	f.mu.Unlock()

	if n == 0 {
		defer close(f.aListed)
	} else {
		// The second concurrent List (B's) only proceeds once A's create has landed
		// — i.e. once there is something new upstream for B to (wrongly) sweep up.
		<-f.createLanded
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	md := make([]iamtypes.AccessKeyMetadata, 0, len(f.keys))
	for _, id := range f.keys {
		id := id
		ct := f.created[id]
		md = append(md, iamtypes.AccessKeyMetadata{AccessKeyId: &id, CreateDate: &ct, UserName: in.UserName})
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: md}, nil
}

func (f *raceFakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	f.mu.Lock()
	// Mirror AWS's real hard two-key-per-user cap: a properly serialized rotation
	// never calls Create while already at 2 keys (it evicts first); an interleaved
	// one can, and here it fails exactly like AWS would.
	if len(f.keys) >= 2 {
		f.mu.Unlock()
		return nil, fmt.Errorf("LimitExceeded: cannot create more than 2 access keys")
	}
	f.seq++
	id := fmt.Sprintf("KNEW%d", f.seq)
	f.keys = append(f.keys, id)
	f.created[id] = time.Now()
	first := f.seq == 1
	f.mu.Unlock()

	if first {
		close(f.createLanded)
		// Hold A here — after AWS-side creation has already landed — until the test
		// lets B run its entire concurrent rotation to completion first.
		<-f.releaseCreate
	}
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String(id), SecretAccessKey: aws.String("secret-" + id), UserName: in.UserName,
	}}, nil
}

func (f *raceFakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	id := aws.ToString(in.AccessKeyId)
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.keys[:0]
	found := false
	for _, k := range f.keys {
		if k == id {
			found = true
			continue
		}
		out = append(out, k)
	}
	f.keys = out
	if !found {
		// Real AWS DeleteAccessKey on an already-gone key id returns NoSuchEntity —
		// which is exactly what happens when a concurrent rotation already deleted
		// this same key out from under the caller.
		return nil, fmt.Errorf("NoSuchEntity: access key %s not found", id)
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (f *raceFakeIAM) liveKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

// TestAWSIAM_GenerateUpstream_ConcurrentSameRef reproduces the g05 finding:
// GenerateUpstream performs an unsynchronized list→evict→create→delete sequence
// against AWS IAM, so two concurrent calls for the SAME ref (e.g. the auto-rotation
// scheduler tick racing a manually-triggered on-demand rotation — both reachable in
// the same process) can interleave.
//
// Orchestration: the IAM user starts with one key (K0, seeded old). Call "A" lists
// (sees only K0, below the 2-key cap, so no eviction) and creates a new key — which
// is deliberately held from returning to A's Go code until call "B" has been allowed
// to run its ENTIRE GenerateUpstream to completion. Pre-fix, nothing stops B from
// doing exactly that: B lists (now sees [K0, A's new key] — AT the cap), evicts the
// genuinely-oldest K0, creates its own new key, and then — in its final "delete every
// prior" cleanup — deletes A's brand-new key, the one A is about to report back to
// ITS OWN caller as the current live credential. Post-fix, B cannot even begin its
// List until A's mutex-held rotation fully completes, so this interleaving is
// structurally impossible; the test detects that as B still being blocked after a
// generous timeout, then lets A finish and confirms both rotations independently
// leave a fully consistent, sequential result.
func TestAWSIAM_GenerateUpstream_ConcurrentSameRef(t *testing.T) {
	fake := newRaceFakeIAM("K0", time.Hour)
	exec := NewAWSIAMExecutor("aws", "us-east-1", []string{"svc-"})
	exec.newClient = func(context.Context) (iamAPI, error) { return fake, nil }

	type outcome struct {
		val string
		err error
	}
	aCh := make(chan outcome, 1)
	bCh := make(chan outcome, 1)

	go func() {
		v, err := exec.GenerateUpstream(context.Background(), "svc-app")
		aCh <- outcome{v, err}
	}()
	<-fake.aListed // A has listed (and is on its way to Create); safe to start B now

	go func() {
		v, err := exec.GenerateUpstream(context.Background(), "svc-app")
		bCh <- outcome{v, err}
	}()

	// Pre-fix: nothing blocks B, so it races ahead and finishes almost immediately.
	// Post-fix: B is blocked acquiring the per-ref mutex A already holds, and will
	// NOT complete until A does — which A cannot do until we release it below. This
	// wait is not a flaky timing race: whichever branch fires is fully determined by
	// whether the fix's mutex exists, not by scheduling luck.
	var b outcome
	bDone := false
	select {
	case b = <-bCh:
		bDone = true
	case <-time.After(2 * time.Second):
		// Expected once serialized: B is correctly still waiting for A's lock.
	}

	// The core g05 assertion, taken RIGHT HERE — before A is released to resume —
	// because this is the only point that is not itself racing B's independent
	// execution: if B already fully completed while A was still parked mid-flight,
	// A's own brand-new key (deterministically "KNEW1": the aListed gate above
	// guarantees A is always the first Create call) must still exist upstream. A is
	// about to report that exact id back to its own caller as the current live
	// credential — if it's already gone, that's a caller being handed a credential
	// invalidated before it was ever returned, the danger this fix closes. (Once B
	// is legitimately allowed to run a SEPARATE, later rotation of the same secret
	// after A has actually returned, it deleting A's now-superseded key is normal,
	// not a bug — which is why this check must happen now, not after both finish.)
	if bDone {
		assert.Contains(t, fake.liveKeys(), "KNEW1",
			"call B's concurrent rotation for the same ref already deleted call A's brand-new access key %q before A had even reported it as the current credential — the exact g05 race", "KNEW1")
	}

	close(fake.releaseCreate) // let A's held Create return; A can now finish
	a := <-aCh
	if !bDone {
		b = <-bCh // now that A released the lock, B must finish too
	}

	// Once properly serialized, neither call should ever need the partial-failure
	// path — every delete a call attempts is always of a key it alone is entitled to
	// remove, so it always succeeds. (Pre-fix, A's own final cleanup attempts to
	// delete a key B already removed, surfacing exactly as this kind of error.)
	require.NoError(t, a.err, "call A should not need PartialRotationError when properly serialized")
	require.NoError(t, b.err, "call B should not need PartialRotationError when properly serialized")

	// Exactly one access key should remain live after two full rotations of the same
	// ref have completed, run one after the other rather than interleaved.
	assert.Len(t, fake.liveKeys(), 1, "exactly one access key should remain live after two serialized rotations")
}

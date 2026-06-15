package evidencesink

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type putCall struct {
	bucket, key, body, ctype string
	lockMode                 s3types.ObjectLockMode
	retainUntil              *time.Time
	legalHold                s3types.ObjectLockLegalHoldStatus
}

type fakeS3 struct {
	calls []putCall
	err   error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.calls = append(f.calls, putCall{
		bucket: deref(in.Bucket), key: deref(in.Key), body: string(b), ctype: deref(in.ContentType),
		lockMode: in.ObjectLockMode, retainUntil: in.ObjectLockRetainUntilDate, legalHold: in.ObjectLockLegalHoldStatus,
	})
	if f.err != nil {
		return nil, f.err
	}
	return &s3.PutObjectOutput{}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func newTestObjectStore(api s3PutAPI, prefix string) *ObjectStore {
	return &ObjectStore{api: api, bucket: "evidence-bkt", prefix: normalizePrefix(prefix), now: time.Now}
}

func TestObjectStore_UploadsPackAndSignature(t *testing.T) {
	api := &fakeS3{}
	o := newTestObjectStore(api, "keyorix/evidence")

	err := o.ForwardEvidence(context.Background(), "keyorix-evidence-20260615T100000Z.json", []byte(`{"a":1}`), "v1:abc")
	require.NoError(t, err)
	require.Len(t, api.calls, 2, "pack + detached signature")

	pack := api.calls[0]
	assert.Equal(t, "evidence-bkt", pack.bucket)
	assert.Equal(t, "keyorix/evidence/keyorix-evidence-20260615T100000Z.json", pack.key)
	assert.Equal(t, `{"a":1}`, pack.body)
	assert.Equal(t, "application/json", pack.ctype)

	sig := api.calls[1]
	assert.Equal(t, "keyorix/evidence/keyorix-evidence-20260615T100000Z.json.sig", sig.key)
	assert.Equal(t, "v1:abc", sig.body)

	// No object lock by default.
	assert.Empty(t, string(pack.lockMode))
	assert.Nil(t, pack.retainUntil)
}

func TestObjectStore_ObjectLockStampsRetentionOnEveryObject(t *testing.T) {
	api := &fakeS3{}
	fixed := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	o := &ObjectStore{
		api: api, bucket: "evidence-bkt", prefix: "",
		lockMode: s3types.ObjectLockModeCompliance,
		retain:   7 * 24 * time.Hour,
		now:      func() time.Time { return fixed },
	}

	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "v1:abc"))
	require.Len(t, api.calls, 2, "pack + signature both locked")
	for _, c := range api.calls {
		assert.Equal(t, s3types.ObjectLockModeCompliance, c.lockMode, "every object carries the lock mode")
		require.NotNil(t, c.retainUntil)
		assert.Equal(t, fixed.Add(7*24*time.Hour), *c.retainUntil, "retain-until = now + window")
	}
	assert.Contains(t, o.Target(), "lock:compliance")
}

func TestObjectStore_LegalHoldStampsEveryObject(t *testing.T) {
	api := &fakeS3{}
	o := &ObjectStore{api: api, bucket: "evidence-bkt", prefix: "", legalHold: true, now: time.Now}

	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "v1:abc"))
	require.Len(t, api.calls, 2)
	for _, c := range api.calls {
		assert.Equal(t, s3types.ObjectLockLegalHoldStatusOn, c.legalHold, "every object gets a legal hold")
		assert.Empty(t, string(c.lockMode), "legal hold is independent of retention mode")
	}
	assert.Contains(t, o.Target(), "legal-hold")
}

func TestObjectStore_NoLegalHoldByDefault(t *testing.T) {
	api := &fakeS3{}
	o := newTestObjectStore(api, "")
	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	assert.Empty(t, string(api.calls[0].legalHold))
}

func TestNewObjectStore_ObjectLockValidation(t *testing.T) {
	ctx := context.Background()
	// Unknown mode rejected.
	_, err := NewObjectStore(ctx, ObjectStoreConfig{Bucket: "b", LockMode: "weak"})
	require.Error(t, err)
	// Mode set but no retention → rejected.
	_, err = NewObjectStore(ctx, ObjectStoreConfig{Bucket: "b", LockMode: "governance"})
	require.Error(t, err)
}

func TestObjectStore_NoSignatureSkipsSigObject(t *testing.T) {
	api := &fakeS3{}
	o := newTestObjectStore(api, "") // no prefix

	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	require.Len(t, api.calls, 1, "only the pack when unsigned")
	assert.Equal(t, "pack.json", api.calls[0].key, "empty prefix → key is just the name")
}

func TestObjectStore_PutFailurePropagates(t *testing.T) {
	api := &fakeS3{err: errors.New("access denied")}
	o := newTestObjectStore(api, "p")
	err := o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
}

func TestObjectStore_Target(t *testing.T) {
	o := newTestObjectStore(&fakeS3{}, "keyorix/evidence")
	assert.Equal(t, "objectstore:evidence-bkt/keyorix/evidence/", o.Target())
}

func TestNewObjectStore_RequiresBucket(t *testing.T) {
	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{})
	require.Error(t, err)
}

func TestNormalizePrefix(t *testing.T) {
	assert.Equal(t, "", normalizePrefix(""))
	assert.Equal(t, "a/", normalizePrefix("a"))
	assert.Equal(t, "a/b/", normalizePrefix("a/b"))
	assert.Equal(t, "a/b/", normalizePrefix("a/b/"))
}

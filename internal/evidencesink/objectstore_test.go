package evidencesink

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type putCall struct {
	bucket, key, body, ctype string
}

type fakeS3 struct {
	calls []putCall
	err   error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.calls = append(f.calls, putCall{
		bucket: deref(in.Bucket), key: deref(in.Key), body: string(b), ctype: deref(in.ContentType),
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
	return &ObjectStore{api: api, bucket: "evidence-bkt", prefix: normalizePrefix(prefix)}
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

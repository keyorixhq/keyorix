package evidencesink

import (
	"context"
	"errors"
	"io"
	"net"
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

// TestNewObjectStore_RejectsInvalidEndpointScheme verifies a custom object-store
// endpoint with a non-http(s) scheme (or a malformed URL) is rejected at
// construction, rather than being handed to the AWS SDK unchecked. Before this
// fix, ObjectStoreConfig.Endpoint had NO validation at all — unlike webhook.go's
// sibling Endpoint field.
func TestNewObjectStore_RejectsInvalidEndpointScheme(t *testing.T) {
	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b", Endpoint: "ftp://example.com"})
	require.ErrorContains(t, err, "must use http or https")

	_, err = NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b", Endpoint: "file:///etc/passwd"})
	require.ErrorContains(t, err, "must use http or https")
}

// TestNewObjectStore_RejectsMalformedEndpoint verifies an unparseable endpoint URL
// is rejected with a clear error instead of surfacing later as an opaque SDK
// failure.
func TestNewObjectStore_RejectsMalformedEndpoint(t *testing.T) {
	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b", Endpoint: "http://[::1"})
	require.ErrorContains(t, err, "invalid object-store endpoint")
}

// TestNewObjectStore_RejectsEndpointWithNoHost verifies a scheme-only endpoint
// (no host to connect to) is rejected rather than silently passed through.
func TestNewObjectStore_RejectsEndpointWithNoHost(t *testing.T) {
	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b", Endpoint: "https:///path"})
	require.ErrorContains(t, err, "has no host")
}

// TestNewObjectStore_AcceptsSelfHostedPrivateEndpoint verifies the primary,
// legitimate use case — a self-hosted S3-compatible store (MinIO, a local
// gateway, ...) living on a private/internal address — is still accepted.
// Unlike webhook.go's blanket SSRF IP-range guard, the object-store endpoint
// validation must NOT block this: that's the whole point of self-hosting, and
// the finding itself calls out that a blanket private-IP block would break
// this primary use case. The endpoint is a literal IP so no DNS resolution is
// needed, keeping this test hermetic.
func TestNewObjectStore_AcceptsSelfHostedPrivateEndpoint(t *testing.T) {
	o, err := NewObjectStore(context.Background(), ObjectStoreConfig{
		Bucket:       "evidence",
		Endpoint:     "http://10.0.0.50:9000",
		UsePathStyle: true,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
}

// TestNewObjectStore_EndpointResolutionFailurePropagates verifies a hostname
// endpoint that fails to resolve at construction time fails NewObjectStore
// (fail-closed), rather than silently deferring the failure to the first
// upload — and confirms construction actually resolves the configured host as
// part of setting up the pinned dialer.
func TestNewObjectStore_EndpointResolutionFailurePropagates(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	}

	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b", Endpoint: "http://minio.internal:9000"})
	require.ErrorContains(t, err, "resolve object-store endpoint")
}

// TestPinnedDialContext_ResolvesOnceAndPinsIP is the direct regression test for
// the DNS-rebinding mitigation: pinnedDialContext must resolve its host exactly
// ONCE and then dial that same literal IP for every subsequent connection, even
// if the hostname's DNS answer changes afterward (a DNS-rebinding attacker
// repointing the operator-configured endpoint after it was set up). This is what
// closes the finding's residual risk — the evidence pack's PUT (carrying the
// SigV4 Authorization header) keeps going to the address actually resolved at
// setup time, not wherever the hostname currently resolves to.
func TestPinnedDialContext_ResolvesOnceAndPinsIP(t *testing.T) {
	origLookup := lookupIPAddr
	origDial := rawDialContext
	defer func() { lookupIPAddr = origLookup; rawDialContext = origDial }()

	lookups := 0
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		}
		// A later call (there should never be one) simulates a rebound
		// answer — a different IP the pinned dialer must never observe.
		return []net.IPAddr{{IP: net.ParseIP("198.51.100.99")}}, nil
	}

	var dialedAddr string
	rawDialContext = func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("stub: no real dial performed")
	}

	dial, err := pinnedDialContext("minio.internal")
	require.NoError(t, err)
	assert.Equal(t, 1, lookups, "resolves exactly once, at pinning time")

	_, _ = dial(context.Background(), "tcp", "minio.internal:9000")
	assert.Equal(t, "203.0.113.10:9000", dialedAddr, "dials the pinned first-resolution IP")
	assert.Equal(t, 1, lookups, "does not re-resolve on dial")

	// A second dial (as happens across the ObjectStore's many uploads over
	// its lifetime) must still use the originally pinned IP, never a fresh
	// (possibly rebound) DNS answer.
	dialedAddr = ""
	_, _ = dial(context.Background(), "tcp", "minio.internal:9000")
	assert.Equal(t, "203.0.113.10:9000", dialedAddr, "still pinned to the original IP on a later dial")
	assert.Equal(t, 1, lookups, "still exactly one resolution total")
}

// TestPinnedDialContext_LiteralIPSkipsResolution verifies an endpoint that is
// already a literal IP (no hostname to rebind) dials straight through without
// consulting the resolver at all.
func TestPinnedDialContext_LiteralIPSkipsResolution(t *testing.T) {
	origLookup := lookupIPAddr
	defer func() { lookupIPAddr = origLookup }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		t.Fatalf("lookupIPAddr must not be called for a literal-IP endpoint, got host %q", host)
		return nil, nil
	}

	dial, err := pinnedDialContext("10.0.0.50")
	require.NoError(t, err)
	require.NotNil(t, dial)
}

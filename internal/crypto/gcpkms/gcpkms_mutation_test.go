package gcpkms

// Tests added for the gremlins survivors on internal/crypto/gcpkms (#3612,
// MUTANT-CRYPTO-1). Each test pins an exact boundary rather than "no error".

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"path/filepath"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const mutKeyName = "projects/p/locations/l/keyRings/r/cryptoKeys/k"

// strictKMS behaves like the real service for checksum reporting: a request
// checksum is reported as verified ONLY when the request carried it (unlike
// fakeKMS, which reports the AAD checksum as verified when no AAD was sent).
type strictKMS struct {
	capturingKMS
}

func (s *strictKMS) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	resp, err := s.capturingKMS.Encrypt(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	resp.VerifiedAdditionalAuthenticatedDataCrc32C = req.GetAdditionalAuthenticatedDataCrc32C() != nil
	return resp, nil
}

// gcpkms.go:90 (create-client error branch). GOOGLE_APPLICATION_CREDENTIALS
// pointing at a missing file makes NewKeyManagementClient fail deterministically
// with no network access; an authorized_user file makes it succeed (client
// construction is lazy, nothing is dialled or refreshed).
func TestNew_CreateClientFailureIsWrapped(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	c, err := New(context.Background(), mutKeyName, nil, false)
	require.Error(t, err)
	assert.Nil(t, c, "a failed New must not hand back a client")
	assert.ErrorContains(t, err, "gcp-kms: create client")
}

func TestNew_CreateClientSuccessCarriesConfig(t *testing.T) {
	cred := filepath.Join(t.TempDir(), "adc.json")
	require.NoError(t, os.WriteFile(cred, []byte(`{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`), 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", cred)

	got, err := New(context.Background(), mutKeyName, map[string]string{"k": "v"}, true)
	require.NoError(t, err)
	require.NotNil(t, got)
	c, ok := got.(*client)
	require.True(t, ok)
	t.Cleanup(func() { _ = c.kms.(interface{ Close() error }).Close() })
	assert.Equal(t, mutKeyName, c.keyName)
	assert.Equal(t, encContextAAD(map[string]string{"k": "v"}), c.aad)
	assert.True(t, c.allowFallback)
}

// gcpkms.go:120 (33, 42, 66): the buffer is preallocated with an upper bound so
// the appends below never reallocate. The bytes are unaffected by a wrong bound,
// so the only observable is the capacity: it must cover two max-width varint
// prefixes plus the content for every entry.
func TestEncContextAAD_PreallocatesUpperBound(t *testing.T) {
	for _, m := range []map[string]string{
		{"a": "b"},
		{"key": "value", "other": ""},
		{"k1": "v1", "k2": "v2", "k3": "v3"},
	} {
		want := 0
		for k, v := range m {
			want += 2*binary.MaxVarintLen64 + len(k) + len(v)
		}
		got := encContextAAD(m)
		require.NotEmpty(t, got)
		assert.GreaterOrEqual(t, cap(got), want, "map %v", m)
		assert.LessOrEqual(t, len(got), want)
	}
}

// gcpkms.go:148 and :163 — with no AAD configured the client must send neither
// the AAD nor its checksum, and must not require the server to verify one.
func TestEncrypt_NoAAD_SendsNoAADFields_AndNeedsNoAADVerification(t *testing.T) {
	kms := &strictKMS{}
	c := &client{kms: kms, keyName: mutKeyName}

	ct, err := c.Encrypt(context.Background(), []byte("kek"))
	require.NoError(t, err, "a server that (correctly) reports no AAD verification for a request without AAD must be accepted")
	require.NotEmpty(t, ct)

	req := kms.lastEncryptReq
	require.NotNil(t, req)
	assert.Nil(t, req.AdditionalAuthenticatedData)
	assert.Nil(t, req.AdditionalAuthenticatedDataCrc32C, "no AAD checksum without AAD")
	assert.NotNil(t, req.PlaintextCrc32C, "the plaintext checksum is always sent")
}

func TestEncrypt_WithAAD_RequiresAADVerification(t *testing.T) {
	c := &client{kms: corruptChecksumKMS{dropAADVerifiedFlags: true}, keyName: mutKeyName, aad: encContextAAD(map[string]string{"a": "b"})}
	_, err := c.Encrypt(context.Background(), []byte("kek"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "AAD checksum")
}

// gcpkms.go:191 — same on the decrypt request.
func TestDecrypt_NoAAD_SendsNoAADFields(t *testing.T) {
	kms := &strictKMS{}
	c := &client{kms: kms, keyName: mutKeyName}
	ct, err := c.Encrypt(context.Background(), []byte("kek"))
	require.NoError(t, err)

	pt, fellBack, err := c.DecryptReportingFallback(context.Background(), ct)
	require.NoError(t, err)
	assert.False(t, fellBack)
	assert.Equal(t, []byte("kek"), pt)

	req := kms.lastDecryptReq
	require.NotNil(t, req)
	assert.Nil(t, req.AdditionalAuthenticatedData)
	assert.Nil(t, req.AdditionalAuthenticatedDataCrc32C, "no AAD checksum without AAD")
	assert.NotNil(t, req.CiphertextCrc32C)
}

func TestDecrypt_WithAAD_SendsAADAndChecksum(t *testing.T) {
	kms := &strictKMS{}
	aad := encContextAAD(map[string]string{"a": "b"})
	c := &client{kms: kms, keyName: mutKeyName, aad: aad}
	ct, err := c.Encrypt(context.Background(), []byte("kek"))
	require.NoError(t, err)
	_, err = c.Decrypt(context.Background(), ct)
	require.NoError(t, err)

	req := kms.lastDecryptReq
	assert.Equal(t, aad, req.AdditionalAuthenticatedData)
	require.NotNil(t, req.AdditionalAuthenticatedDataCrc32C)
	assert.Equal(t, int64(crc32cSum(aad)), req.AdditionalAuthenticatedDataCrc32C.GetValue())
}

// gcpkms.go:184 — the no-AAD retry needs BOTH the flag and a configured AAD.
func TestContextFallbackEnabled_NeedsFlagAndAAD(t *testing.T) {
	aad := encContextAAD(map[string]string{"a": "b"})
	cases := []struct {
		name  string
		aad   []byte
		allow bool
		want  bool
	}{
		{"flag without aad", nil, true, false},
		{"empty aad", []byte{}, true, false},
		{"aad without flag", aad, false, false},
		{"neither", nil, false, false},
		{"flag and aad", aad, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{kms: fakeKMS{}, keyName: mutKeyName, aad: tc.aad, allowFallback: tc.allow}
			assert.Equal(t, tc.want, c.ContextFallbackEnabled())
		})
	}
}

// With a flag set but no AAD configured there is nothing to fall back from: a
// KMS error must be returned after exactly ONE Decrypt call, not retried.
func TestDecrypt_FlagWithoutAAD_DoesNotRetry(t *testing.T) {
	kms := &countingErrKMS{err: errors.New("denied")}
	c := &client{kms: kms, keyName: mutKeyName, allowFallback: true}
	_, err := c.Decrypt(context.Background(), []byte("ct"))
	require.Error(t, err)
	assert.Equal(t, 1, kms.decrypts)
}

// With flag and AAD, a failing first attempt is retried exactly once.
func TestDecrypt_FlagWithAAD_RetriesExactlyOnce(t *testing.T) {
	kms := &countingErrKMS{err: errors.New("denied")}
	c := &client{kms: kms, keyName: mutKeyName, aad: encContextAAD(map[string]string{"a": "b"}), allowFallback: true}
	_, err := c.Decrypt(context.Background(), []byte("ct"))
	require.Error(t, err)
	assert.Equal(t, 2, kms.decrypts)
	require.Len(t, kms.reqs, 2)
	assert.NotEmpty(t, kms.reqs[0].AdditionalAuthenticatedData)
	assert.Empty(t, kms.reqs[1].AdditionalAuthenticatedData, "the retry carries no AAD")
	assert.Nil(t, kms.reqs[1].AdditionalAuthenticatedDataCrc32C)
}

type countingErrKMS struct {
	err      error
	decrypts int
	reqs     []*kmspb.DecryptRequest
}

func (c *countingErrKMS) Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	return nil, c.err
}

func (c *countingErrKMS) Decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	c.decrypts++
	c.reqs = append(c.reqs, req)
	return nil, c.err
}

// gcpkms.go:243 — a sink failure is logged, a sink success is not.
func TestEmitFallbackAudit_LogsOnlyOnSinkFailure(t *testing.T) {
	var buf bytes.Buffer
	prevW, prevF := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevW); log.SetFlags(prevF) })

	c := &client{kms: fakeKMS{}, keyName: mutKeyName}

	c.SetAuditSink(func(context.Context, *models.AuditEvent) error { return nil })
	c.emitFallbackAudit(context.Background(), "desc")
	assert.NotContains(t, buf.String(), "failed to write audit event", "a successful sink write must not log a failure")

	buf.Reset()
	c.SetAuditSink(func(context.Context, *models.AuditEvent) error { return errors.New("sink down") })
	c.emitFallbackAudit(context.Background(), "desc")
	assert.Contains(t, buf.String(), "failed to write audit event")
	assert.Contains(t, buf.String(), "sink down")
}

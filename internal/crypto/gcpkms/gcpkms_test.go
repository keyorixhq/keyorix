package gcpkms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeKMS models GCP KMS AAD and CRC32C semantics: a blob decrypts only with the
// exact AdditionalAuthenticatedData it was encrypted under, and both Encrypt and
// Decrypt responses carry correct checksums/verified-flags, matching what a real
// KMS endpoint returns for a request it received uncorrupted. The AAD is embedded
// in the ciphertext so the fake is stateless.
type fakeKMS struct{}

type fakeBlob struct {
	Plaintext []byte `json:"p"`
	AAD       []byte `json:"a"`
}

func (fakeKMS) Encrypt(_ context.Context, req *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	b, _ := json.Marshal(fakeBlob{Plaintext: req.Plaintext, AAD: req.AdditionalAuthenticatedData})
	return &kmspb.EncryptResponse{
		Ciphertext:              b,
		CiphertextCrc32C:        wrapperspb.Int64(int64(crc32cSum(b))),
		VerifiedPlaintextCrc32C: req.GetPlaintextCrc32C() != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: req.GetAdditionalAuthenticatedDataCrc32C() != nil || len(req.AdditionalAuthenticatedData) == 0,
	}, nil
}

func (fakeKMS) Decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	var b fakeBlob
	if err := json.Unmarshal(req.Ciphertext, &b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b.AAD, req.AdditionalAuthenticatedData) {
		return nil, errors.New("decryption failed: AAD mismatch")
	}
	return &kmspb.DecryptResponse{
		Plaintext:       b.Plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32cSum(b.Plaintext))),
	}, nil
}

// corruptChecksumKMS wraps fakeKMS but returns a response whose checksum field
// does not match its payload, modelling transport corruption between the client
// and the KMS service.
type corruptChecksumKMS struct {
	corruptEncryptResp bool
	corruptDecryptResp bool
	dropVerifiedFlags  bool
}

func (c corruptChecksumKMS) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	resp, err := (fakeKMS{}).Encrypt(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	if c.corruptEncryptResp {
		resp.CiphertextCrc32C = wrapperspb.Int64(resp.CiphertextCrc32C.GetValue() + 1)
	}
	if c.dropVerifiedFlags {
		resp.VerifiedPlaintextCrc32C = false
	}
	return resp, nil
}

func (c corruptChecksumKMS) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	resp, err := (fakeKMS{}).Decrypt(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	if c.corruptDecryptResp {
		resp.PlaintextCrc32C = wrapperspb.Int64(resp.PlaintextCrc32C.GetValue() + 1)
	}
	return resp, nil
}

// capturingKMS records the last request it saw so tests can assert on the
// checksum fields the client populated.
type capturingKMS struct {
	fakeKMS
	lastEncryptReq *kmspb.EncryptRequest
	lastDecryptReq *kmspb.DecryptRequest
}

func (c *capturingKMS) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	c.lastEncryptReq = req
	return c.fakeKMS.Encrypt(ctx, req, opts...)
}

func (c *capturingKMS) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	c.lastDecryptReq = req
	return c.fakeKMS.Decrypt(ctx, req, opts...)
}

func newTestClient(encCtx map[string]string, allowFallback bool) *client {
	return &client{kms: fakeKMS{}, keyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k", aad: encContextAAD(encCtx), allowFallback: allowFallback}
}

func TestGCPKMS_RoundTripWithContext(t *testing.T) {
	c := newTestClient(map[string]string{"keyorix-install": "inst-1"}, false)
	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "kek-material" {
		t.Fatalf("round-trip got %q", pt)
	}
}

// #123: with the fallback OFF (the default), an AAD-less blob — the exact shape an
// attacker with encrypt permission on a shared CMK (but not Keyorix's own data) would
// plant — must NOT decrypt against an AAD-bound client.
func TestGCPKMS_FallbackDisabledByDefault_PlantedNoAADBlobRejected(t *testing.T) {
	planted := newTestClient(nil, false)
	ct, _ := planted.Encrypt(context.Background(), []byte("malicious-kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, false)
	if _, err := bound.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("a no-AAD blob must NOT decrypt against an AAD-bound client when kms_allow_context_fallback is off")
	}
}

// With kms_allow_context_fallback explicitly enabled, a legacy no-AAD blob DOES
// decrypt — preserving the documented migration path.
func TestGCPKMS_FallbackEnabled_LegacyBlobDecryptsAsMigrationAid(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, _ := legacy.Encrypt(context.Background(), []byte("kek"))
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true)
	pt, err := bound.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("legacy blob must decrypt via the explicitly-enabled fallback: %v", err)
	}
	if string(pt) != "kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestGCPKMS_CrossInstallDenied(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, false)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's AAD-bound KEK")
	}
}

// Cross-install isolation between two DIFFERENTLY-bound installs holds regardless of
// the fallback setting; only a no-AAD blob benefits from it.
func TestGCPKMS_CrossInstallDenied_EvenWithFallbackEnabled(t *testing.T) {
	a := newTestClient(map[string]string{"keyorix-install": "inst-A"}, false)
	ct, _ := a.Encrypt(context.Background(), []byte("kek-A"))
	b := newTestClient(map[string]string{"keyorix-install": "inst-B"}, true)
	if _, err := b.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("install B must not unwrap install A's AAD-bound KEK even with its own fallback enabled")
	}
}

func TestEncContextAAD_DeterministicAndEmpty(t *testing.T) {
	if encContextAAD(nil) != nil || encContextAAD(map[string]string{}) != nil {
		t.Fatal("empty context must produce nil AAD (byte-identical to no binding)")
	}
	a := encContextAAD(map[string]string{"b": "2", "a": "1"})
	b := encContextAAD(map[string]string{"a": "1", "b": "2"})
	if !bytes.Equal(a, b) {
		t.Fatal("AAD must be deterministic regardless of map iteration order")
	}
}

// crypto-gcpkms-02: Encrypt must populate PlaintextCrc32C (and the AAD checksum
// when AAD is set) on the outgoing request.
func TestGCPKMS_Encrypt_PopulatesRequestChecksums(t *testing.T) {
	kms := &capturingKMS{}
	c := &client{kms: kms, keyName: "k", aad: encContextAAD(map[string]string{"install": "i1"})}
	if _, err := c.Encrypt(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if kms.lastEncryptReq.GetPlaintextCrc32C() == nil {
		t.Fatal("PlaintextCrc32C was not set on the EncryptRequest")
	}
	if got, want := kms.lastEncryptReq.GetPlaintextCrc32C().GetValue(), int64(crc32cSum([]byte("payload"))); got != want {
		t.Fatalf("PlaintextCrc32C = %d, want %d", got, want)
	}
	if kms.lastEncryptReq.GetAdditionalAuthenticatedDataCrc32C() == nil {
		t.Fatal("AdditionalAuthenticatedDataCrc32C was not set on the EncryptRequest despite AAD being set")
	}
}

// crypto-gcpkms-02: Decrypt must populate CiphertextCrc32C (and the AAD checksum
// when AAD is set) on the outgoing request.
func TestGCPKMS_Decrypt_PopulatesRequestChecksums(t *testing.T) {
	kms := &capturingKMS{}
	c := &client{kms: kms, keyName: "k", aad: encContextAAD(map[string]string{"install": "i1"})}
	ct, err := c.Encrypt(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := c.Decrypt(context.Background(), ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if kms.lastDecryptReq.GetCiphertextCrc32C() == nil {
		t.Fatal("CiphertextCrc32C was not set on the DecryptRequest")
	}
	if got, want := kms.lastDecryptReq.GetCiphertextCrc32C().GetValue(), int64(crc32cSum(ct)); got != want {
		t.Fatalf("CiphertextCrc32C = %d, want %d", got, want)
	}
	if kms.lastDecryptReq.GetAdditionalAuthenticatedDataCrc32C() == nil {
		t.Fatal("AdditionalAuthenticatedDataCrc32C was not set on the DecryptRequest despite AAD being set")
	}
}

// crypto-gcpkms-02: a corrupted EncryptResponse.ciphertext_crc32c must be
// detected and rejected rather than silently trusted.
func TestGCPKMS_Encrypt_RejectsCorruptedResponseChecksum(t *testing.T) {
	c := &client{kms: corruptChecksumKMS{corruptEncryptResp: true}, keyName: "k"}
	if _, err := c.Encrypt(context.Background(), []byte("payload")); err == nil {
		t.Fatal("Encrypt must reject a response whose ciphertext_crc32c does not match its ciphertext")
	}
}

// crypto-gcpkms-02: an EncryptResponse that never reports the plaintext checksum
// as verified (e.g. an intermediary dropped/ignored the request checksum) must
// also be rejected — a false verified flag is exactly what an undetected
// request-side corruption looks like.
func TestGCPKMS_Encrypt_RejectsUnverifiedPlaintextChecksum(t *testing.T) {
	c := &client{kms: corruptChecksumKMS{dropVerifiedFlags: true}, keyName: "k"}
	if _, err := c.Encrypt(context.Background(), []byte("payload")); err == nil {
		t.Fatal("Encrypt must reject a response that does not report the plaintext checksum as verified")
	}
}

// crypto-gcpkms-02: a corrupted DecryptResponse.plaintext_crc32c must be detected
// and rejected rather than silently trusted.
func TestGCPKMS_Decrypt_RejectsCorruptedResponseChecksum(t *testing.T) {
	enc := &client{kms: fakeKMS{}, keyName: "k"}
	ct, err := enc.Encrypt(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	c := &client{kms: corruptChecksumKMS{corruptDecryptResp: true}, keyName: "k"}
	if _, err := c.Decrypt(context.Background(), ct); err == nil {
		t.Fatal("Decrypt must reject a response whose plaintext_crc32c does not match its plaintext")
	}
}

// crypto-gcpkms-03: a successful AAD-fallback decrypt must be reported through
// the wired audit sink, not just log.Printf.
func TestGCPKMS_Decrypt_FallbackEmitsAuditEvent(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, err := legacy.Encrypt(context.Background(), []byte("kek"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true)

	var got []*models.AuditEvent
	bound.SetAuditSink(func(_ context.Context, event *models.AuditEvent) error {
		got = append(got, event)
		return nil
	})

	if _, err := bound.Decrypt(context.Background(), ct); err != nil {
		t.Fatalf("decrypt via fallback: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one audit event from the fallback decrypt, got %d", len(got))
	}
	if got[0].EventType != EventGCPKMSAADFallback {
		t.Fatalf("EventType = %q, want %q", got[0].EventType, EventGCPKMSAADFallback)
	}
	if got[0].Success == nil || *got[0].Success {
		t.Fatal("fallback audit event must report Success=false (it is a security-negative condition)")
	}
}

// The audit sink must NOT fire on an ordinary bound decrypt that never falls back.
func TestGCPKMS_Decrypt_NoFallback_NoAuditEvent(t *testing.T) {
	c := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true)
	ct, err := c.Encrypt(context.Background(), []byte("kek"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	fired := false
	c.SetAuditSink(func(_ context.Context, _ *models.AuditEvent) error {
		fired = true
		return nil
	})
	if _, err := c.Decrypt(context.Background(), ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if fired {
		t.Fatal("audit sink must not fire when the decrypt succeeds without falling back")
	}
}

// SetAuditSink is a no-op when unset — the fallback must still succeed and only
// log, never error, when no sink is wired.
func TestGCPKMS_Decrypt_FallbackWithoutSinkStillSucceeds(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, err := legacy.Encrypt(context.Background(), []byte("kek"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	bound := newTestClient(map[string]string{"keyorix-install": "inst-1"}, true)
	pt, err := bound.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt via fallback without a sink: %v", err)
	}
	if string(pt) != "kek" {
		t.Fatalf("got %q", pt)
	}
}

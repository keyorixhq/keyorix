// gcpkms_audit_sink_wiring_test.go — verifies wireKMSAuditSink (service.go)
// actually connects a Service's audit sink to a directly-configured KMS key
// provider's underlying client, mirroring TestNewKeyProviderFromConfig_WeakFallback_RuntimeAuditEvent's
// coverage of the sibling MultiKeyProvider downgrade-hook wiring. This is the
// production-wiring counterpart to gcpkms's own package-level fallback-audit
// tests: those prove the client emits the event when a sink IS wired; this
// proves Service actually wires one for the gcp-kms provider shape, using a fake
// client (real gcpkms.New() needs live GCP ADC credentials, unavailable in CI —
// same constraint documented in encryption_s17_test.go).
package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/crypto/gcpkms"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fakeGCPKMSClient stands in for the real *gcpkms client: it implements
// crypto.KMSClient and, like the real client, an optional SetAuditSink hook.
type fakeGCPKMSClient struct {
	sink gcpkms.AuditSink
}

func (f *fakeGCPKMSClient) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (f *fakeGCPKMSClient) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (f *fakeGCPKMSClient) SetAuditSink(sink gcpkms.AuditSink) {
	f.sink = sink
}

// TestWireKMSAuditSink_ConnectsSinkToGCPKMSClient asserts that a Service with an
// audit sink set wires that sink onto a gcp-kms-shaped KMSKeyProvider's
// underlying client, and that invoking the wired sink actually reaches the
// Service's sink function.
func TestWireKMSAuditSink_ConnectsSinkToGCPKMSClient(t *testing.T) {
	fake := &fakeGCPKMSClient{}
	provider := crypto.NewKMSKeyProvider(fake, "gcp-kms", t.TempDir(), "wrapped.key")

	svc := NewService(&config.EncryptionConfig{Enabled: true}, t.TempDir())
	var got *models.AuditEvent
	svc.SetAuditSink(func(_ context.Context, event *models.AuditEvent) error {
		got = event
		return nil
	})

	svc.wireKMSAuditSink(provider)

	if fake.sink == nil {
		t.Fatal("wireKMSAuditSink did not wire a sink onto the underlying gcp-kms client")
	}
	event := &models.AuditEvent{EventType: gcpkms.EventGCPKMSAADFallback}
	if err := fake.sink(context.Background(), event); err != nil {
		t.Fatalf("wired sink returned an error: %v", err)
	}
	if got != event {
		t.Fatal("invoking the wired sink did not reach the Service's own audit sink")
	}
}

// TestWireKMSAuditSink_NoSinkConfigured_NoWiring asserts that with no Service
// audit sink set, wireKMSAuditSink leaves the client's sink unset (nil is a
// legitimate steady state: the client falls back to log.Printf only).
func TestWireKMSAuditSink_NoSinkConfigured_NoWiring(t *testing.T) {
	fake := &fakeGCPKMSClient{}
	provider := crypto.NewKMSKeyProvider(fake, "gcp-kms", t.TempDir(), "wrapped.key")

	svc := NewService(&config.EncryptionConfig{Enabled: true}, t.TempDir())
	svc.wireKMSAuditSink(provider)

	if fake.sink != nil {
		t.Fatal("wireKMSAuditSink must not wire anything when the Service has no audit sink configured")
	}
}

// TestWireKMSAuditSink_NonKMSProvider_NoPanic asserts that a non-KMS provider
// (e.g. the password provider) is simply skipped, not a panic or error.
func TestWireKMSAuditSink_NonKMSProvider_NoPanic(t *testing.T) {
	svc := NewService(&config.EncryptionConfig{Enabled: true}, t.TempDir())
	svc.SetAuditSink(func(_ context.Context, _ *models.AuditEvent) error { return nil })
	provider := crypto.NewPasswordKeyProvider("pw", t.TempDir(), "salt")
	svc.wireKMSAuditSink(provider) // must not panic
}

// Package dynamictest provides FakeEngine, an in-memory ports.DynamicBackendEngine
// for tests across packages that exercise dynamic-secret issuance without touching
// a real target backend. Test-only code (imported only from _test.go files) lives
// in its own package, never in internal/dynamic's production engine.go, so a
// production build never links a fake backend engine (family-check: FakeEngine is
// not, and must never become, a member registered by any production factory).
package dynamictest

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// Credential is a type alias of ports.DynamicCredential so FakeEngine's methods
// satisfy ports.DynamicBackendEngine directly, matching internal/dynamic's own
// Credential alias.
type Credential = ports.DynamicCredential

// FakeEngine is an in-memory engine for tests: it records issued and revoked
// roles without touching any real database.
type FakeEngine struct {
	mu           sync.Mutex
	Issued       []string
	Revoked      []string
	Renewed      []string
	FailIssue    bool
	FailRevoke   bool
	FailRenew    bool
	NativeExpiry bool              // when true, mimics a backend with DB-level TTL (e.g. Postgres)
	Ephemeral    bool              // when true, mimics a cloud-IAM backend (no renew)
	IssueFields  map[string]string // when set, returned in the issued Credential.Fields
	// RevokeEffective overrides RevokeInvalidatesCredential's result when non-nil,
	// for tests simulating a backend (like Kubernetes' opt-in bound-token mode)
	// whose Revoke genuinely invalidates the credential despite being ephemeral.
	// When nil, it defaults to !Ephemeral (matching every real non-ephemeral
	// engine, and AWS STS/Azure/GCP's always-false ephemeral no-op).
	RevokeEffective *bool
}

func (f *FakeEngine) BackendType() string        { return "fake" }
func (f *FakeEngine) SupportsNativeExpiry() bool { return f.NativeExpiry }
func (f *FakeEngine) IsEphemeralBackend() bool   { return f.Ephemeral }
func (f *FakeEngine) RevokeInvalidatesCredential(_ string) bool {
	if f.RevokeEffective != nil {
		return *f.RevokeEffective
	}
	return !f.Ephemeral
}

func (f *FakeEngine) Issue(_ context.Context, _, _ string, _ time.Duration) (Credential, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailIssue {
		return Credential{}, "", fmt.Errorf("fake issue failure")
	}
	suffix, err := randString(8)
	if err != nil {
		return Credential{}, "", err
	}
	role := "kx_fake_" + suffix
	pw, _ := randString(16)
	f.Issued = append(f.Issued, role)
	return Credential{Username: role, Password: pw, Fields: f.IssueFields}, role, nil
}

func (f *FakeEngine) Revoke(_ context.Context, _, roleName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailRevoke {
		return fmt.Errorf("fake revoke failure")
	}
	f.Revoked = append(f.Revoked, roleName)
	return nil
}

func (f *FakeEngine) Renew(_ context.Context, _, roleName string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailRenew {
		return fmt.Errorf("fake renew failure")
	}
	f.Renewed = append(f.Renewed, roleName)
	return nil
}

// randString returns n characters from a quote-free, identifier-safe alphabet
// (lowercase + digits) drawn from crypto/rand. Duplicated from internal/dynamic's
// unexported randString rather than imported, since that symbol is production-only
// and this package must not import internal/dynamic (it's imported BY internal/dynamic's
// own tests, and by other packages' tests, never the reverse).
func randString(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= 252 { // 252 = 7*36; reject 252-255 to keep it uniform
			continue
		}
		out = append(out, alphabet[int(buf[0])%len(alphabet)])
	}
	return string(out), nil
}

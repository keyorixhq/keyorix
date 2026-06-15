// Package dynamic implements the dynamic-secrets credential engines (ADR-035):
// on-demand, short-lived database credentials that Keyorix mints on the target
// and revokes on expiry — Vault's database-secrets-engine model.
package dynamic

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// Credential is an issued, short-lived credential returned to the caller once.
// Database backends populate Username/Password; cloud-IAM backends (e.g. AWS STS)
// have no username/password and instead populate Fields (access_key_id,
// secret_access_key, session_token, …).
type Credential struct {
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// CredentialEngine mints and revokes credentials on a target backend. The admin
// connection string (adminDSN) is supplied per call so the engine holds no
// long-lived state or secrets.
type CredentialEngine interface {
	// Issue creates a credential on the target valid for ttl, then runs the
	// operator's creationTemplate ({{name}} → the generated role name). It returns
	// the credential and the role name used to revoke it later.
	Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (cred Credential, roleName string, err error)
	// Revoke removes the role/credential from the target.
	Revoke(ctx context.Context, adminDSN, roleName string) error
	// Renew extends the credential's validity to expiresAt on backends that carry a
	// DB-level expiry (PostgreSQL VALID UNTIL). Backends without one (MySQL) make it
	// a no-op — the lease's new expiry is enforced by the auto-revoke sweep.
	Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) error
	// SupportsNativeExpiry reports whether the backend enforces the lease TTL at the
	// database level (PostgreSQL VALID UNTIL). A backend that returns false relies
	// ENTIRELY on the auto-revoke sweeper to enforce expiry, so issuing from it with
	// the sweeper disabled would mint a credential whose TTL is never enforced.
	SupportsNativeExpiry() bool
	BackendType() string
	// IsEphemeralBackend reports whether the backend mints self-expiring,
	// non-revocable credentials (e.g. AWS STS) rather than a persistent role on a
	// target. For such backends Revoke is a no-op (nothing to drop) and Renew is
	// refused — the credential's lifetime is fixed by the cloud provider at issue,
	// so a new lease must be issued instead of extending an existing one.
	IsEphemeralBackend() bool
}

// New returns the engine for a backend type.
func New(backendType string) (CredentialEngine, error) {
	switch backendType {
	case "postgres":
		return &PostgresEngine{}, nil
	case "mysql":
		return &MySQLEngine{}, nil
	case "mongodb":
		return &MongoEngine{}, nil
	case "redis":
		return &RedisEngine{}, nil
	case "aws-sts":
		return &AWSSTSEngine{}, nil
	case "gcp":
		return &GCPEngine{}, nil
	case "azure":
		return &AzureEngine{}, nil
	default:
		return nil, fmt.Errorf("unsupported dynamic-secret backend %q (supported: postgres, mysql, mongodb, redis, aws-sts, gcp, azure)", backendType)
	}
}

// randString returns n characters from a quote-free, identifier-safe alphabet
// (lowercase + digits) drawn from crypto/rand. 36 divides 252 with a small
// remainder; reject the top of the byte range to avoid modulo bias.
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
	Ephemeral    bool              // when true, mimics a cloud-IAM backend (no revoke, no renew)
	IssueFields  map[string]string // when set, returned in the issued Credential.Fields
}

func (f *FakeEngine) BackendType() string        { return "fake" }
func (f *FakeEngine) SupportsNativeExpiry() bool { return f.NativeExpiry }
func (f *FakeEngine) IsEphemeralBackend() bool   { return f.Ephemeral }

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

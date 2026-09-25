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

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// dialResolve resolves an admin-DSN hostname to its IP addresses for the
// dial-time SSRF re-check (dialPostgres, openMySQL) — a var (like
// evidencesink/notifychan's identically-shaped lookupIPAddr) so tests can
// substitute a fake resolver to simulate a DNS-rebinding target without a
// real DNS query.
var dialResolve netutil.Resolver = netutil.DefaultResolver

// Credential is an issued, short-lived credential returned to the caller once.
// Database backends populate Username/Password; cloud-IAM backends (e.g. AWS STS)
// have no username/password and instead populate Fields (access_key_id,
// secret_access_key, session_token, …).
//
// A type alias of ports.DynamicCredential (ADR-109 step 3) so every backend
// engine's Issue implementation below satisfies ports.DynamicBackendEngine
// directly, with no adapter.
type Credential = ports.DynamicCredential

// CredentialEngine mints and revokes credentials on a target backend. The admin
// connection string (adminDSN) is supplied per call so the engine holds no
// long-lived state or secrets.
//
// A type alias of ports.DynamicBackendEngine (ADR-109 step 3) — see that
// type's doc comment (internal/core/ports/ports.go) for what each method does;
// duplicated there rather than here since a type alias cannot carry its own
// doc comment distinct from the aliased type's declaration site.
type CredentialEngine = ports.DynamicBackendEngine

// New returns the engine for a backend type. allowPrivateNetwork mirrors
// KeyorixCore.dynamicAllowPrivateTargets (dynamic_secrets.allow_private_network_targets):
// when false (the default), an engine that dials the admin DSN itself
// (postgres, mysql, mongodb, redis) re-validates the resolved target address
// on every connection and refuses a private/link-local one — closing the
// DNS-rebinding gap a validate-once-at-config-time guard alone leaves open
// (G48). allowInsecureTransport mirrors
// KeyorixCore.dynamicAllowInsecureTransport
// (dynamic_secrets.allow_insecure_transport): when false (the default),
// mongodb/redis (the two backends here whose wire protocol has no
// bolted-on-elsewhere TLS enforcement of its own — Postgres/MySQL are
// pre-existing, verified-correct call sites out of this change's scope)
// refuse a connection that isn't using TLS. The cloud-IAM engines and
// Kubernetes (in-cluster/explicit api_server) don't dial an admin_dsn host
// the same way and ignore both parameters.
func New(backendType string, allowPrivateNetwork, allowInsecureTransport bool) (CredentialEngine, error) {
	switch backendType {
	case "postgres":
		return &PostgresEngine{allowPrivateNetwork: allowPrivateNetwork}, nil
	case "mysql":
		return &MySQLEngine{allowPrivateNetwork: allowPrivateNetwork}, nil
	case "mongodb":
		return &MongoEngine{allowPrivateNetwork: allowPrivateNetwork, allowInsecureTransport: allowInsecureTransport}, nil
	case "redis":
		return &RedisEngine{allowPrivateNetwork: allowPrivateNetwork, allowInsecureTransport: allowInsecureTransport}, nil
	case "aws-sts":
		return &AWSSTSEngine{}, nil
	case "gcp":
		return &GCPEngine{}, nil
	case "azure":
		return &AzureEngine{}, nil
	case "kubernetes":
		return &KubernetesEngine{}, nil
	default:
		return nil, fmt.Errorf("unsupported dynamic-secret backend %q (supported: postgres, mysql, mongodb, redis, aws-sts, gcp, azure, kubernetes)", backendType)
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

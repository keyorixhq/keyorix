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
	// IsEphemeralBackend reports whether the backend mints self-expiring
	// credentials (e.g. AWS STS) rather than a persistent role on a target. Renew
	// is refused for such backends — the credential's lifetime is fixed by the
	// cloud provider at issue, so a new lease must be issued instead of extending
	// an existing one. It does NOT by itself mean Revoke is a no-op: see
	// RevokeInvalidatesCredential.
	IsEphemeralBackend() bool
	// RevokeInvalidatesCredential reports whether calling Revoke for this specific
	// adminDSN actually invalidates the credential at the provider before its
	// natural expiry (true), or is only local Keyorix bookkeeping that leaves the
	// credential live until it self-expires (false). Persistent-role backends
	// (Postgres/MySQL/MongoDB/Redis) always return true — DROP/DELETE really
	// removes the account. Most cloud-IAM backends (AWS STS, Azure, GCP) always
	// return false — see each file's header comment for the provider-specific
	// reason a real revoke isn't safely automatable. Kubernetes returns true only
	// when the specific lease's adminDSN config opted into bound-token revocation
	// (see kubernetes.go); otherwise false. Callers use this to render an accurate
	// audit message instead of assuming every ephemeral backend is a no-op.
	RevokeInvalidatesCredential(adminDSN string) bool
}

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

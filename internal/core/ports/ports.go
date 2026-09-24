// Package ports defines the interfaces ADR-109
// (docs/adr-109-core-depends-on-interfaces.md) puts between internal/core and
// the integration packages it currently imports directly: internal/connect,
// internal/rotation, internal/dynamic, internal/encryption, internal/notary,
// internal/saml. Each interface here is modeled on the exact subset of
// methods internal/core already calls on today's concrete type — see the
// doc comment on each one for which type it mirrors and which core files
// call it.
//
// Nothing in internal/core is wired against these yet. Each ADR-109 "Order
// of work" step swaps one integration from its concrete package type to the
// interface here, and wires the real implementation from server/main.go
// instead — see internal/core's own dependency_guard_test.go, whose
// allowlist shrinks by one entry per completed step.
//
// This package must never import an integration package itself, or any of
// their cloud SDKs — that would silently defeat the whole point. See
// ports_deps_test.go.
package ports

import (
	"context"
	"net/http"
	"time"
)

// Connector reads a secret value from one external store. Mirrors
// internal/connect.Connector — internal/core.ReadFederatedSecret
// (connect.go) calls only these three methods on the value
// internal/connect.Manager.Get returns.
type Connector interface {
	Name() string
	Type() string
	GetSecret(ctx context.Context, ref string) (string, error)
}

// ConnectorResolver resolves a configured Keyorix Connect connector by name.
// Mirrors internal/connect.Manager, the only methods internal/core calls on
// it (connect.go, service.go).
type ConnectorResolver interface {
	Get(name string) (Connector, bool)
	Names() []string
}

// RotationExecutor applies a new credential to an upstream system during
// rotation. Mirrors internal/rotation.Executor.
type RotationExecutor interface {
	Name() string
	Type() string
	Rotate(ctx context.Context, ref, newValue string) error
}

// GeneratingRotationExecutor is a RotationExecutor whose upstream mints the
// new value itself (e.g. a cloud key API). Mirrors
// internal/rotation.GeneratingExecutor — rotation_executor.go type-asserts a
// resolved RotationExecutor against this to prefer GenerateUpstream over
// Rotate when the backend supports it.
type GeneratingRotationExecutor interface {
	RotationExecutor
	GenerateUpstream(ctx context.Context, ref string) (string, error)
}

// RotationExecutorResolver resolves a configured rotation backend by name.
// Mirrors internal/rotation.Manager, the only methods internal/core calls on
// it (rotation_executor.go, rotation_dryrun.go, service.go).
type RotationExecutorResolver interface {
	Get(name string) (RotationExecutor, bool)
	Names() []string
}

// DynamicCredential is an issued, short-lived credential returned to the
// caller once. Mirrors internal/dynamic.Credential.
type DynamicCredential struct {
	Username string
	Password string
	Fields   map[string]string
}

// DynamicBackendEngine mints and revokes credentials on a target backend.
// Mirrors internal/dynamic.CredentialEngine — the methods internal/core
// calls (dynamic_secrets.go).
type DynamicBackendEngine interface {
	Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (cred DynamicCredential, roleName string, err error)
	Revoke(ctx context.Context, adminDSN, roleName string) error
	Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) error
	SupportsNativeExpiry() bool
	BackendType() string
	IsEphemeralBackend() bool
}

// DynamicBackendFactory builds a DynamicBackendEngine for the named backend
// type. Mirrors the func(string) (dynamic.CredentialEngine, error) shape
// internal/core.dynamicEngineFactory already holds (service.go,
// SetDynamicEngineFactory) — backed by internal/dynamic.New in production.
type DynamicBackendFactory interface {
	Engine(backendType string) (DynamicBackendEngine, error)
}

// EncryptionProvider performs authenticated encryption/decryption for secret
// values and auth-flow secrets (MFA, dynamic-secret admin DSNs and leases).
// Mirrors internal/encryption.Service — the ONLY four methods internal/core
// calls on it, across secret_value_crypto.go, mfa.go, dynamic_secrets.go,
// secret_render.go and service.go's authEncryptor/secretValueEncryptor
// helpers. AAD is built by the caller (internal/encryption.SecretAAD and
// siblings today) and passed through opaquely — this interface has no
// opinion on how AAD is constructed.
type EncryptionProvider interface {
	IsEnabled() bool
	IsInitialized() bool
	EncryptSecretWithAAD(plaintext, aad []byte) (ciphertext, meta []byte, err error)
	DecryptSecretWithAAD(ciphertext, aad []byte) (plaintext []byte, err error)
}

// NotaryReceipt is proof an external timestamping authority anchored a
// message. Mirrors internal/notary.Receipt.
type NotaryReceipt struct {
	Token    []byte
	Time     time.Time
	Provider string
}

// TimestampNotary anchors a message with an external timestamping authority.
// Mirrors internal/notary.Notary — audit_checkpoint.go's checkpointNotary
// field. internal/notary.VerifyReceipt (a free function, not a method) has
// no SDK dependency of its own; it moves alongside this interface's wiring
// in the step that implements it, not represented here.
type TimestampNotary interface {
	Anchor(ctx context.Context, message []byte) (*NotaryReceipt, error)
	Provider() string
}

// SAMLAssertion is the parsed content of a SAML response Keyorix has
// verified. Mirrors internal/saml.AssertionInfo, the fields sso.go reads off
// it.
type SAMLAssertion struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// SAMLServiceProvider is a SAML Service Provider. Mirrors the shape
// internal/core/sso.go's own SAMLAuthn interface already has (it predates
// this package) — the only difference is ParseResponse returning
// *SAMLAssertion here instead of *internal/saml.AssertionInfo, which is what
// still forces sso.go to import internal/saml today. Once sso.go's SAML
// login path is rewritten against *SAMLAssertion (ADR-109 step 1),
// SAMLAuthn retires in favor of this type.
type SAMLServiceProvider interface {
	AuthnRequest(relayState string) (redirectURL, requestID string, err error)
	ParseResponse(r *http.Request, possibleRequestIDs []string) (*SAMLAssertion, error)
	Metadata() ([]byte, error)
}

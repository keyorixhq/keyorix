// Package ports defines the interfaces ADR-109
// (docs/adr-109-core-depends-on-interfaces.md) puts between internal/core and
// the integration packages it currently imports directly: internal/connect,
// internal/rotation, internal/dynamic, internal/encryption, internal/notary,
// internal/saml. Each interface here is modeled on the exact subset of
// methods internal/core already calls on today's concrete type — see the
// doc comment on each one for which type it mirrors and which core files
// call it.
//
// Each ADR-109 "Order of work" step swaps one integration from its concrete
// package type to the interface here, and wires the real implementation from
// server/main.go's DefaultIntegrations instead — see internal/core's own
// dependency_guard_test.go, whose allowlist shrinks by one entry per
// completed step. notary and saml are wired as of step 1, rotation as of
// step 2; dynamic, connect, and encryption are not wired yet.
//
// This package must never import an integration package itself, or any of
// their cloud SDKs — that would silently defeat the whole point. See
// ports_deps_test.go.
package ports

import (
	"context"
	"crypto/x509"
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
// rotation. A type alias of internal/rotation.Executor (ADR-109 step 2) — the
// alias lives on the internal/rotation side (see that package's doc comment)
// so every existing rotation.Executor implementation satisfies this directly,
// with no adapter.
type RotationExecutor interface {
	Name() string
	Type() string
	Rotate(ctx context.Context, ref, newValue string) error
}

// GeneratingRotationExecutor is a RotationExecutor whose upstream mints the
// new value itself (e.g. a cloud key API). Mirrors (and, as of ADR-109 step 2,
// aliased by) internal/rotation.GeneratingExecutor — rotation_executor.go
// type-asserts a resolved RotationExecutor against this to prefer
// GenerateUpstream over Rotate when the backend supports it.
type GeneratingRotationExecutor interface {
	RotationExecutor
	GenerateUpstream(ctx context.Context, ref string) (string, error)
}

// RotationExecutorResolver resolves a configured rotation backend by name.
// Mirrors internal/rotation.Manager (a concrete type, not aliased — only the
// element types it returns are), the only methods internal/core calls on it
// (rotation_executor.go, rotation_dryrun.go, service.go).
type RotationExecutorResolver interface {
	Get(name string) (RotationExecutor, bool)
	Names() []string
}

// RotationPartialError reports that a RotationExecutor's upstream minted a new
// credential (Value is the value to store in Keyorix) but a follow-up step
// failed — typically a prior, possibly compromised credential that could not
// be deleted. A type alias of internal/rotation.PartialRotationError (ADR-109
// step 2); its Error()/Unwrap() methods are declared here, alongside the
// canonical type, since a type alias cannot carry methods of its own —
// internal/rotation's own doc comment on PartialRotationError has the full
// rationale for why Value must still be stored.
type RotationPartialError struct {
	Value string
	Err   error
}

func (e *RotationPartialError) Error() string { return e.Err.Error() }
func (e *RotationPartialError) Unwrap() error { return e.Err }

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
// field. Receipt verification (internal/notary.VerifyReceipt) is a separate
// free function, not a TimestampNotary method — see VerifyReceiptFunc below.
type TimestampNotary interface {
	Anchor(ctx context.Context, message []byte) (*NotaryReceipt, error)
	Provider() string
}

// VerifyReceiptFunc re-checks a TimestampNotary receipt token against a trusted
// root pool and the original anchored message, returning the authority-asserted
// time. Mirrors internal/notary.VerifyReceipt exactly — it stays a free function,
// not a TimestampNotary method, since verifying a receipt depends only on the
// configured trust roots, not on which Notary produced it (see
// audit_checkpoint.go's VerifyCheckpointAnchor). Wired alongside TimestampNotary
// at startup (SetCheckpointAnchorRoots); nil means stored anchors cannot be
// locally re-verified — fails closed rather than asserting an unverifiable proof.
type VerifyReceiptFunc func(roots *x509.CertPool, message, token []byte) (time.Time, error)

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
// internal/core/sso.go's own SAMLAuthn used to have (it predates this
// package) — ADR-109 step 1 made SAMLAuthn a type alias of this interface,
// and internal/saml.AssertionInfo a type alias of SAMLAssertion, so
// *internal/saml.Provider satisfies this interface directly with no adapter.
type SAMLServiceProvider interface {
	AuthnRequest(relayState string) (redirectURL, requestID string, err error)
	ParseResponse(r *http.Request, possibleRequestIDs []string) (*SAMLAssertion, error)
	Metadata() ([]byte, error)
}

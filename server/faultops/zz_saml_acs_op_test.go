// zz_saml_acs_op_test.go wires the SAML Assertion Consumer Service into opCatalog:
// REST POST /auth/saml/{provider}/acs — the unauthenticated endpoint that consumes
// an IdP's signed SAMLResponse and mints a session (CompleteSAML). Left StatusPending
// because driving ParseResponse's real signature/audience/destination verification
// (not a stub, see server/http/handlers/saml_s13_test.go's own stub-based tests, which
// deliberately bypass that verification) needs a genuinely valid, cryptographically
// signed SAML Response — the same problem internal/saml/parse_response_success_test.go
// solves at the package-internal level by driving crewjam/saml's own IdP-side
// machinery directly. That builder (signedIDPFixture + the IdP-side assertion/response
// construction in TestParseResponse_Success) is unexported and test-only within
// internal/saml, so this PR moves the reusable parts into a new, deliberately
// non-"_test.go" package, internal/saml/samltest, importable from here. The one
// additional surface internal/saml itself needed (RawServiceProviderMetadata,
// testsupport.go) exposes the typed SP metadata (*Provider).Metadata() already
// returns as XML, needed to build a matching signed response — it does not touch
// ParseResponse's own signature/audience/destination checks in any way.
package faultops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	csaml "github.com/crewjam/saml"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/saml/samltest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	fuzzSAMLProviderName = "fuzzsaml"
	fuzzSAMLIdPEntityID  = "https://fuzz-idp.invalid/entity"
	fuzzSAMLSPEntityID   = "https://fuzz-world.invalid/saml/fuzzsaml/metadata"
	fuzzSAMLACSURL       = "https://fuzz-world.invalid/saml/fuzzsaml/acs"
)

// fuzzSAMLFixtureShared is a package-level, lazily-built self-signed IdP signing
// key/cert (RSA keygen via crypto/rand) — expensive, but entirely iteration-
// independent: a throwaway signing identity has nothing to do with any particular
// world's state, so it's generated ONCE per test binary run (sync.Once-guarded),
// not once per world/reset. Contrast with wireSAMLProvider below, which IS
// iteration-specific (wires into a *specific* core) and must re-run on every
// newWorldCore/newFaultWorld call.
var (
	fuzzSAMLFixtureOnce sync.Once
	fuzzSAMLFixture     *samltest.IdPFixture
	fuzzSAMLFixtureErr  error
)

func fuzzSAMLFixtureShared() (*samltest.IdPFixture, error) {
	fuzzSAMLFixtureOnce.Do(func() {
		fuzzSAMLFixture, fuzzSAMLFixtureErr = samltest.NewIdPFixture(fuzzSAMLIdPEntityID)
	})
	return fuzzSAMLFixture, fuzzSAMLFixtureErr
}

// fuzzSAMLProviderConfig returns the saml.Config shared by wireSAMLProvider and
// fuzzSAMLSPMetadata — kept in one place so the two never drift apart.
func fuzzSAMLProviderConfig(fixture *samltest.IdPFixture) saml.Config {
	return saml.Config{
		Name:              fuzzSAMLProviderName,
		IDPMetadataXML:    fixture.MetadataXML,
		SPEntityID:        fuzzSAMLSPEntityID,
		ACSURL:            fuzzSAMLACSURL,
		AllowIDPInitiated: true,
		// Match crewjam's DefaultAssertionMaker attribute FriendlyNames (the IdP-side
		// machinery samltest.SignedResponse drives) — same override
		// internal/saml/parse_response_success_test.go's TestParseResponse_Success
		// uses, and for the same reason: Config's own defaults are ADFS/Azure claim
		// URIs that DefaultAssertionMaker never emits, so without this override
		// extractAssertion finds no matching attribute and every op run would fail
		// resolveSSOUser/provisionSSOUser with "no email", never reaching
		// CompleteSAML's real session-minting logic at all.
		EmailAttr:  "mail",
		NameAttr:   "cn",
		GroupsAttr: "eduPersonAffiliation",
	}
}

// wireSAMLProvider builds a saml.Provider from the shared IdP fixture and wires it
// into core as the "fuzzsaml" SSO provider. Called unconditionally from
// newFaultWorld/newWorldCore (mirroring the unconditional SetWebAuthn call next to
// it) — core itself is rebuilt fresh every reset (see newWorldCore's own doc
// comment) and would otherwise have nil ssoProviders.
//
// AutoProvision + TrustAssertedEmail are both on: every Setup call asserts a
// fresh, unique subject/email (table-reset between iterations — see
// newWorldCore's doc comment), so each op run JIT-provisions a brand-new account
// rather than needing one pre-seeded to match against. This is a throwaway
// fuzz-world provider's config, not a change to any production default — #89's
// own ADR discussion of TrustAssertedEmail is about a REAL low-trust IdP being
// able to claim an EXISTING account, which doesn't apply here (AutoProvision
// always creates a new account; resolveSSOUser's claim-by-email path is never
// exercised because the email is always fresh).
func wireSAMLProvider(c *core.KeyorixCore) error {
	fixture, err := fuzzSAMLFixtureShared()
	if err != nil {
		return fmt.Errorf("fuzzSAMLFixtureShared: %w", err)
	}
	prov, err := saml.NewProvider(fuzzSAMLProviderConfig(fixture))
	if err != nil {
		return fmt.Errorf("saml.NewProvider: %w", err)
	}
	c.SetSSOProviders(map[string]*core.SSOProvider{
		fuzzSAMLProviderName: {
			Name: fuzzSAMLProviderName, Type: "saml", SAML: prov,
			AutoProvision: true, TrustAssertedEmail: true,
			CompleteURL: "https://fuzz-world.invalid/sso/complete",
		},
	}, nil)
	return nil
}

// fuzzSAMLSPMetadata rebuilds the SP metadata used to sign a matching Response.
// A second, throwaway saml.Provider built from the identical Config
// wireSAMLProvider wired into core — cheap (XML parse of a small embedded
// metadata string, no RSA) — rather than threading the real provider's metadata
// through the faultWorld struct.
func fuzzSAMLSPMetadata() (*csaml.EntityDescriptor, error) {
	fixture, err := fuzzSAMLFixtureShared()
	if err != nil {
		return nil, fmt.Errorf("fuzzSAMLFixtureShared: %w", err)
	}
	prov, err := saml.NewProvider(fuzzSAMLProviderConfig(fixture))
	if err != nil {
		return nil, fmt.Errorf("saml.NewProvider: %w", err)
	}
	return prov.RawServiceProviderMetadata(), nil
}

func randFuzzSAMLToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type samlFuzzState struct {
	relayState      string
	samlResponseB64 string
}

// The zz_ file-name prefix is load-bearing: Go runs a package's init()s in
// file-name order, and fuzz seeds address ops by opCatalog INDEX. Appending this
// op after webauthn_finish_ops_test.go's init keeps every existing committed
// seed pointing at the same op it was recorded against.
func init() {
	opCatalog = append(opCatalog, operation{
		Key: "REST POST /auth/saml/{provider}/acs",
		Setup: func(ctx context.Context, w *faultWorld) (any, error) {
			relayState, err := randFuzzSAMLToken()
			if err != nil {
				return nil, fmt.Errorf("setup randFuzzSAMLToken: %w", err)
			}
			// Register a provider + matching SSOLoginState directly via storage: the
			// real BeginSAML endpoint would mint its own RelayState/request ID and
			// redirect to an unreachable fake IdP URL, so Setup supplies the
			// prerequisite login-state row the same way enrolMFADirect/
			// storeFuzzWebAuthnSession supply THEIR prerequisite state (real, just not
			// through the full redirect round trip).
			if err := w.db.Create(&models.SSOLoginState{
				State:     relayState,
				Provider:  fuzzSAMLProviderName,
				ExpiresAt: time.Now().Add(10 * time.Minute),
				CreatedAt: time.Now(),
			}).Error; err != nil {
				return nil, fmt.Errorf("setup create SSOLoginState: %w", err)
			}
			fixture, err := fuzzSAMLFixtureShared()
			if err != nil {
				return nil, fmt.Errorf("setup fuzzSAMLFixtureShared: %w", err)
			}
			spMetadata, err := fuzzSAMLSPMetadata()
			if err != nil {
				return nil, fmt.Errorf("setup fuzzSAMLSPMetadata: %w", err)
			}
			subject := "fuzz-saml-" + relayState[:8]
			resp, err := samltest.SignedResponse(fixture, fuzzSAMLIdPEntityID, spMetadata,
				subject, subject+"@fuzz-saml.example", "Fuzz SAML User", nil, relayState)
			if err != nil {
				return nil, fmt.Errorf("setup samltest.SignedResponse: %w", err)
			}
			return samlFuzzState{relayState: relayState, samlResponseB64: resp}, nil
		},
		Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			st := state.(samlFuzzState)
			body := url.Values{"SAMLResponse": {st.samlResponseB64}, "RelayState": {st.relayState}}.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost,
				w.httpServer.URL+"/auth/saml/"+fuzzSAMLProviderName+"/acs", strings.NewReader(body))
			if err != nil {
				return opResult{}, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// CompleteSAML always 302s to the SPA completion page regardless of outcome
			// (error vs success is signaled in the URL FRAGMENT, not the status code —
			// mirrors CompleteSSO's identical redirectFragment pattern), and the
			// completion page itself ("fuzz-world.invalid") isn't dialable — a default
			// http.Client would chase the redirect and fail with a connection error.
			// CheckRedirect stops at the first response so the real Location/status can
			// be inspected directly.
			client := &http.Client{
				Timeout:       10 * time.Second,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			}
			resp, err := client.Do(req)
			if err != nil {
				return opResult{}, err
			}
			defer func() { _ = resp.Body.Close() }()
			loc := resp.Header.Get("Location")
			success := resp.StatusCode == http.StatusFound && loc != "" && !strings.Contains(loc, "error=")
			return opResult{Success: success, Detail: fmt.Sprintf("HTTP %d Location=%s", resp.StatusCode, loc)}, nil
		},
	})
}

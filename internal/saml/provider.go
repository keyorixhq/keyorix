// Package saml implements a SAML 2.0 Service Provider (SP) core for Keyorix human SSO
// (ADR-063). It is a thin, safe wrapper over the vetted crewjam/saml + goxmldsig stack:
// the dangerous XML-DSig validation (signature, audience, recipient, time, InResponseTo,
// replay) is delegated to the library on purpose — SAML signature handling must never be
// hand-rolled. This package owns provider construction, SP metadata, the SP-initiated
// AuthnRequest, and mapping a validated assertion to (subject, email, name, groups).
//
// It has no callers yet; the HTTP routes and the SSO-provider wiring that turn a parsed
// assertion into a Keyorix session are a separate step (Phase 1b), so adding this package
// is no behaviour change.
package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	csaml "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// Default attribute names (used when a Config field is empty). These cover the common
// Azure AD / ADFS claim URIs; operators override per IdP.
const (
	defaultEmailAttr  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	defaultNameAttr   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname"
	defaultGroupsAttr = "http://schemas.xmlsoap.org/claims/Group"
)

// Config configures one SAML provider (one IdP).
type Config struct {
	Name string
	// IDPMetadataXML is the IdP's SAML metadata (entityID, SSO URL, signing certificate).
	IDPMetadataXML []byte
	// SPEntityID is our SP entity ID (conventionally the metadata URL).
	SPEntityID string
	// ACSURL is our Assertion Consumer Service URL (where the IdP POSTs the response).
	ACSURL string
	// AllowIDPInitiated permits responses with no InResponseTo. Off by default — it loses
	// CSRF/replay protection — enable only for IdPs that require it.
	AllowIDPInitiated bool
	// Attribute names to read from the assertion (empty → the defaults above).
	EmailAttr, NameAttr, GroupsAttr string
}

// Provider is a configured SAML Service Provider for one IdP.
type Provider struct {
	name                            string
	sp                              *csaml.ServiceProvider
	emailAttr, nameAttr, groupsAttr string
}

// AssertionInfo is the identity extracted from a validated assertion.
type AssertionInfo struct {
	Subject string // the NameID
	Email   string
	Name    string
	Groups  []string
}

// NewProvider builds a Provider from config, parsing the IdP metadata.
func NewProvider(cfg Config) (*Provider, error) {
	if strings.TrimSpace(cfg.ACSURL) == "" {
		return nil, errors.New("saml: acs_url is required")
	}
	if strings.TrimSpace(cfg.SPEntityID) == "" {
		return nil, errors.New("saml: sp_entity_id is required")
	}
	acs, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid acs_url: %w", err)
	}
	meta, err := url.Parse(cfg.SPEntityID)
	if err != nil {
		return nil, fmt.Errorf("saml: invalid sp_entity_id: %w", err)
	}
	idp, err := parseIDPMetadata(cfg.IDPMetadataXML)
	if err != nil {
		return nil, fmt.Errorf("saml: parse idp metadata: %w", err)
	}

	sp := &csaml.ServiceProvider{
		EntityID:          cfg.SPEntityID,
		MetadataURL:       *meta,
		AcsURL:            *acs,
		IDPMetadata:       idp,
		AllowIDPInitiated: cfg.AllowIDPInitiated,
	}
	return &Provider{
		name:       cfg.Name,
		sp:         sp,
		emailAttr:  orDefault(cfg.EmailAttr, defaultEmailAttr),
		nameAttr:   orDefault(cfg.NameAttr, defaultNameAttr),
		groupsAttr: orDefault(cfg.GroupsAttr, defaultGroupsAttr),
	}, nil
}

// Name returns the provider name.
func (p *Provider) Name() string { return p.name }

// Metadata returns this SP's SAML metadata XML — hand it to the IdP administrator.
func (p *Provider) Metadata() ([]byte, error) {
	out, err := xml.MarshalIndent(p.sp.Metadata(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return out, nil
}

// AuthnRequest builds an SP-initiated authentication request: it returns the IdP redirect
// URL (HTTP-Redirect binding) and the request ID to remember for InResponseTo matching.
func (p *Provider) AuthnRequest(relayState string) (redirectURL, requestID string, err error) {
	ssoURL := p.sp.GetSSOBindingLocation(csaml.HTTPRedirectBinding)
	if ssoURL == "" {
		return "", "", errors.New("saml: IdP has no HTTP-Redirect SSO binding")
	}
	req, err := p.sp.MakeAuthenticationRequest(ssoURL, csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("saml: build authn request: %w", err)
	}
	u, err := req.Redirect(relayState, p.sp)
	if err != nil {
		return "", "", fmt.Errorf("saml: build redirect: %w", err)
	}
	return u.String(), req.ID, nil
}

// ParseResponse validates the SAMLResponse on r (signature against the pinned IdP
// certificate, audience, recipient, time window, and — for SP-initiated — InResponseTo
// against possibleRequestIDs) via the vetted library, then maps the assertion to an
// AssertionInfo. A validation failure is returned as an error; nothing is trusted from an
// unvalidated response.
func (p *Provider) ParseResponse(r *http.Request, possibleRequestIDs []string) (*AssertionInfo, error) {
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		// Unwrap the library's detailed (private) error for logs without leaking it to
		// the caller's surface.
		var ire *csaml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, fmt.Errorf("saml: invalid response: %w", ire.PrivateErr)
		}
		return nil, fmt.Errorf("saml: invalid response: %w", err)
	}
	return extractAssertion(assertion, p.emailAttr, p.nameAttr, p.groupsAttr), nil
}

// extractAssertion maps a validated assertion to identity fields. Split out so the
// mapping is unit-tested without needing a signed response.
func extractAssertion(a *csaml.Assertion, emailAttr, nameAttr, groupsAttr string) *AssertionInfo {
	info := &AssertionInfo{}
	if a.Subject != nil && a.Subject.NameID != nil {
		info.Subject = a.Subject.NameID.Value
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			vals := attributeValues(attr)
			if len(vals) == 0 {
				continue
			}
			switch {
			case attrMatches(attr, emailAttr):
				info.Email = vals[0]
			case attrMatches(attr, nameAttr):
				info.Name = vals[0]
			case attrMatches(attr, groupsAttr):
				info.Groups = append(info.Groups, vals...)
			}
		}
	}
	return info
}

// attrMatches reports whether the attribute is the one named by want (by Name or
// FriendlyName, case-insensitive on FriendlyName).
func attrMatches(attr csaml.Attribute, want string) bool {
	return attr.Name == want || strings.EqualFold(attr.FriendlyName, want)
}

// attributeValues returns the non-empty string values of an attribute.
func attributeValues(attr csaml.Attribute) []string {
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if s := strings.TrimSpace(v.Value); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// parseIDPMetadata parses IdP SAML metadata, accepting either a single EntityDescriptor
// or an EntitiesDescriptor wrapper (picking the entity that has an IDPSSODescriptor). It
// runs the XML round-trip validator first (defence against XML parser quirks), mirroring
// crewjam's samlsp.ParseMetadata without pulling that package's heavier dependencies.
func parseIDPMetadata(data []byte) (*csaml.EntityDescriptor, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty metadata")
	}
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("metadata failed XML validation: %w", err)
	}
	entity := &csaml.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err != nil && strings.Contains(err.Error(), "EntitiesDescriptor") {
		entities := &csaml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		for i := range entities.EntityDescriptors {
			if len(entities.EntityDescriptors[i].IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no IDPSSODescriptor in metadata")
	}
	if err != nil {
		return nil, err
	}
	if len(entity.IDPSSODescriptors) == 0 {
		return nil, errors.New("metadata has no IDPSSODescriptor")
	}
	return entity, nil
}

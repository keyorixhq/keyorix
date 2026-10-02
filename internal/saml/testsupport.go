package saml

import csaml "github.com/crewjam/saml"

// RawServiceProviderMetadata returns the typed SP metadata csaml.ServiceProvider.Metadata()
// produces. Exported ONLY so a cross-package test fixture (internal/saml/samltest,
// used by server/faultops' real-transport fuzz harness) can build a matching signed
// IdP-side Response to drive ParseResponse's real verification path — no production
// code should need this; (*Provider).Metadata() (the XML-marshaled form served at the
// SP metadata route) is the one callers outside tests should use.
func (p *Provider) RawServiceProviderMetadata() *csaml.EntityDescriptor {
	return p.sp.Metadata()
}

package saml

import (
	"testing"
)

// minimalIDPMetadata is a structurally valid SAML IdP metadata document with no signing
// certificate — a useful fuzzer seed because it exercises the full parse path without
// requiring real crypto material in the seed corpus.
var minimalIDPMetadata = []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

// FuzzSAMLMetadata feeds arbitrary bytes as IdP metadata XML into NewProvider.
// The target is the XML parsing + entity-descriptor unmarshalling path inside
// parseIDPMetadata — historically the most fuzz-productive surface in SAML stacks
// (XXE, entity-expansion, malformed attribute names). NewProvider must never panic;
// returning an error for any malformed input is the only acceptable outcome.
func FuzzSAMLMetadata(f *testing.F) {
	f.Add(minimalIDPMetadata)
	f.Add([]byte(""))
	f.Add([]byte("<foo/>"))
	f.Add([]byte("not xml at all"))
	f.Add([]byte(`<?xml version="1.0"?><EntityDescriptor/>`))
	f.Add([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID=""><IDPSSODescriptor/></EntityDescriptor>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Config{
			Name:           "fuzz",
			IDPMetadataXML: data,
			SPEntityID:     "https://keyorix.internal/saml/fuzz/metadata",
			ACSURL:         "https://keyorix.internal/auth/saml/fuzz/acs",
		}
		// Must never panic.
		_, _ = NewProvider(cfg)
	})
}

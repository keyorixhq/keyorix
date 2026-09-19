package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	csaml "github.com/crewjam/saml"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// minimalIDPMetadata is a structurally valid SAML IdP metadata document with no signing
// certificate — a useful fuzzer seed because it exercises the full parse path without
// requiring real crypto material in the seed corpus.
var minimalIDPMetadata = []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

// twoDescriptorsSecondValidUntilInvalid is a structurally valid SAML IdP metadata
// document (passes xrv validation) with TWO IDPSSODescriptor elements: the first
// complete and well-formed, the second carrying a malformed `validUntil` attribute
// (IDPSSODescriptor embeds RoleDescriptor, which has its own validUntil/
// cacheDuration attrs distinct from EntityDescriptor's root-level ones).
//
// Go's encoding/xml processes repeated elements one at a time, appending each to
// the slice as it succeeds — confirmed empirically: by the time the SECOND
// element's validUntil attribute fails to parse, the FIRST descriptor is already
// appended to EntityDescriptor.IDPSSODescriptors (len==1, not 0), even though
// xml.Unmarshal's overall call returns a non-nil error. A single malformed
// root-level validUntil/cacheDuration (attributes, processed before ANY child
// element) does NOT reproduce this — it leaves IDPSSODescriptors at len==0, which
// both correct code and the mutant below reject (via different error messages),
// so it does not distinguish them. This two-descriptor shape is the seed that
// actually does: it is exactly what makes parseIDPMetadata's own fallback check
// (`len(entity.IDPSSODescriptors) == 0`) evaluate to FALSE despite the real parse
// having failed — the precise condition under which dropping the
// `if err != nil { return nil, err }` guard right after xml.Unmarshal (rather than
// falling through to that fallback check) silently returns the partially-populated
// entity as if parsing had succeeded.
var twoDescriptorsSecondValidUntilInvalid = []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" validUntil="not-a-valid-time">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

// FuzzSAMLMetadata feeds arbitrary bytes as IdP metadata XML into NewProvider.
// The target is the XML parsing + entity-descriptor unmarshalling path inside
// parseIDPMetadata — historically the most fuzz-productive surface in SAML stacks
// (XXE, entity-expansion, malformed attribute names). NewProvider must never panic;
// returning an error for any malformed input is the only acceptable outcome.
//
// REJECTION ORACLE (added 2026-09): a plain "NewProvider must return an error"
// check does not distinguish every malformed-metadata mutation -- some malformed
// inputs make BOTH correct code and a dropped-error-guard mutant return an error
// (just a different, less specific one), so a naive presence-of-error check passes
// either way. The oracle below is the STRONGER property that does distinguish
// them: for any input where a strict xml.Unmarshal into EntityDescriptor fails for
// a reason OTHER than needing the EntitiesDescriptor-wrapper fallback,
// parseIDPMetadata must ALSO fail -- it must never silently return a
// partially-populated entity as success. See twoDescriptorsSecondValidUntilInvalid
// for the seed that actually exercises the distinguishing case.
func FuzzSAMLMetadata(f *testing.F) {
	f.Add(minimalIDPMetadata)
	f.Add([]byte(""))
	f.Add([]byte("<foo/>"))
	f.Add([]byte("not xml at all"))
	f.Add([]byte(`<?xml version="1.0"?><EntityDescriptor/>`))
	f.Add([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID=""><IDPSSODescriptor/></EntityDescriptor>`))
	f.Add(twoDescriptorsSecondValidUntilInvalid)

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := Config{
			Name:           "fuzz",
			IDPMetadataXML: data,
			SPEntityID:     "https://keyorix.internal/saml/fuzz/metadata",
			ACSURL:         "https://keyorix.internal/auth/saml/fuzz/acs",
		}
		fuzzutil.Guard(t.Fatalf, "saml.NewProvider", func() { _, _ = NewProvider(cfg) })

		// Ground truth, independent of parseIDPMetadata: mirror its own first
		// xml.Unmarshal call directly. Safe to run unguarded here -- Guard above
		// already ran the SAME underlying xml.Unmarshal (inside NewProvider ->
		// parseIDPMetadata) on this exact input without the process crashing, so a
		// panic here would already have happened there first.
		ground := &csaml.EntityDescriptor{}
		rawErr := xml.Unmarshal(data, ground)
		if rawErr == nil || strings.Contains(rawErr.Error(), "EntitiesDescriptor") {
			return
		}
		if _, parseErr := parseIDPMetadata(data); parseErr == nil {
			t.Fatalf("REJECTION ORACLE: parseIDPMetadata succeeded despite a strict xml.Unmarshal into EntityDescriptor failing (not the EntitiesDescriptor-fallback case) -- ground truth error: %v", rawErr)
		}
	})
}

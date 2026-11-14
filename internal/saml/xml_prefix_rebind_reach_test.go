package saml

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	csaml "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// TestXMLPrefixRebindPassesBothRoundTripValidators is the reachability half of finding
// LF1-XRV-xml-prefix-rebind (internal/libconformance/xrv_findings_test.go): a document
// that rebinds the reserved xml prefix (xmlns:xml="urn:evil"), which encoding/xml and
// etree resolve differently, passes BOTH round-trip validators keyorix's SAML code
// runs:
//
//   - mattermost/xml-roundtrip-validator, which parseIDPMetadata runs on the
//     operator-supplied IdP metadata (read afterwards by xml.Unmarshal only);
//   - crewjam/saml's own internal/xmlroundtrip, which ParseXMLResponse runs on the
//     POSTed SAMLResponse at the unauthenticated ACS before etree parsing and signature
//     verification. A rejection there surfaces as "invalid xml"; this input gets past it
//     and fails later, at unmarshalling, for not being a Response.
//
// The test goes red when either validator starts rejecting the rebind.
//
// What this does NOT verify: that the rebind changes what keyorix authenticates. No
// exploit is claimed: an attacker cannot alter the IdP-signed element, and crewjam
// re-reads the verified element with encoding/xml, which never maps xml: onto a SAML
// namespace. FuzzParseResponseXSW is where an end-to-end wrapping attack would show.
func TestXMLPrefixRebindPassesBothRoundTripValidators(t *testing.T) {
	doc := []byte(`<a xmlns:xml="urn:evil"><xml:b/></a>`)
	if err := xrv.Validate(strings.NewReader(string(doc))); err != nil {
		t.Fatalf("mattermost xrv now rejects the rebind: %v", err)
	}
	sp := csaml.ServiceProvider{}
	_, err := sp.ParseXMLResponse(doc, nil, url.URL{})
	ire, ok := errors.AsType[*csaml.InvalidResponseError](err)
	if !ok {
		t.Fatalf("ParseXMLResponse error %v is not an InvalidResponseError", err)
	}
	if msg := ire.PrivateErr.Error(); strings.HasPrefix(msg, "invalid xml") {
		t.Fatalf("crewjam's round-trip validator now rejects the rebind: %s", msg)
	}
	// Calibration: the same check does see a validator rejection.
	_, err = sp.ParseXMLResponse([]byte(`<x::Root/>`), nil, url.URL{})
	if ire, ok := errors.AsType[*csaml.InvalidResponseError](err); !ok || !strings.HasPrefix(ire.PrivateErr.Error(), "invalid xml") {
		t.Fatalf("calibration: a malformed document did not fail as invalid xml: %v", err)
	}
}

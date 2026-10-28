package cryptoinventory

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"
)

// maxSAMLMetadataCerts bounds how many signing certificates one IdP metadata
// document contributes. SAMLSigningCertificates reports when the trusted
// descriptor holds more.
const maxSAMLMetadataCerts = 8

// SAMLSigningCertificates returns the certificates in IdP metadata that Keyorix
// trusts to verify a SAML response, selected the way internal/saml's
// parseIDPMetadata and crewjam's signature check select them:
//
//   - the entity: the root EntityDescriptor, or under an EntitiesDescriptor root
//     the first child EntityDescriptor that has an IDPSSODescriptor;
//   - in that entity, every IDPSSODescriptor's KeyDescriptor whose use is
//     "signing" or unspecified, every KeyInfo/X509Data/X509Certificate in it.
//
// SPSSODescriptor, RoleDescriptor and other entities' keys are not trusted and
// are not returned. At most maxSAMLMetadataCerts certificates are returned; more
// is true when the trusted descriptor holds further ones. Elements are matched by
// local name only (the namespace is not checked). The certificates are public;
// Keyorix holds no SAML private key of its own. The parse is a token walk over
// the XML, independent of the SAML library, and echoes no metadata content in
// errors.
func SAMLSigningCertificates(metadata []byte) (certs []CertInfo, more bool, err error) {
	dec := xml.NewDecoder(bytes.NewReader(metadata))
	var stack []string
	// entityDepth is the stack depth of the candidate EntityDescriptor (0: none).
	var entityDepth int
	var hasIDP, inSigningKey, inCert bool
	var b64 strings.Builder
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, errors.New("metadata is not well-formed XML")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			d := len(stack)
			switch {
			case d == 1 && t.Name.Local != "EntityDescriptor" && t.Name.Local != "EntitiesDescriptor":
				return nil, false, errors.New("metadata has no EntityDescriptor")
			case t.Name.Local == "EntityDescriptor" && (d == 1 || (d == 2 && stack[0] == "EntitiesDescriptor")):
				entityDepth, hasIDP, certs, more = d, false, nil, false
			case entityDepth > 0 && d == entityDepth+1 && t.Name.Local == "IDPSSODescriptor":
				hasIDP = true
			case entityDepth > 0 && d == entityDepth+2 && t.Name.Local == "KeyDescriptor" && stack[d-2] == "IDPSSODescriptor":
				inSigningKey = true
				for _, a := range t.Attr {
					if a.Name.Local == "use" && a.Value != "" && a.Value != "signing" {
						inSigningKey = false
					}
				}
			case inSigningKey && d == entityDepth+5 && slices.Equal(stack[d-3:], []string{"KeyInfo", "X509Data", "X509Certificate"}):
				inCert = true
				b64.Reset()
			}
		case xml.CharData:
			if inCert {
				b64.Write(t)
			}
		case xml.EndElement:
			d := len(stack)
			switch {
			case inCert && t.Name.Local == "X509Certificate":
				inCert = false
				if len(certs) == maxSAMLMetadataCerts {
					more = true
					break
				}
				ci, err := samlCertInfo(b64.String())
				if err != nil {
					return nil, false, err
				}
				certs = append(certs, ci)
			case inSigningKey && t.Name.Local == "KeyDescriptor" && d == entityDepth+2:
				inSigningKey = false
			case d == entityDepth && t.Name.Local == "EntityDescriptor":
				if hasIDP {
					// The entity parseIDPMetadata selects: later entities are not trusted.
					if len(certs) == 0 {
						return nil, false, errors.New("metadata has no signing certificate")
					}
					return certs, more, nil
				}
				entityDepth, certs, more = 0, nil, false
			}
			stack = stack[:d-1]
		}
	}
	return nil, false, errors.New("metadata has no IDPSSODescriptor")
}

func samlCertInfo(b64 string) (CertInfo, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return CertInfo{}, errors.New("metadata certificate is not valid base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertInfo{}, errors.New("metadata certificate is not a valid X.509 certificate")
	}
	return certInfo(cert), nil
}

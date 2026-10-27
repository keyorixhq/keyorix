package cryptoinventory

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// maxSAMLMetadataCerts bounds how many signing certificates one IdP metadata
// document contributes (a federation metadata file lists many entities).
const maxSAMLMetadataCerts = 8

// SAMLSigningCertificates returns the certificates in IdP metadata that Keyorix
// would trust to verify a SAML response: every KeyDescriptor whose use is
// "signing" or unspecified (an unspecified key serves both purposes). The
// certificates are public; Keyorix holds no SAML private key of its own. The
// parse is a token walk over the XML, independent of the SAML library, and
// echoes no metadata content in errors.
func SAMLSigningCertificates(metadata []byte) ([]CertInfo, error) {
	dec := xml.NewDecoder(bytes.NewReader(metadata))
	var out []CertInfo
	var inSigningKey, inCert bool
	var b64 strings.Builder
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("metadata is not well-formed XML")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "KeyDescriptor":
				inSigningKey = true
				for _, a := range t.Attr {
					if a.Name.Local == "use" && a.Value == "encryption" {
						inSigningKey = false
					}
				}
			case "X509Certificate":
				if inSigningKey {
					inCert = true
					b64.Reset()
				}
			}
		case xml.CharData:
			if inCert {
				b64.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "KeyDescriptor":
				inSigningKey = false
			case "X509Certificate":
				if !inCert {
					continue
				}
				inCert = false
				ci, err := samlCertInfo(b64.String())
				if err != nil {
					return nil, err
				}
				out = append(out, ci)
				if len(out) >= maxSAMLMetadataCerts {
					return out, nil
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("metadata has no signing certificate")
	}
	return out, nil
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

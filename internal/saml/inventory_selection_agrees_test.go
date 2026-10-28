package saml

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/cryptoinventory"
)

// trustedSigningSubjects is what this package verifies a response with:
// parseIDPMetadata's entity, then crewjam's ServiceProvider.getIDPSigningCerts
// rule (every IDPSSODescriptor, KeyDescriptor use "signing" or unset).
func trustedSigningSubjects(t *testing.T, md []byte) ([]string, error) {
	t.Helper()
	idp, err := parseIDPMetadata(md)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range idp.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, c := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Data), ""))
				require.NoError(t, err)
				cert, err := x509.ParseCertificate(der)
				require.NoError(t, err)
				out = append(out, cert.Subject.String())
			}
		}
	}
	return out, nil
}

// TestCryptoInventorySAMLSelection_AgreesWithTrustedCerts is the drift guard for
// cryptoinventory.SAMLSigningCertificates, which selects the trusted IdP signing
// certificates with its own token walk (it does not link this package): for
// each metadata shape the certificates it inventories are exactly the ones this
// package trusts. It covers SP and role descriptor keys, several entities under
// an EntitiesDescriptor, several IDPSSODescriptors, use values and an entity
// with no IDPSSODescriptor; it does not cover namespace mismatches (the walk
// matches local names only) or documents over the inventory's cap.
func TestCryptoInventorySAMLSelection_AgreesWithTrustedCerts(t *testing.T) {
	kd := func(use, cn string) string {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		require.NoError(t, err)
		attr := ""
		if use != "" {
			attr = fmt.Sprintf(` use="%s"`, use)
		}
		return fmt.Sprintf(`<md:KeyDescriptor%s><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
			attr, base64.StdEncoding.EncodeToString(der))
	}
	const ns = `xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	sso := `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/>`
	idpDesc := func(keys ...string) string {
		return `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			strings.Join(keys, "") + sso + `</md:IDPSSODescriptor>`
	}
	spDesc := func(keys ...string) string {
		return `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			strings.Join(keys, "") + `</md:SPSSODescriptor>`
	}
	entity := func(id string, body ...string) string {
		return `<md:EntityDescriptor entityID="` + id + `">` + strings.Join(body, "") + `</md:EntityDescriptor>`
	}
	root := func(id string, body ...string) string {
		return `<md:EntityDescriptor ` + ns + ` entityID="` + id + `">` + strings.Join(body, "") + `</md:EntityDescriptor>`
	}
	entities := func(body ...string) string {
		return `<md:EntitiesDescriptor ` + ns + `>` + strings.Join(body, "") + `</md:EntitiesDescriptor>`
	}

	corpus := map[string]string{
		"single":            root("https://idp/", idpDesc(kd("signing", "s1"))),
		"use-unset":         root("https://idp/", idpDesc(kd("", "u1"), kd("encryption", "e1"), kd("other", "o1"))),
		"sp-descriptor-key": root("https://idp/", spDesc(kd("signing", "sp1")), idpDesc(kd("signing", "s1"))),
		"two-idp-descriptors": root("https://idp/", idpDesc(kd("signing", "a")),
			idpDesc(kd("signing", "b"))),
		"federation": entities(entity("https://sp/", spDesc(kd("signing", "sp1"), kd("signing", "sp2"))),
			entity("https://idp1/", idpDesc(kd("signing", "idp1"))),
			entity("https://idp2/", idpDesc(kd("signing", "idp2")))),
		"no-idp-descriptor": root("https://sp/", spDesc(kd("signing", "sp1"))),
		"federation-no-idp": entities(entity("https://sp/", spDesc(kd("signing", "sp1")))),
	}
	for name, md := range corpus {
		t.Run(name, func(t *testing.T) {
			want, wantErr := trustedSigningSubjects(t, []byte(md))
			infos, more, err := cryptoinventory.SAMLSigningCertificates([]byte(md))
			if wantErr != nil {
				require.Error(t, err, "metadata this package rejects (%v) has no trusted certificate to inventory", wantErr)
				return
			}
			require.NoError(t, err)
			assert.False(t, more)
			var got []string
			for _, ci := range infos {
				got = append(got, ci.SubjectName)
			}
			assert.Equal(t, want, got)
		})
	}
}

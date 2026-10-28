package cryptoinventory

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// namedCertDER is a real self-signed Ed25519 certificate whose subject CN is cn,
// so a test can tell which certificate an asset came from.
func namedCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: riskNow.Add(-time.Hour), NotAfter: riskNow.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	return der
}

// keyDescriptor is a KeyDescriptor carrying a certificate with subject CN cn; an
// empty use leaves the attribute out.
func keyDescriptor(t *testing.T, use, cn string) string {
	t.Helper()
	attr := ""
	if use != "" {
		attr = fmt.Sprintf(` use="%s"`, use)
	}
	return fmt.Sprintf(`<KeyDescriptor%s><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>`,
		attr, base64.StdEncoding.EncodeToString(namedCertDER(t, cn)))
}

const mdNS = `xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`

func samlSubjects(t *testing.T, inv Inventory) []string {
	t.Helper()
	var out []string
	for _, a := range inv.Assets {
		require.Equal(t, ClassSAMLCertificate, a.Class)
		require.NotNil(t, a.Certificate)
		out = append(out, a.Certificate.SubjectName)
	}
	return out
}

// TestBuild_SAMLOnlyTheIDPDescriptorKeyorixTrusts: internal/saml's
// parseIDPMetadata keeps the root EntityDescriptor (or, under an
// EntitiesDescriptor, the first entity with an IDPSSODescriptor), and the
// response signature is checked only against that entity's IDPSSODescriptor
// signing keys. SP, role and other entities' keys are not trusted, so they are
// not inventoried, and they cannot crowd the trusted key out of the cap.
func TestBuild_SAMLOnlyTheIDPDescriptorKeyorixTrusts(t *testing.T) {
	many := func(use, prefix string, n int) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(keyDescriptor(t, use, fmt.Sprintf("%s-%d", prefix, i)))
		}
		return b.String()
	}
	cases := map[string]struct {
		md   string
		want []string
	}{
		"sp-and-role-descriptors-skipped": {
			md: `<EntityDescriptor ` + mdNS + ` entityID="https://idp/">` +
				`<RoleDescriptor>` + keyDescriptor(t, "signing", "role") + `</RoleDescriptor>` +
				`<SPSSODescriptor>` + keyDescriptor(t, "signing", "sp") + `</SPSSODescriptor>` +
				`<IDPSSODescriptor>` + keyDescriptor(t, "", "idp-unspecified") + keyDescriptor(t, "signing", "idp-signing") +
				keyDescriptor(t, "encryption", "idp-enc") + keyDescriptor(t, "other", "idp-other") + `</IDPSSODescriptor>` +
				`</EntityDescriptor>`,
			want: []string{"CN=idp-unspecified", "CN=idp-signing"},
		},
		"first-entity-with-an-idp-descriptor": {
			md: `<EntitiesDescriptor ` + mdNS + `>` +
				`<EntityDescriptor entityID="https://sp/"><SPSSODescriptor>` + many("signing", "sp", maxSAMLMetadataCerts+1) + `</SPSSODescriptor></EntityDescriptor>` +
				`<EntityDescriptor entityID="https://idp1/"><IDPSSODescriptor>` + keyDescriptor(t, "signing", "idp1") + `</IDPSSODescriptor></EntityDescriptor>` +
				`<EntityDescriptor entityID="https://idp2/"><IDPSSODescriptor>` + keyDescriptor(t, "signing", "idp2") + `</IDPSSODescriptor></EntityDescriptor>` +
				`</EntitiesDescriptor>`,
			want: []string{"CN=idp1"},
		},
		"every-idp-descriptor-of-the-entity": {
			md: `<EntityDescriptor ` + mdNS + ` entityID="https://idp/">` +
				`<IDPSSODescriptor>` + keyDescriptor(t, "signing", "a") + `</IDPSSODescriptor>` +
				`<IDPSSODescriptor>` + keyDescriptor(t, "signing", "b") + `</IDPSSODescriptor>` +
				`</EntityDescriptor>`,
			want: []string{"CN=a", "CN=b"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			inv := Build(Inputs{SAML: []SAMLInput{{Name: "fed", Metadata: []byte(c.md)}}}, DefaultPolicy(), riskNow)
			assert.Equal(t, c.want, samlSubjects(t, inv))
			assert.Empty(t, gapWarnings(inv))
		})
	}

	// An entity with no IDPSSODescriptor is not a trusted IdP: nothing to list,
	// and the provider is reported as uninspectable (fail closed).
	spOnly := `<EntityDescriptor ` + mdNS + ` entityID="https://sp/"><SPSSODescriptor>` +
		keyDescriptor(t, "signing", "sp") + `</SPSSODescriptor></EntityDescriptor>`
	inv := Build(Inputs{SAML: []SAMLInput{{Name: "sp", Metadata: []byte(spOnly)}}}, DefaultPolicy(), riskNow)
	require.Len(t, inv.Assets, 1)
	assert.Equal(t, "unknown", inv.Assets[0].Algorithm)
	require.Len(t, gapWarnings(inv), 1)
}

// TestBuild_SAMLMetadataOverCapWarns: the cap stays, but a trusted IdP with
// more signing certificates than it is reported, not silently cut.
func TestBuild_SAMLMetadataOverCapWarns(t *testing.T) {
	md := func(n int) []byte {
		var b strings.Builder
		b.WriteString(`<EntityDescriptor ` + mdNS + ` entityID="https://idp/"><IDPSSODescriptor>`)
		for i := range n {
			b.WriteString(keyDescriptor(t, "signing", fmt.Sprintf("k%d", i)))
		}
		b.WriteString(`</IDPSSODescriptor></EntityDescriptor>`)
		return []byte(b.String())
	}
	at := Build(Inputs{SAML: []SAMLInput{{Name: "okta", Metadata: md(maxSAMLMetadataCerts)}}}, DefaultPolicy(), riskNow)
	assert.Len(t, at.Assets, maxSAMLMetadataCerts)
	assert.Empty(t, gapWarnings(at), "exactly the cap is complete")

	over := Build(Inputs{SAML: []SAMLInput{{Name: "okta", Metadata: md(maxSAMLMetadataCerts + 1)}}}, DefaultPolicy(), riskNow)
	assert.Len(t, over.Assets, maxSAMLMetadataCerts)
	w := gapWarnings(over)
	require.Len(t, w, 1)
	assert.Contains(t, w[0], `"okta"`)
	assert.Contains(t, w[0], fmt.Sprintf("first %d", maxSAMLMetadataCerts))
}

// TestBuild_DatabaseCABundleOverCapWarns: a CA bundle larger than the cap (AWS
// RDS's global bundle holds over 100 CAs) is reported, not silently cut.
func TestBuild_DatabaseCABundleOverCapWarns(t *testing.T) {
	dir := t.TempDir()
	bundle := func(n int) string {
		var b []byte
		for i := range n {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: namedCertDER(t, fmt.Sprintf("ca-%d", i))})...)
		}
		p := filepath.Join(dir, fmt.Sprintf("bundle-%d.pem", n))
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	at := Build(Inputs{Database: &DatabaseTLSInput{SSLMode: "verify-full", RootCertFile: bundle(maxCABundleCerts)}}, DefaultPolicy(), riskNow)
	assert.Len(t, at.Assets, maxCABundleCerts)
	assert.Empty(t, gapWarnings(at), "exactly the cap is complete")

	path := bundle(maxCABundleCerts + 1)
	over := Build(Inputs{Database: &DatabaseTLSInput{SSLMode: "verify-full", RootCertFile: path}}, DefaultPolicy(), riskNow)
	assert.Len(t, over.Assets, maxCABundleCerts)
	w := gapWarnings(over)
	require.Len(t, w, 1)
	assert.Contains(t, w[0], path)
	assert.Contains(t, w[0], fmt.Sprintf("first %d", maxCABundleCerts))
}

// TestBuild_DatabaseTLSWithSSLModeDisable: with sslmode=disable the connection
// uses no TLS, so a configured certificate is not inventoried as one in use.
func TestBuild_DatabaseTLSWithSSLModeDisable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: namedCertDER(t, "client")}), 0o600))
	inv := Build(Inputs{Database: &DatabaseTLSInput{SSLMode: "disable", ClientCertFile: p, RootCertFile: p}}, DefaultPolicy(), riskNow)
	assert.Empty(t, inv.Assets)
	assert.Empty(t, gapWarnings(inv))
	found := false
	for _, n := range inv.Notes {
		found = found || strings.Contains(n, "sslmode=disable")
	}
	assert.True(t, found, "the skip is stated in Notes: %v", inv.Notes)
}

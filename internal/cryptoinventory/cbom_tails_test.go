package cryptoinventory

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cbomDoc is the slice of the CycloneDX document the reference checks read.
type cbomDoc struct {
	Components []struct {
		BomRef           string `json:"bom-ref"`
		Name             string `json:"name"`
		CryptoProperties struct {
			AssetType string `json:"assetType"`
			Algorithm *struct {
				Primitive    string `json:"primitive"`
				ParameterSet string `json:"parameterSetIdentifier"`
			} `json:"algorithmProperties"`
			Certificate *struct {
				SignatureAlgorithmRef string `json:"signatureAlgorithmRef"`
			} `json:"certificateProperties"`
			Related *struct {
				AlgorithmRef string `json:"algorithmRef"`
			} `json:"relatedCryptoMaterialProperties"`
		} `json:"cryptoProperties"`
	} `json:"components"`
}

func renderCBOM(t *testing.T, inv Inventory) cbomDoc {
	t.Helper()
	raw, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)
	var doc cbomDoc
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc
}

// A certificate's signatureAlgorithmRef must name the algorithm the certificate
// was SIGNED with, not the algorithm of the key it certifies (the two differ for
// every CA-issued leaf, and for a self-signed ECDSA-P256 cert: ECDSA-SHA256).
func TestCBOM_CertificateSignatureAlgorithmRefResolvesToTheSignatureAlgorithm(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)
	doc := renderCBOM(t, inv)

	byRef := map[string]string{} // bom-ref -> algorithm component name
	for _, c := range doc.Components {
		if c.CryptoProperties.AssetType == "algorithm" {
			byRef[c.BomRef] = c.Name
		}
	}

	var certs int
	for _, a := range inv.Assets {
		if a.Certificate == nil {
			continue
		}
		for _, c := range doc.Components {
			if c.BomRef != assetRef(a.ID) || c.CryptoProperties.Certificate == nil {
				continue
			}
			certs++
			ref := c.CryptoProperties.Certificate.SignatureAlgorithmRef
			require.NotEmpty(t, ref, "%s: certificate with a known signature algorithm must reference it", a.ID)
			name, ok := byRef[ref]
			require.True(t, ok, "%s: signatureAlgorithmRef %q must resolve to an algorithm component", a.ID, ref)
			assert.Equal(t, a.Certificate.SignatureAlgorithm, name, "%s: signatureAlgorithmRef points at the wrong algorithm", a.ID)
			assert.NotEqual(t, a.Algorithm, name, "%s: the key algorithm is not the signature algorithm", a.ID)
		}
	}
	require.Positive(t, certs, "fixture must contain a certificate asset")
}

func TestCBOM_CertificateWithoutSignatureAlgorithmDropsTheRef(t *testing.T) {
	inv := Inventory{Assets: []Asset{{
		ID: "tls.x", Name: "x", Class: ClassTLSCertificate, Primitive: "signature", Algorithm: "RSA-2048", KeySizeBits: 2048,
		Asymmetric: true, Certificate: &CertInfo{KeyAlgorithm: "RSA-2048"},
	}}}
	doc := renderCBOM(t, inv)
	for _, c := range doc.Components {
		if c.CryptoProperties.Certificate != nil {
			assert.Empty(t, c.CryptoProperties.Certificate.SignatureAlgorithmRef)
		}
	}
}

// Every algorithmRef a key-material component carries resolves to an algorithm component.
func TestCBOM_AllAlgorithmRefsResolve(t *testing.T) {
	in, _ := fullInputs(t)
	doc := renderCBOM(t, Build(in, DefaultPolicy(), riskNow))
	algos := map[string]bool{}
	for _, c := range doc.Components {
		if c.CryptoProperties.AssetType == "algorithm" {
			algos[c.BomRef] = true
		}
	}
	for _, c := range doc.Components {
		if r := c.CryptoProperties.Related; r != nil && r.AlgorithmRef != "" {
			assert.True(t, algos[r.AlgorithmRef], "%s: algorithmRef %q does not resolve", c.BomRef, r.AlgorithmRef)
		}
	}
}

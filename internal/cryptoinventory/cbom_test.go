package cryptoinventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cdxSchemaDir = "testdata/cyclonedx-1.6"
	cdxBomID     = "http://cyclonedx.org/schema/bom-1.6.schema.json"
)

// compileCycloneDX16 loads the vendored OFFICIAL CycloneDX 1.6 schema (and the two
// schemas it $refs) so validation is offline and deterministic.
func compileCycloneDX16(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for file, id := range map[string]string{
		"bom-1.6.schema.json":  cdxBomID,
		"spdx.schema.json":     "http://cyclonedx.org/schema/spdx.schema.json",
		"jsf-0.82.schema.json": "http://cyclonedx.org/schema/jsf-0.82.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(cdxSchemaDir, file))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(id, doc))
	}
	sch, err := c.Compile(cdxBomID)
	require.NoError(t, err)
	return sch
}

func validate(t *testing.T, sch *jsonschema.Schema, doc []byte) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	require.NoError(t, err)
	return sch.Validate(v)
}

func TestVendoredSchemaIsTheOfficialOne(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(cdxSchemaDir, "bom-1.6.schema.json"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), cdxBomID)
	assert.Contains(t, string(raw), `"cryptographic-asset"`)
	_, err = os.Stat(filepath.Join(cdxSchemaDir, "LICENSE"))
	assert.NoError(t, err, "vendored schema must ship with its license text")
	_, err = os.Stat(filepath.Join(cdxSchemaDir, "NOTICE.md"))
	assert.NoError(t, err)
}

func TestCBOM_ValidatesAgainstOfficialSchema(t *testing.T) {
	sch := compileCycloneDX16(t)
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)

	doc, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc), "CBOM must validate against CycloneDX 1.6")
}

func TestCBOM_ValidatesForEveryProviderShape(t *testing.T) {
	sch := compileCycloneDX16(t)
	for _, p := range []string{"password", "file", "env", "exec", "shamir", "tpm", "aws-kms", "gcp-kms", "azure-kms"} {
		t.Run(p, func(t *testing.T) {
			in := Inputs{EncryptionEnabled: true, KeyProvider: p, KeyProviderRef: "ref",
				TLS: []TLSInput{{Name: "http", AutoCert: true}}, WebAuthnEnabled: true, WebAuthnRPID: "x.example"}
			doc, err := Build(in, DefaultPolicy(), riskNow).CBOM(CBOMOptions{})
			require.NoError(t, err)
			require.NoError(t, validate(t, sch, doc))
		})
	}
	// Empty inventory (encryption off, nothing configured) is still a valid BOM.
	doc, err := Build(Inputs{}, DefaultPolicy(), riskNow).CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc))
}

// The schema check must have teeth: a document that breaks the CBOM rules fails.
func TestCBOM_SchemaRejectsBrokenDocuments(t *testing.T) {
	sch := compileCycloneDX16(t)
	for name, doc := range map[string]string{
		"wrong spec version type": `{"bomFormat":"CycloneDX","specVersion":1.6}`,
		"unknown asset type": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x",
			"cryptoProperties":{"assetType":"banana"}}]}`,
		"unknown component field": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x","bogus":1}]}`,
		"bad primitive": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"x",
			"cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"rot13"}}}]}`,
	} {
		assert.Error(t, validate(t, sch, []byte(doc)), name)
	}
}

func TestCBOM_Structure(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)
	ts := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	doc, err := inv.CBOM(CBOMOptions{SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", Timestamp: ts, ServerVersion: "9.9.9"})
	require.NoError(t, err)

	var bom struct {
		BomFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Component struct {
				Type, Name, Version string
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Type             string `json:"type"`
			BomRef           string `json:"bom-ref"`
			Name             string `json:"name"`
			CryptoProperties struct {
				AssetType string `json:"assetType"`
				Related   *struct {
					Type  string  `json:"type"`
					Value *string `json:"value"`
					Size  int     `json:"size"`
				} `json:"relatedCryptoMaterialProperties"`
			} `json:"cryptoProperties"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(doc, &bom))
	assert.Equal(t, "CycloneDX", bom.BomFormat)
	assert.Equal(t, "1.6", bom.SpecVersion)
	assert.Equal(t, "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", bom.SerialNumber)
	assert.Equal(t, 1, bom.Version)
	assert.Equal(t, "2026-10-23T12:00:00Z", bom.Metadata.Timestamp)
	assert.Equal(t, "Keyorix", bom.Metadata.Component.Name)
	assert.Equal(t, "9.9.9", bom.Metadata.Component.Version)

	refs := map[string]bool{}
	var scored int
	for _, c := range bom.Components {
		assert.Equal(t, "cryptographic-asset", c.Type)
		assert.NotEmpty(t, c.BomRef)
		assert.False(t, refs[c.BomRef], "duplicate bom-ref %s", c.BomRef)
		refs[c.BomRef] = true
		assert.NotEmpty(t, c.CryptoProperties.AssetType)
		if r := c.CryptoProperties.Related; r != nil {
			assert.Nil(t, r.Value, "CBOM must never carry a key value (%s)", c.Name)
		}
		for _, p := range c.Properties {
			if p.Name == "keyorix:quantum-risk-score" {
				scored++
			}
		}
	}
	assert.Positive(t, scored, "quantum-risk score must be exported as a component property")
	assert.GreaterOrEqual(t, len(bom.Components), len(inv.Assets), "one component per asset plus shared algorithm components")
}

func TestCBOM_CarriesRiskAndFlagsClassicalKeys(t *testing.T) {
	in, _ := fullInputs(t)
	inv := Build(in, DefaultPolicy(), riskNow)
	doc, err := inv.CBOM(CBOMOptions{})
	require.NoError(t, err)

	var bom struct {
		Components []struct {
			BomRef     string                         `json:"bom-ref"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(doc, &bom))
	prop := func(ref, name string) string {
		for _, c := range bom.Components {
			if c.BomRef == ref {
				for _, p := range c.Properties {
					if p.Name == name {
						return p.Value
					}
				}
			}
		}
		return ""
	}
	assert.Equal(t, "true", prop("keyorix:asset:tls.http", "keyorix:quantum-vulnerable"))
	assert.Equal(t, "false", prop("keyorix:asset:dek", "keyorix:quantum-vulnerable"))
	assert.Equal(t, "low", prop("keyorix:asset:dek", "keyorix:quantum-risk-level"))
}

func TestCBOM_DeterministicGivenOptions(t *testing.T) {
	in, _ := fullInputs(t)
	opts := CBOMOptions{SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", Timestamp: riskNow}
	a, err := Build(in, DefaultPolicy(), riskNow).CBOM(opts)
	require.NoError(t, err)
	b, err := Build(in, DefaultPolicy(), riskNow).CBOM(opts)
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b))
}

func TestCBOM_GeneratesSerialWhenUnset(t *testing.T) {
	sch := compileCycloneDX16(t)
	doc, err := Build(Inputs{}, DefaultPolicy(), riskNow).CBOM(CBOMOptions{})
	require.NoError(t, err)
	require.NoError(t, validate(t, sch, doc))
	var m map[string]any
	require.NoError(t, json.Unmarshal(doc, &m))
	assert.Regexp(t, `^urn:uuid:[0-9a-f-]{36}$`, m["serialNumber"])
}

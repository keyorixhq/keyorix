package v1alpha1

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// crdSchema is a narrow projection of just the pieces of the generated CRD's
// openAPIV3Schema this test cares about.
type crdSchema struct {
	Spec crdSchemaSpec `json:"spec"`
}

type crdSchemaSpec struct {
	Versions []crdSchemaVersion `json:"versions"`
}

type crdSchemaVersion struct {
	Name   string                 `json:"name"`
	Schema crdSchemaVersionSchema `json:"schema"`
}

type crdSchemaVersionSchema struct {
	OpenAPIV3Schema crdOpenAPIV3Schema `json:"openAPIV3Schema"`
}

type crdOpenAPIV3Schema struct {
	Properties crdOpenAPIV3SchemaProperties `json:"properties"`
}

type crdOpenAPIV3SchemaProperties struct {
	Spec crdSpecSchema `json:"spec"`
}

type crdSpecSchema struct {
	Properties crdSpecSchemaProperties `json:"properties"`
}

type crdSpecSchemaProperties struct {
	Data           crdDataSchema               `json:"data"`
	Server         crdRefSchema                `json:"server"`
	TokenSecretRef crdTokenSecretRefProperties `json:"tokenSecretRef"`
}

type crdTokenSecretRefProperties struct {
	Properties crdTokenSecretRefSchema `json:"properties"`
}

type crdTokenSecretRefSchema struct {
	Name crdRefSchema `json:"name"`
	Key  crdRefSchema `json:"key"`
}

type crdDataSchema struct {
	MaxItems int                `json:"maxItems"`
	MinItems int                `json:"minItems"`
	Items    crdDataItemsSchema `json:"items"`
}

type crdDataItemsSchema struct {
	Properties crdDataItemsProperties `json:"properties"`
}

type crdDataItemsProperties struct {
	Ref crdRefSchema `json:"ref"`
}

type crdRefSchema struct {
	MaxLength int `json:"maxLength"`
}

// The kubebuilder validation markers on KeyorixSecretSpec.Data and KeyorixSecretData.Ref
// (r143) are enforced by the Kubernetes API server against the GENERATED CRD manifest, not
// against the Go struct tags directly — a CR create/update request never goes through this
// Go type's markers at runtime, only through whatever schema `make manifests`
// (controller-gen) baked into config/crd/bases/secrets.keyorix.io_keyorixsecrets.yaml. This
// module has no envtest wired up (see operator/Makefile: "Run unit/controller tests (fake
// client; no envtest required)"), so a fake-client reconciler test can't exercise real
// admission validation. This test instead asserts the actual artifact the API server would
// load, catching both (a) a marker value regressing and (b) someone editing the Go type
// without regenerating the CRD (a stale/missing maxItems here would silently reopen the
// unbounded-fan-out DoS this cap exists to close).
func TestGeneratedCRD_DataMaxItemsAndRefMaxLength(t *testing.T) {
	raw, err := os.ReadFile("../../config/crd/bases/secrets.keyorix.io_keyorixsecrets.yaml")
	require.NoError(t, err, "generated CRD manifest must exist — run `make manifests` in operator/")

	var doc crdSchema
	require.NoError(t, yaml.Unmarshal(raw, &doc))

	var found bool
	for _, v := range doc.Spec.Versions {
		if v.Name != "v1alpha1" {
			continue
		}
		found = true
		data := v.Schema.OpenAPIV3Schema.Properties.Spec.Properties.Data
		assert.Equal(t, 50, data.MaxItems,
			"spec.data must stay bounded (r143): an unbounded array lets a single tenant's "+
				"KeyorixSecret stall the reconciler's (small, shared) worker pool for an "+
				"unbounded time, starving every other tenant's reconciliation")
		assert.Equal(t, 1, data.MinItems, "spec.data must still require at least one entry")
		assert.Equal(t, 512, data.Items.Properties.Ref.MaxLength,
			"spec.data[].ref must stay bounded (r143) so a single entry can't inflate "+
				"request/response size arbitrarily")

		spec := v.Schema.OpenAPIV3Schema.Properties.Spec.Properties
		assert.Equal(t, 2048, spec.Server.MaxLength,
			"spec.server must stay bounded: an oversized value is echoed verbatim into "+
				"validateServer's rejection message, which reconcile writes into the Ready "+
				"condition's Message — capped at 32768 chars by this CRD's own Condition "+
				"schema, so an unbounded Server could make the status write itself fail "+
				"validation and mask the real error behind a stuck Ready condition")
		assert.Equal(t, 253, spec.TokenSecretRef.Properties.Name.MaxLength,
			"spec.tokenSecretRef.name must stay bounded for the same reason as spec.server")
		assert.Equal(t, 253, spec.TokenSecretRef.Properties.Key.MaxLength,
			"spec.tokenSecretRef.key must stay bounded for the same reason as spec.server")
	}
	require.True(t, found, "CRD manifest must define the v1alpha1 version")
}

// A regenerated CRD (operator/config/crd/bases) that isn't also copied into the Helm
// chart (deploy/helm/keyorix-operator/crds, per the `manifests` Makefile target's final
// `cp` step) means a Helm-deployed operator would enforce a DIFFERENT, stale schema than
// the one actually generated from the Go types — silently reopening whatever gap the
// latest markers were meant to close. Skips (rather than fails) if the sibling repo layout
// isn't present, since this module can in principle be built standalone.
func TestHelmChartCRD_MatchesGeneratedCRD(t *testing.T) {
	generated, err := os.ReadFile("../../config/crd/bases/secrets.keyorix.io_keyorixsecrets.yaml")
	require.NoError(t, err)

	chartPath := "../../../deploy/helm/keyorix-operator/crds/secrets.keyorix.io_keyorixsecrets.yaml"
	chart, err := os.ReadFile(chartPath)
	if os.IsNotExist(err) {
		t.Skip("deploy/helm/keyorix-operator not present in this checkout; skipping cross-module drift check")
	}
	require.NoError(t, err)

	assert.Equal(t, string(generated), string(chart),
		"deploy/helm/keyorix-operator/crds must be an exact copy of operator/config/crd/bases "+
			"(re-run `make manifests` in operator/, which syncs both)")
}

package handlers

// COMPLIANCE-TILE-NOV-1 item 1: GET /compliance/posture returns core.CompliancePosture
// verbatim, so its OpenAPI schema is checked two ways. The body of a real call is
// validated against the spec (TestContractPosture_GetCompliancePosture), which
// catches a wrong type or a missing required field. That alone cannot see an
// omitempty field a sparse deployment never returns (stale, trend, ...), so
// TestCompliancePostureSchemaMatchesHandlerBody also walks the Go type and the
// schema side by side: same property names, and "required" exactly the fields
// without omitempty.
//
// Not covered: enum values and descriptions (prose), and the gRPC proto, which
// has its own parity test in server/grpc/services.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractPosture_GetCompliancePosture(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func loadPostureSpec(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("openapi.yaml")
	require.NoError(t, err)
	return doc
}

func TestCompliancePostureSchemaMatchesHandlerBody(t *testing.T) {
	doc := loadPostureSpec(t)
	ref := doc.Components.Schemas["CompliancePosture"]
	require.NotNil(t, ref, "components.schemas.CompliancePosture is missing")

	problems := schemaProblems("CompliancePosture", ref, reflect.TypeFor[core.CompliancePosture]())
	assert.Empty(t, problems)
}

// The comparison must fail on drift, not only pass on the current tree: a copy of
// the emergency-access schema without degraded_activations has to be reported,
// both as a missing property and as a missing required entry.
func TestCompliancePostureSchemaMatchesHandlerBody_DetectsDrift(t *testing.T) {
	doc := loadPostureSpec(t)
	em := doc.Components.Schemas["EmergencyAccessPosture"].Value

	mutated := *em
	mutated.Properties = openapi3.Schemas{}
	for k, v := range em.Properties {
		if k != "degraded_activations" {
			mutated.Properties[k] = v
		}
	}
	mutated.Required = slices.DeleteFunc(slices.Clone(em.Required), func(s string) bool { return s == "degraded_activations" })

	problems := schemaProblems("EmergencyAccessPosture", &openapi3.SchemaRef{Value: &mutated}, reflect.TypeFor[core.EmergencyAccessPosture]())
	assert.Len(t, problems, 2, "%v", problems)
	assert.Contains(t, strings.Join(problems, "\n"), `does not declare "degraded_activations"`)
}

// schemaProblems compares one schema with the Go type marshalled into it, then
// recurses into nested objects and arrays. It returns one line per difference.
func schemaProblems(path string, ref *openapi3.SchemaRef, typ reflect.Type) []string {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if ref == nil || ref.Value == nil {
		return []string{path + ": no (or unresolved) schema"}
	}
	schema := ref.Value
	kindIs := func(want string) []string {
		if schema.Type.Is(want) {
			return nil
		}
		return []string{fmt.Sprintf("%s: Go %s, schema type is %v", path, typ, schema.Type.Slice())}
	}

	if typ == reflect.TypeFor[time.Time]() {
		if p := kindIs("string"); p != nil {
			return p
		}
		if schema.Format != "date-time" {
			return []string{path + ": time.Time must have format date-time"}
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Slice:
		if p := kindIs("array"); p != nil {
			return p
		}
		return schemaProblems(path+"[]", schema.Items, typ.Elem())
	case reflect.Bool:
		return kindIs("boolean")
	case reflect.String:
		return kindIs("string")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return kindIs("integer")
	case reflect.Struct:
	default:
		return []string{fmt.Sprintf("%s: Go kind %s is not handled by this test", path, typ.Kind())}
	}

	if p := kindIs("object"); p != nil {
		return p
	}
	var problems []string
	fields, wantRequired := map[string]reflect.Type{}, []string{}
	for f := range typ.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = f.Type
		if !strings.Contains(opts, "omitempty") {
			wantRequired = append(wantRequired, name)
		}
	}
	for name, ft := range fields {
		prop, ok := schema.Properties[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: the handler returns it but the schema does not declare %q", path, name))
			continue
		}
		problems = append(problems, schemaProblems(path+"."+name, prop, ft)...)
	}
	for name := range schema.Properties {
		if _, ok := fields[name]; !ok {
			problems = append(problems, fmt.Sprintf("%s: the schema declares %q but the handler never returns it", path, name))
		}
	}
	gotRequired := slices.Clone(schema.Required)
	slices.Sort(gotRequired)
	slices.Sort(wantRequired)
	if !slices.Equal(gotRequired, wantRequired) {
		problems = append(problems, fmt.Sprintf("%s: required is %v, want exactly the fields without omitempty %v", path, gotRequired, wantRequired))
	}
	slices.Sort(problems)
	return problems
}

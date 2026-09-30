package statemap

import (
	"go/parser"
	"go/token"
	"testing"
)

// restFixtureSrc is a small, FIXED chi-router-shaped source (not router.go
// itself, so this test is stable regardless of router.go's real content)
// exercising exactly the two things B1's coordinator review asked to see
// permanently red-proofed:
//  1. nested r.Route(...) prefix composition (two DIFFERENT groups each
//     registering a locally-identical "/" path must NOT collide once
//     composed with their distinct mount prefixes), and
//  2. a genuine duplicate: the SAME composed path registered twice under
//     the same prefix (a literal copy/paste mistake) DOES still collide,
//     proving the extractor isn't just always producing unique output
//     regardless of input.
const restFixtureSrc = `package fixture

func NewRouter(r chi.Router) {
	r.Route("/api/v1/secrets", func(r chi.Router) {
		r.Get("/", listSecrets)
	})
	r.Route("/api/v1/folders", func(r chi.Router) {
		r.Get("/", listFolders)
	})
	r.Route(pathDup, func(r chi.Router) {
		r.Get("/x", dupOne)
		r.Get("/x", dupTwo)
	})
}
`

func parseFixture(t *testing.T) ([]Entry, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", restFixtureSrc, 0)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return restRoutesFromAST(f, fset, "fixture.go"), fset
}

// TestRESTRouteComposition_NestedPrefixesDistinguishSameLocalPath is the
// permanent version of this session's earlier manual red-proof (a scratch
// route added to router.go, tested, then reverted): two different
// r.Route(...) groups each registering "/" must NOT collapse into a single
// "GET /" key -- this was PR #2336's original B1 defect (737 rows -> 586
// unique keys, "GET / x10").
func TestRESTRouteComposition_NestedPrefixesDistinguishSameLocalPath(t *testing.T) {
	entries, _ := parseFixture(t)
	want := map[string]bool{
		"GET /api/v1/secrets/": false,
		"GET /api/v1/folders/": false,
	}
	for _, e := range entries {
		if _, ok := want[e.ID]; ok {
			want[e.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected composed route id %q not found among: %v", id, entries)
		}
	}
}

// TestRESTRouteComposition_GenuineDuplicateStillCollides proves the
// extractor is not vacuously "always unique" -- a real copy/paste mistake
// (the identical path registered twice under the identical mount prefix)
// must still produce two rows with the SAME id, so
// TestCompletenessGuard_EntrypointsAndStoresMatchCode's count-based diff
// (not mere presence) has something to actually detect a THIRD occurrence
// against.
func TestRESTRouteComposition_GenuineDuplicateStillCollides(t *testing.T) {
	// pathDup is intentionally an unresolved const (not declared in the
	// fixture source) -- resolveStringExpr's own "<name>" fallback for an
	// unknown identifier is fine here: both dup registrations resolve to the
	// SAME fallback string, which is exactly what this test needs (the point
	// is proving equal inputs produce equal, colliding IDs, not proving a
	// specific path string).
	entries, _ := parseFixture(t)
	count := 0
	var id string
	for _, e := range entries {
		if e.Handler == "dupOne" || e.Handler == "dupTwo" {
			count++
			id = e.ID
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 entries for the dup fixture handlers, got %d", count)
	}
	// Confirm they actually share the composed ID (the collision B1's
	// count-based guard needs to be able to see), by re-deriving each one's
	// ID independently instead of trusting the loop above alone.
	var ids []string
	for _, e := range entries {
		if e.Handler == "dupOne" || e.Handler == "dupTwo" {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Errorf("expected both dup-fixture entries to share one composed id, got %v (single id checked: %q)", ids, id)
	}
}

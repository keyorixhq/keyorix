package contracttest

import (
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// setFlag sets a registered testing flag for the duration of the calling
// test and restores its previous value afterward via t.Cleanup. These
// functions (currentRunFilter, testListModeActive) read flag.Lookup
// directly rather than taking a parameter, because their real caller
// (CheckAllEnforcedExercised, invoked from TestMain) has no *testing.T of
// its own to thread one through -- so exercising both branches here means
// manipulating the actual flag.
func setFlag(t *testing.T, name, value string) {
	t.Helper()
	f := flag.Lookup(name)
	if f == nil {
		t.Fatalf("flag %q is not registered", name)
	}
	original := f.Value.String()
	if err := f.Value.Set(value); err != nil {
		t.Fatalf("setting flag %q to %q: %v", name, value, err)
	}
	t.Cleanup(func() {
		if err := f.Value.Set(original); err != nil {
			t.Fatalf("restoring flag %q to %q: %v", name, original, err)
		}
	})
}

func TestTestListModeActive(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		setFlag(t, "test.list", "")
		if testListModeActive() {
			t.Error("expected false with test.list unset")
		}
	})
	t.Run("set", func(t *testing.T) {
		setFlag(t, "test.list", "^Test")
		if !testListModeActive() {
			t.Error("expected true with test.list set")
		}
	})
}

func TestCurrentRunFilter(t *testing.T) {
	t.Run("unset returns nil (matches everything)", func(t *testing.T) {
		setFlag(t, "test.run", "")
		if got := currentRunFilter(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
	t.Run("set returns a compiled regexp", func(t *testing.T) {
		setFlag(t, "test.run", "^(TestFoo|TestBar)$")
		got := currentRunFilter()
		if got == nil {
			t.Fatal("expected a compiled regexp, got nil")
		}
		if !got.MatchString("TestFoo") || got.MatchString("TestBaz") {
			t.Errorf("regexp %v did not behave as expected", got)
		}
	})
	t.Run("invalid pattern is treated as unfiltered, not a panic", func(t *testing.T) {
		setFlag(t, "test.run", "[")
		if got := currentRunFilter(); got != nil {
			t.Errorf("expected nil for an invalid pattern, got %v", got)
		}
	})
}

func TestAnyEligible(t *testing.T) {
	cases := []struct {
		name      string
		runFilter *regexp.Regexp
		names     []string
		want      bool
	}{
		{"nil filter selects everything", nil, []string{"TestAnything"}, true},
		{"matching name", regexp.MustCompile("^(TestFoo)$"), []string{"TestFoo"}, true},
		{"one of several names matches", regexp.MustCompile("^(TestBar)$"), []string{"TestFoo", "TestBar"}, true},
		{"no names match", regexp.MustCompile("^(TestBar)$"), []string{"TestFoo", "TestBaz"}, false},
		{"empty names", regexp.MustCompile("^(TestBar)$"), nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := anyEligible(tc.runFilter, tc.names); got != tc.want {
				t.Errorf("anyEligible(%v, %v) = %v, want %v", tc.runFilter, tc.names, got, tc.want)
			}
		})
	}
}

// TestCheckPartition_BothRegistries covers the third violation branch
// (registered in both pendingRegistry and outOfScopeRegistry) that no other
// test exercises -- CheckPartition's own doc comment only names the other
// two directions, and ADR-074's Phase 3 verification tested those two
// manually rather than as a standing test.
func TestCheckPartition_BothRegistries(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	const opID = "healthCheck" // has a schema, chosen so it's unambiguous either way
	pendingRegistry[opID] = "TEST: both-registries case"
	outOfScopeRegistry[opID] = "TEST: both-registries case"
	t.Cleanup(func() {
		delete(pendingRegistry, opID)
		delete(outOfScopeRegistry, opID)
	})

	err := CheckPartition()
	if err == nil {
		t.Fatal("expected an error when an operation is registered in both maps")
	}
	if got := err.Error(); !strings.Contains(got, "registered in BOTH pendingRegistry") {
		t.Errorf("error does not mention the both-registries violation: %s", got)
	}
}

// TestCheckAllEnforcedExercised covers all three of its own branches
// directly -- the -list-mode short-circuit, the all-exercised success path,
// and the eligible-but-missing failure path -- none of which any other test
// in this package reaches, since exercising the real 9 enforced operations
// normally only happens from server/http/handlers' own tests (a different
// test binary, whose coverage is never attributed back to this package --
// see AssertOpenAPIResponse's own direct test for the same reasoning).
func TestCheckAllEnforcedExercised(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	saveAndClearExercised := func(t *testing.T) {
		t.Helper()
		exercisedMu.Lock()
		saved := exercised
		exercised = map[string]bool{}
		exercisedMu.Unlock()
		t.Cleanup(func() {
			exercisedMu.Lock()
			exercised = saved
			exercisedMu.Unlock()
		})
	}

	t.Run("list mode short-circuits to nil", func(t *testing.T) {
		saveAndClearExercised(t)
		setFlag(t, "test.list", "^Test")
		if err := CheckAllEnforcedExercised(); err != nil {
			t.Errorf("expected nil under -list, got %v", err)
		}
	})

	t.Run("all enforced operations exercised: nil", func(t *testing.T) {
		saveAndClearExercised(t)
		setFlag(t, "test.run", "")
		exercisedMu.Lock()
		for opID := range enforcedOperationIDs() {
			exercised[opID] = true
		}
		exercisedMu.Unlock()
		if err := CheckAllEnforcedExercised(); err != nil {
			t.Errorf("expected nil when every enforced operation is marked exercised, got %v", err)
		}
	})

	t.Run("eligible but unexercised operation fails", func(t *testing.T) {
		saveAndClearExercised(t)
		// Unfiltered -run means every exercisingTests entry is eligible, so
		// leaving `exercised` empty must fail for all 9 real enforced ops.
		setFlag(t, "test.run", "")
		err := CheckAllEnforcedExercised()
		if err == nil {
			t.Fatal("expected an error when enforced operations are never exercised")
		}
	})

	t.Run("ineligible in this shard is skipped, not failed", func(t *testing.T) {
		saveAndClearExercised(t)
		// A -run pattern that matches none of the real exercising test names
		// -- every enforced operation is "not eligible here" rather than
		// "missing", exactly ADR-074's shard-awareness requirement.
		setFlag(t, "test.run", "^(TestNoSuchTestNameAnywhere)$")
		if err := CheckAllEnforcedExercised(); err != nil {
			t.Errorf("expected nil when no exercising test is eligible in this shard, got %v", err)
		}
	})
}

// TestAssertOpenAPIResponse_Success covers the success path (a real request
// that matches a real operation, with a response that validates) -- the
// only other test touching AssertOpenAPIResponse exercises the unmatched-
// request failure branch. Handler-level success calls happen from
// server/http/handlers' own tests, a different test binary whose coverage
// is never attributed back to this package (see checks.go's
// CheckAllEnforcedExercised doc comment for the general reason).
func TestAssertOpenAPIResponse_Success(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	exercisedMu.Lock()
	delete(exercised, "healthCheck")
	exercisedMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy","timestamp":"2026-01-01T00:00:00Z"}`))

	AssertOpenAPIResponse(t, req, w)

	exercisedMu.Lock()
	got := exercised["healthCheck"]
	exercisedMu.Unlock()
	if !got {
		t.Error("expected healthCheck to be recorded as exercised after a successful call")
	}
}

// TestAssertOpenAPIResponse_SpecErrFailsLoudly covers the branch no other
// test reaches: loadSpec() having already recorded a failure (specErr set)
// by the time AssertOpenAPIResponse runs. Every other caller in this package
// exercises a clean spec, so this manipulates the package-global specErr
// directly (safe: specOnce has already fired earlier in the suite, so
// loadSpec()'s own call inside AssertOpenAPIResponse is a no-op and won't
// clobber our injected value).
func TestAssertOpenAPIResponse_SpecErrFailsLoudly(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	original := specErr
	boom := errors.New("TEST: synthetic spec load failure")
	specErr = boom
	t.Cleanup(func() { specErr = original })

	fakeT := &testing.T{}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- fakeT.Failed() }()
		AssertOpenAPIResponse(fakeT, req, w)
	}()
	failed := <-done

	if !failed {
		t.Fatal("expected AssertOpenAPIResponse to fail loudly when specErr is already set")
	}
}

// TestOperationHasSchema_NilResponses covers the guard at the top of
// operationHasSchema: an operation with a nil Responses object (never
// produced by the real, validated openapi.yaml, since OpenAPI validation
// requires every operation to declare at least one response) must report no
// schema rather than panic walking a nil map.
func TestOperationHasSchema_NilResponses(t *testing.T) {
	op := &openapi3.Operation{}
	if operationHasSchema(op) {
		t.Error("expected operationHasSchema to return false when Responses is nil")
	}
}

// TestStaleRegistryEntries_FlagsUnknownKeys covers the "key not in validIDs"
// branch directly (the real registries are always kept in sync with
// openapi.yaml, so this branch is otherwise only reachable by staging real
// registry corruption through CheckPartition).
func TestStaleRegistryEntries_FlagsUnknownKeys(t *testing.T) {
	validIDs := map[string]bool{"knownOp": true}
	got := staleRegistryEntries("exampleRegistry", []string{"knownOp", "staleOp"}, validIDs)
	if len(got) != 1 {
		t.Fatalf("expected exactly one stale-entry violation, got %v", got)
	}
	if !strings.Contains(got[0], "staleOp") || !strings.Contains(got[0], "exampleRegistry") {
		t.Errorf("expected the violation to name the stale key and registry, got: %q", got[0])
	}
}

// syntheticSpecWithMissingOperationID is a valid OpenAPI document (operationId
// is optional per the spec itself) whose single operation declares none --
// the real openapi.yaml never has one, since every operation in it already
// carries an operationId, so this branch needs a synthetic doc to reach.
const syntheticSpecWithMissingOperationID = `
openapi: 3.0.3
info:
  title: missing operationId test
  version: "1.0"
paths:
  /no-id:
    get:
      responses:
        '200':
          description: ok
`

// loadSyntheticSpec parses and validates a literal OpenAPI document, the
// same way harness_test.go's dualContentSpec does, for tests that need a
// spec shape the real openapi.yaml can't express.
func loadSyntheticSpec(t *testing.T, yaml string) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(yaml))
	if err != nil {
		t.Fatalf("loading synthetic spec: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validating synthetic spec: %v", err)
	}
	return doc
}

// swapSpec temporarily replaces the package-global spec (already populated
// by loadSpec() earlier in the suite, so its sync.Once won't overwrite this)
// and restores the original on cleanup.
func swapSpec(t *testing.T, doc *openapi3.T) {
	t.Helper()
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	original := spec
	spec = doc
	t.Cleanup(func() { spec = original })
}

// TestOperationsWithoutID_MissingID covers operationsWithoutID's actual
// "found a missing operationId" branch, which the real, fully-IDed
// openapi.yaml never reaches.
func TestOperationsWithoutID_MissingID(t *testing.T) {
	swapSpec(t, loadSyntheticSpec(t, syntheticSpecWithMissingOperationID))

	got := operationsWithoutID()
	if len(got) != 1 {
		t.Fatalf("expected exactly one missing-operationId entry, got %v", got)
	}
	if !strings.Contains(got[0], "/no-id") {
		t.Errorf("expected the entry to mention /no-id, got %q", got[0])
	}
}

// TestCheckPartition_MissingOperationID covers CheckPartition's own loop
// over operationsWithoutID() (checks.go), which the real spec never
// populates since every real operation already carries an operationId.
func TestCheckPartition_MissingOperationID(t *testing.T) {
	swapSpec(t, loadSyntheticSpec(t, syntheticSpecWithMissingOperationID))

	err := CheckPartition()
	if err == nil {
		t.Fatal("expected an error for an operation with no operationId")
	}
	if !strings.Contains(err.Error(), "operation has no operationId") {
		t.Errorf("expected the missing-operationId violation, got: %v", err)
	}
}

// TestCheckPartition_PropagatesSpecErr covers the top-of-function specErr
// short-circuit, unreachable through the real (always-valid) openapi.yaml.
func TestCheckPartition_PropagatesSpecErr(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	boom := errors.New("TEST: synthetic spec load failure")
	specErr = boom
	t.Cleanup(func() { specErr = nil })

	if err := CheckPartition(); !errors.Is(err, boom) {
		t.Errorf("expected CheckPartition to propagate specErr verbatim, got: %v", err)
	}
}

// TestCheckPartition_PendingButHasSchema covers the "pending entry whose
// operation has since gained a schema" violation -- every operation in
// pendingRegistry today genuinely has no schema, so this stages the
// contradiction on a real, schema-bearing operation (healthCheck) instead
// of relying on the registry ever actually drifting into that state.
func TestCheckPartition_PendingButHasSchema(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	const opID = "healthCheck" // enforced: has a real 2xx schema
	if _, already := pendingRegistry[opID]; already {
		t.Fatalf("test assumption violated: %s is already in pendingRegistry", opID)
	}
	pendingRegistry[opID] = "TEST: pending-but-has-schema case"
	t.Cleanup(func() { delete(pendingRegistry, opID) })

	err := CheckPartition()
	if err == nil {
		t.Fatal("expected an error when a pending entry's operation has a schema")
	}
	if !strings.Contains(err.Error(), "still in pendingRegistry") {
		t.Errorf("expected the pending-but-scheduled violation, got: %v", err)
	}
}

// TestCheckPartition_OutOfScopeButHasSchemaNotExempt covers the
// "schema-bearing operation opted out of enforcement without an explicit
// schemaExemptOperations entry" violation -- the only real outOfScopeRegistry
// entry with a schema (prometheusMetrics) is already exempt, so this stages
// the non-exempt case on a real, schema-bearing operation instead.
func TestCheckPartition_OutOfScopeButHasSchemaNotExempt(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	const opID = "healthCheck"
	if _, already := outOfScopeRegistry[opID]; already {
		t.Fatalf("test assumption violated: %s is already in outOfScopeRegistry", opID)
	}
	if schemaExemptOperations[opID] {
		t.Fatalf("test assumption violated: %s is already schema-exempt", opID)
	}
	outOfScopeRegistry[opID] = "TEST: out-of-scope-but-has-schema case"
	t.Cleanup(func() { delete(outOfScopeRegistry, opID) })

	err := CheckPartition()
	if err == nil {
		t.Fatal("expected an error when a non-exempt out-of-scope entry's operation has a schema")
	}
	if !strings.Contains(err.Error(), "without being in schemaExemptOperations") {
		t.Errorf("expected the not-exempt violation, got: %v", err)
	}
}

// TestCheckPartition_UnregisteredNoSchema covers the "no schema, and not
// registered anywhere" violation -- every real schema-less operation is
// already in pendingRegistry, so this removes one temporarily to stage the
// gap the check exists to catch.
func TestCheckPartition_UnregisteredNoSchema(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	const opID = "acknowledgeAnomalyAlert" // real, currently-pending, no-schema operation
	if _, isOOS := outOfScopeRegistry[opID]; isOOS {
		t.Fatalf("test assumption violated: %s is already in outOfScopeRegistry", opID)
	}
	original, wasPending := pendingRegistry[opID]
	if !wasPending {
		t.Fatalf("test assumption violated: %s is not in pendingRegistry", opID)
	}
	delete(pendingRegistry, opID)
	t.Cleanup(func() { pendingRegistry[opID] = original })

	err := CheckPartition()
	if err == nil {
		t.Fatal("expected an error when a schema-less operation is registered nowhere")
	}
	if !strings.Contains(err.Error(), "not registered in pendingRegistry") {
		t.Errorf("expected the unregistered-no-schema violation, got: %v", err)
	}
}

// TestCheckAllEnforcedExercised_PropagatesSpecErr covers its own top-of-
// function specErr short-circuit, unreachable through the real spec.
func TestCheckAllEnforcedExercised_PropagatesSpecErr(t *testing.T) {
	setFlag(t, "test.list", "")
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}
	boom := errors.New("TEST: synthetic spec load failure")
	specErr = boom
	t.Cleanup(func() { specErr = nil })

	if err := CheckAllEnforcedExercised(); !errors.Is(err, boom) {
		t.Errorf("expected CheckAllEnforcedExercised to propagate specErr verbatim, got: %v", err)
	}
}

// TestCheckAllEnforcedExercised_NoExercisingTestsEntry covers the
// "enforced operation has no exercisingTests entry at all" branch, distinct
// from the eligible-but-unexercised branch TestCheckAllEnforcedExercised
// already covers -- every real enforced operation already has an entry, so
// this removes one temporarily to stage the gap.
func TestCheckAllEnforcedExercised_NoExercisingTestsEntry(t *testing.T) {
	loadSpec()
	if specErr != nil {
		t.Fatal(specErr)
	}

	exercisedMu.Lock()
	saved := exercised
	exercised = map[string]bool{}
	exercisedMu.Unlock()
	t.Cleanup(func() {
		exercisedMu.Lock()
		exercised = saved
		exercisedMu.Unlock()
	})
	setFlag(t, "test.run", "")

	const opID = "healthCheck"
	original, ok := exercisingTests[opID]
	if !ok {
		t.Fatalf("test assumption violated: %s has no exercisingTests entry to remove", opID)
	}
	delete(exercisingTests, opID)
	t.Cleanup(func() { exercisingTests[opID] = original })

	err := CheckAllEnforcedExercised()
	if err == nil {
		t.Fatal("expected an error when an enforced operation has no exercisingTests entry")
	}
	if !strings.Contains(err.Error(), "no entry in exercisingTests") {
		t.Errorf("expected the no-entry violation message, got: %v", err)
	}
}

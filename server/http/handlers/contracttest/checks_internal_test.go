package contracttest

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
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

package oapiruntime

import (
	"strings"
	"testing"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

// Each test drives the same helper the fuzz body calls: RED with a planted
// defect, GREEN with the real upstream method.

// TestOraclePanic_RedGreen validates the panic oracle (class (a)).
func TestOraclePanic_RedGreen(t *testing.T) {
	// RED: planted panic must be caught and reported.
	r := runOpResult("test-panic", func() error {
		panic("planted panic for oracle validation")
	})
	if opViolation(r) == "" || !strings.Contains(opViolation(r), "PANIC") {
		t.Fatalf("panic oracle GREEN on a planted panic: %+v", r)
	}

	// GREEN: a fn that returns normally must produce no violation.
	r = runOpResult("test-normal", func() error { return nil })
	if v := opViolation(r); v != "" {
		t.Fatalf("panic oracle RED on a normal return: %q", v)
	}
}

// TestOracleHang_RedGreen validates the hang oracle (class (a)) with a short
// watchdog: a blocked fn must time out (RED), a prompt fn must not (GREEN).
func TestOracleHang_RedGreen(t *testing.T) {
	old := opWatchdog
	opWatchdog = 50 * time.Millisecond
	t.Cleanup(func() { opWatchdog = old })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // lets the planted goroutine exit
	r := runOpResult("test-hang", func() error {
		<-release
		return nil
	})
	if !r.timedOut {
		t.Fatal("hang oracle GREEN on a planted hang: timedOut=false")
	}
	if !strings.HasPrefix(opViolation(r), "HANG") {
		t.Fatalf("hang oracle verdict = %q, want HANG prefix", opViolation(r))
	}

	r = runOpResult("test-prompt", func() error { return nil })
	if r.timedOut || opViolation(r) != "" {
		t.Fatalf("hang oracle RED on a prompt fn: %+v", r)
	}
}

// TestOracleIdempotence_RedGreen validates the Email and Date round-trip
// oracles through the helpers the fuzz bodies call.
func TestOracleIdempotence_RedGreen(t *testing.T) {
	validEmail := []byte(`"user@example.com"`)
	validDate := []byte(`"2024-01-15"`)

	// GREEN: the real upstream methods round-trip valid input.
	if v := emailRoundTripViolation(validEmail, realEmailMarshal); v != "" {
		t.Fatalf("GREEN Email: violation on valid round-trip: %s", v)
	}
	if v := dateRoundTripViolation(validDate, realDateMarshal); v != "" {
		t.Fatalf("GREEN Date: violation on valid round-trip: %s", v)
	}

	// RED: a marshaler that changes the value must be reported as a divergence.
	badEmail := func(openapi_types.Email) ([]byte, error) { return []byte(`"other@x.com"`), nil }
	if v := emailRoundTripViolation(validEmail, badEmail); !strings.Contains(v, "IDEMPOTENCE BROKEN") || !strings.Contains(v, "differ") {
		t.Fatalf("RED Email: differing value not reported: %q", v)
	}
	// RED: a marshaler whose output no longer parses.
	garbageEmail := func(openapi_types.Email) ([]byte, error) { return []byte(`42`), nil }
	if v := emailRoundTripViolation(validEmail, garbageEmail); !strings.Contains(v, "re-UnmarshalJSON failed") {
		t.Fatalf("RED Email: unparseable re-marshal not reported: %q", v)
	}
	badDate := func(openapi_types.Date) ([]byte, error) { return []byte(`"2000-02-29"`), nil }
	if v := dateRoundTripViolation(validDate, badDate); !strings.Contains(v, "IDEMPOTENCE BROKEN") || !strings.Contains(v, "differ") {
		t.Fatalf("RED Date: differing value not reported: %q", v)
	}
	garbageDate := func(openapi_types.Date) ([]byte, error) { return []byte(`42`), nil }
	if v := dateRoundTripViolation(validDate, garbageDate); !strings.Contains(v, "re-UnmarshalJSON failed") {
		t.Fatalf("RED Date: unparseable re-marshal not reported: %q", v)
	}
}

// TestOracleEmailMarshalFailure_RedGreen validates the M1 rule: a MarshalJSON
// error after a successful UnmarshalJSON is a violation, except the pinned
// quoted-local-part class (#4797).
func TestOracleEmailMarshalFailure_RedGreen(t *testing.T) {
	failing := func(openapi_types.Email) ([]byte, error) { return nil, errPlanted }

	// RED: an ordinary address whose marshal fails is not the known class.
	if v := emailRoundTripViolation([]byte(`"user@example.com"`), failing); !strings.Contains(v, "IDEMPOTENCE BROKEN") {
		t.Fatalf("RED: marshal failure on a plain address not reported: %q", v)
	}
	// GREEN (tolerated): the real upstream failure on a quoted local part.
	for _, in := range []string{`"\"a b\"@example.com"`, `"\"a@b\"@x.com"`} {
		if v := emailRoundTripViolation([]byte(in), realEmailMarshal); v != "" {
			t.Fatalf("GREEN: known upstream class %s reported: %s", in, v)
		}
	}
	// The tolerance predicate itself: true for the class, false for a valid
	// address and for garbage.
	for in, want := range map[string]bool{
		`a b@example.com`:  true,
		`a@b@x.com`:        true,
		`user@example.com`: false,
		`nonsense`:         false,
		``:                 false,
	} {
		if got := emailNeedsQuotedLocalPart(openapi_types.Email(in)); got != want {
			t.Fatalf("emailNeedsQuotedLocalPart(%q) = %v, want %v", in, got, want)
		}
	}
}

type plantedError string

func (e plantedError) Error() string { return string(e) }

const errPlanted = plantedError("planted marshal failure")

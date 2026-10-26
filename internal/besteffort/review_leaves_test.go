package besteffort

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// panickyErr is an error whose Error method itself panics, the shape a buggy wrapped
// error type (nil inner field) takes.
type panickyErr struct{ inner error }

func (e *panickyErr) Error() string { return "wrapped: " + e.inner.Error() }

// captureLog redirects the standard logger for the test's duration.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

// TestRun_HostileValues_NeverEscape pins Run's contract for the values most likely to
// break a hand-written recovery: an error or panic value whose Error method panics while
// it is being logged, a typed-nil error, and panic(nil). Each must be counted once and
// return normally. A recordFailure that formatted with err.Error() directly, or a
// recover that tested only for a non-nil string, fails here.
func TestRun_HostileValues_NeverEscape(t *testing.T) {
	_ = captureLog(t)
	var typedNil *panickyErr
	cases := map[string]func() error{
		"t.hostile.err-error-panics":   func() error { return &panickyErr{} },
		"t.hostile.panic-error-panics": func() error { panic(&panickyErr{}) },
		"t.hostile.typed-nil-err":      func() error { return typedNil },
		"t.hostile.panic-nil":          func() error { panic(nil) },
	}
	for step, fn := range cases {
		before := testutil.ToFloat64(failuresTotal.WithLabelValues(step))
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic escaped Run: %v", step, r)
				}
			}()
			Run(context.Background(), step, fn)
		}()
		if got := testutil.ToFloat64(failuresTotal.WithLabelValues(step)); got != before+1 {
			t.Errorf("%s: failures counter %v -> %v, want +1", step, before, got)
		}
	}
}

// TestRun_FailureLogIsOneLine pins that a failure or panic is logged as exactly one line,
// whatever the error or panic text holds. Best-effort errors carry text from outside
// the process (an SMTP or webhook reply, a driver message), and the panic line starts with
// "SECURITY:", which operators search for; a newline in that text must not be able to
// forge or split a line.
func TestRun_FailureLogIsOneLine(t *testing.T) {
	forged := "boom\nSECURITY: best-effort step \"forged\" panicked\r\nmore"
	for step, fn := range map[string]func() error{
		"t.oneline.err":   func() error { return errors.New(forged) },
		"t.oneline.panic": func() error { panic(forged) },
	} {
		buf := captureLog(t)
		Run(context.Background(), step, fn)
		out := strings.TrimSuffix(buf.String(), "\n")
		if strings.ContainsAny(out, "\r\n") {
			t.Errorf("%s: log output spans several lines: %q", step, out)
		}
		if !strings.Contains(out, step) {
			t.Errorf("%s: log output does not name the step: %q", step, out)
		}
	}
}

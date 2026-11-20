package dynamic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// replyMarker stands for bytes a hostile target put on the wire and a client library
// copied into its panic value.
const replyMarker = "REPLYBYTES-7f3a"

type replyPanicEngine struct{ value any }

func (p replyPanicEngine) Issue(context.Context, string, string, time.Duration) (Credential, string, error) {
	panic(p.value)
}
func (p replyPanicEngine) Revoke(context.Context, string, string) error { panic(p.value) }
func (p replyPanicEngine) Renew(context.Context, string, string, time.Time) error {
	panic(p.value)
}
func (replyPanicEngine) SupportsNativeExpiry() bool              { return true }
func (replyPanicEngine) BackendType() string                     { return "probe" }
func (replyPanicEngine) IsEphemeralBackend() bool                { return false }
func (replyPanicEngine) RevokeInvalidatesCredential(string) bool { return true }

type replyError struct{ frame string }

func (e replyError) Error() string { return "malformed frame " + e.frame }

// fakeRuntimeError claims to be a runtime.Error (the interface only needs a
// RuntimeError marker method) while its text carries reply bytes.
type fakeRuntimeError struct{ replyError }

func (fakeRuntimeError) RuntimeError() {}

func captureContainLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &logs
}

// The panic value of a client library can carry the bytes of the reply that broke it.
// The log says where (stack) and what class (type), not what the target sent.
func TestContain_LogWithholdsPanicValueThatMayCarryReplyBytes(t *testing.T) {
	values := map[string]any{
		"string":       "unexpected frame " + replyMarker,
		"error":        errors.New("bad reply " + replyMarker),
		"custom":       replyError{frame: replyMarker},
		"sprintf":      fmt.Sprintf("%q", []byte(replyMarker)),
		"stringer-ptr": &replyError{frame: replyMarker},
		"fake-runtime": fakeRuntimeError{replyError{frame: replyMarker}},
	}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			logs := captureContainLog(t)
			e := Contain(replyPanicEngine{value: v})
			_, _, err := e.Issue(context.Background(), "x", "", time.Hour)
			if !errors.Is(err, ErrEngineClientPanic) {
				t.Fatalf("want ErrEngineClientPanic, got %v", err)
			}
			out := logs.String()
			if strings.Contains(out, replyMarker) {
				t.Errorf("log carries reply bytes from the panic value:\n%s", out)
			}
			if !strings.Contains(out, "SECURITY:") || !strings.Contains(out, "panicked in Issue") {
				t.Errorf("log lost the where-line:\n%s", out)
			}
			if !strings.Contains(out, "value withheld") {
				t.Errorf("log should say the value was withheld:\n%s", out)
			}
		})
	}
}

// A runtime error (what an out-of-range read in a client parser raises) is the case the
// operator needs to see: its text holds indices and lengths only, so it stays in the log.
func TestContain_LogKeepsRuntimeErrorText(t *testing.T) {
	logs := captureContainLog(t)
	short := []byte{1, 2}
	n := 5
	e := Contain(replyPanicEngine{value: nil})
	// replyPanicEngine panics with nil, which Go 1.21+ turns into a *runtime.PanicNilError.
	_, _, err := e.Issue(context.Background(), "x", "", time.Hour)
	if !errors.Is(err, ErrEngineClientPanic) {
		t.Fatalf("panic(nil): want ErrEngineClientPanic, got %v", err)
	}
	logs.Reset()

	err = func() (err error) {
		defer RecoverClientPanic("dynamic-secret engine", "probe", "Issue", &err)()
		_ = short[n]
		return nil
	}()
	if !errors.Is(err, ErrEngineClientPanic) {
		t.Fatalf("bounds panic: want ErrEngineClientPanic, got %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "index out of range [5] with length 2") {
		t.Errorf("runtime error text should stay in the log:\n%s", out)
	}
}

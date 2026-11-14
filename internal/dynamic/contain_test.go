package dynamic

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

type panicEngine struct{ op string }

const panicDSN = "postgres://admin:hunter2@db.internal:5432/app"

func (p panicEngine) Issue(context.Context, string, string, time.Duration) (Credential, string, error) {
	if p.op == "Issue" {
		panic("bad reply from " + panicDSN + "\nSECURITY: forged line")
	}
	return Credential{Username: "u"}, "u", nil
}
func (p panicEngine) Revoke(context.Context, string, string) error {
	if p.op == "Revoke" {
		panic("bad reply from " + panicDSN)
	}
	return nil
}
func (p panicEngine) Renew(context.Context, string, string, time.Time) error {
	if p.op == "Renew" {
		panic(errors.New("bad reply from " + panicDSN))
	}
	return nil
}
func (panicEngine) SupportsNativeExpiry() bool { return true }
func (panicEngine) BackendType() string        { return "probe" }
func (panicEngine) IsEphemeralBackend() bool   { return false }
func (p panicEngine) RevokeInvalidatesCredential(string) bool {
	if p.op == "RevokeInvalidatesCredential" {
		panic("x")
	}
	return true
}

func TestContain_ConvertsPanicToTypedErrorWithoutPanicText(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	for _, op := range []string{"Issue", "Revoke", "Renew"} {
		e := Contain(panicEngine{op: op})
		var err error
		switch op {
		case "Issue":
			_, _, err = e.Issue(context.Background(), panicDSN, "", time.Hour)
		case "Revoke":
			err = e.Revoke(context.Background(), panicDSN, "r")
		case "Renew":
			err = e.Renew(context.Background(), panicDSN, "r", time.Now())
		}
		if !errors.Is(err, ErrEngineClientPanic) {
			t.Fatalf("%s: want ErrEngineClientPanic, got %v", op, err)
		}
		var pe *EngineClientPanicError
		if !errors.As(err, &pe) || pe.Name != "probe" || pe.Op != op {
			t.Fatalf("%s: error does not carry engine and operation: %#v", op, err)
		}
		for _, leak := range []string{"hunter2", "db.internal", "forged"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("%s: error leaks %q: %v", op, leak, err)
			}
		}
	}

	out := logs.String()
	if strings.Contains(out, "hunter2") {
		t.Errorf("log carries the DSN password:\n%s", out)
	}
	if !strings.Contains(out, "goroutine") && !strings.Contains(out, "contain") {
		t.Errorf("log should carry the stack:\n%s", out)
	}
	// the injected newline in the panic text must not start a second SECURITY line
	if strings.Count(out, "\nSECURITY:") != 0 {
		t.Errorf("panic text forged a log line:\n%s", out)
	}
}

func TestContain_PassThroughAndIdempotent(t *testing.T) {
	e := Contain(panicEngine{op: "none"})
	if Contain(e) != e {
		t.Fatal("Contain must be idempotent")
	}
	if Contain(nil) != nil {
		t.Fatal("Contain(nil) must stay nil")
	}
	cred, role, err := e.Issue(context.Background(), "", "", time.Hour)
	if err != nil || cred.Username != "u" || role != "u" {
		t.Fatalf("healthy call must pass through: %v %v %v", cred, role, err)
	}
	if !e.SupportsNativeExpiry() || e.BackendType() != "probe" || e.IsEphemeralBackend() {
		t.Fatal("metadata must pass through")
	}
	if e := Contain(panicEngine{op: "RevokeInvalidatesCredential"}); e.RevokeInvalidatesCredential("dsn") {
		t.Fatal("a panic in RevokeInvalidatesCredential must answer false")
	}
}

func TestNewReturnsContainedEngines(t *testing.T) {
	for _, bt := range []string{"postgres", "mysql", "mongodb", "redis"} {
		e, err := New(bt, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := e.(*containedEngine); !ok {
			t.Errorf("New(%q) returned an uncontained %T", bt, e)
		}
	}
}

package rotation

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/dynamic"
)

// panicMySQLConn stands in for an admin connection whose driver panics mid-statement.
type panicMySQLConn struct{ closed *bool }

func (panicMySQLConn) Exec(context.Context, string, ...any) error {
	panic("malformed reply from mysql://admin:hunter2@db.internal:3306/")
}
func (p panicMySQLConn) Close() error { *p.closed = true; return nil }

// #4378 review: the MySQL executor as core gets it (through NewManager, so contained)
// turns a driver panic during Rotate into *dynamic.EngineClientPanicError, still closes
// the connection, and logs the panic with the DSN password masked.
func TestMySQLExecutor_ContainedRotatePanic(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	closed := false
	raw := NewMySQLExecutor("my", "user:pw@tcp(db:3306)/", []string{"app_"})
	raw.newConn = func(context.Context, string) (mysqlConn, error) { return panicMySQLConn{closed: &closed}, nil }
	e, ok := NewManager([]Executor{raw}).Get("my")
	if !ok {
		t.Fatal("executor missing")
	}

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic reached the caller of the contained executor: %v", r)
			}
		}()
		err = e.Rotate(context.Background(), "app_svc", "new-value")
	}()

	var pe *dynamic.EngineClientPanicError
	if !errors.As(err, &pe) || pe.Name != "my" || pe.Op != "Rotate" {
		t.Fatalf("want *dynamic.EngineClientPanicError{my, Rotate}, got %#v", err)
	}
	for _, leak := range []string{"hunter2", "db.internal", "new-value"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
	}
	if !closed {
		t.Error("the connection must still be closed after a contained panic")
	}
	if out := logs.String(); strings.Contains(out, "hunter2") || !strings.Contains(out, "malformed reply") {
		t.Errorf("want the panic logged with the password masked:\n%s", out)
	}
}

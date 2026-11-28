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

// DBCLIENT-PANIC-NOV-3 item 3 (#4133): every database executor, as core gets it
// (through NewManager), turns a client-library panic during Rotate into
// *dynamic.EngineClientPanicError, still releases its admin connection, and keeps the
// panic value (which may carry target reply bytes or the admin DSN) out of both the
// error and the log. MySQL has its own test (mysql_contained_panic_test.go); these are
// the other three sites. The panic is injected at the connection seam (newConn), the
// point where the third-party client would raise it.

const panicValue = "malformed reply from admin:hunter2@db.internal:5432"

type panicPGConn struct{ closed *bool }

func (panicPGConn) Exec(context.Context, string) error { panic(panicValue) }
func (p panicPGConn) Close(context.Context)            { *p.closed = true }

type panicMongoConn struct{ closed *bool }

func (panicMongoConn) UpdateUserPassword(context.Context, string, string) error { panic(panicValue) }
func (p panicMongoConn) Close(context.Context)                                  { *p.closed = true }

type panicRedisConn struct{ closed *bool }

func (panicRedisConn) SetUserPassword(context.Context, string, string) error { panic(panicValue) }
func (p panicRedisConn) Close() error                                        { *p.closed = true; return nil }

func TestDBExecutors_ContainedRotatePanic(t *testing.T) {
	const name = "site"
	cases := []struct {
		backend string
		build   func(closed *bool) Executor
	}{
		{"postgresql", func(closed *bool) Executor {
			e := NewPostgresExecutor(name, "postgres://admin:hunter2@db.internal:5432/app", []string{"app_"})
			e.newConn = func(context.Context, string) (pgConn, error) { return panicPGConn{closed}, nil }
			return e
		}},
		{"mongodb", func(closed *bool) Executor {
			e := NewMongoExecutor(name, "mongodb://admin:hunter2@db.internal:27017/admin", []string{"app_"})
			e.newConn = func(context.Context, string) (mongoConn, error) { return panicMongoConn{closed}, nil }
			return e
		}},
		{"redis", func(closed *bool) Executor {
			e := NewRedisExecutor(name, "redis://admin:hunter2@db.internal:6379/0", []string{"app_"})
			e.newConn = func(context.Context, string) (redisConn, error) { return panicRedisConn{closed}, nil }
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.backend, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			defer log.SetOutput(os.Stderr)

			closed := false
			e, ok := NewManager([]Executor{tc.build(&closed)}).Get(name)
			if !ok {
				t.Fatal("executor missing")
			}
			if e.Type() != tc.backend {
				t.Fatalf("executor type %q, want %q", e.Type(), tc.backend)
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
			if !errors.As(err, &pe) || !errors.Is(err, dynamic.ErrEngineClientPanic) || pe.Name != name || pe.Op != "Rotate" {
				t.Fatalf("want *dynamic.EngineClientPanicError{%s, Rotate}, got %#v", name, err)
			}
			for _, leak := range []string{"hunter2", "db.internal", "malformed", "new-value"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error leaks %q: %v", leak, err)
				}
			}
			if !closed {
				t.Error("the admin connection must still be closed after a contained panic")
			}
			out := logs.String()
			if strings.Contains(out, "hunter2") || strings.Contains(out, "malformed") ||
				!strings.Contains(out, `rotation executor "site" panicked in Rotate`) || !strings.Contains(out, "value withheld") {
				t.Errorf("want the panic logged without its value or the password:\n%s", out)
			}
		})
	}
}

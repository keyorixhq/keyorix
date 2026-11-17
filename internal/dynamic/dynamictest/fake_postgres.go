package dynamictest

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// FakePostgres is a PostgreSQL wire-protocol stub on loopback for tests that
// drive the real internal/dynamic PostgresEngine end to end without a database:
// it declines TLS, accepts any startup without authentication, answers every
// statement with success and records the SQL it received.
type FakePostgres struct {
	Host, Port string

	mu    sync.Mutex
	stmts []string
}

// StartFakePostgres listens on 127.0.0.1 until the test ends. The engine must
// allow private targets (allow_private_network_targets) to reach it.
func StartFakePostgres(t *testing.T) *FakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &FakePostgres{}
	f.Host, f.Port, _ = net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

// Statements returns every SQL text received so far, joined by newlines.
func (f *FakePostgres) Statements() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.stmts, "\n")
}

func (f *FakePostgres) record(sql string) {
	f.mu.Lock()
	f.stmts = append(f.stmts, sql)
	f.mu.Unlock()
}

func (f *FakePostgres) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	be := pgproto3.NewBackend(conn, conn)
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.SSLRequest); ok {
			if _, err := conn.Write([]byte("N")); err != nil {
				return
			}
			continue
		}
		if _, ok := msg.(*pgproto3.StartupMessage); !ok {
			return
		}
		break
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.record(m.String)
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			f.record(m.Query)
			be.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Bind:
			be.Send(&pgproto3.BindComplete{})
		case *pgproto3.Describe:
			be.Send(&pgproto3.NoData{})
		case *pgproto3.Execute:
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Close:
			be.Send(&pgproto3.CloseComplete{})
		case *pgproto3.Terminate:
			return
		}
		if be.Flush() != nil {
			return
		}
	}
}

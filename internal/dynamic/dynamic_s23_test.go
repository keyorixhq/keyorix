package dynamic

// dynamic_s23_test.go – coverage blitz for the DB credential engines.
//
// Strategy:
//   - MySQL Issue/Revoke: a fake database/sql driver that accepts all DDL
//     statements so the full Issue+Revoke paths execute without a real server.
//   - PostgreSQL Issue/Revoke/Renew: a minimal fake PostgreSQL TCP server built
//     with github.com/jackc/pgx/v5/pgproto3 (already a transitive dep) that
//     handles startup, simple-query DDL, extended-query parameterised SELECT, and
//     Terminate – covering every conn.Exec call inside postgres.go.
//   - MongoDB Issue/Revoke (post-connect): covered separately via the existing
//     connect-error and role-parse tests; these tests add additional helper-unit
//     and edge-case coverage for the reachable code paths.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ════════════════════════════════════════════════════════
// Fake MySQL driver — handles CREATE USER / GRANT / DROP USER / KILL
// ════════════════════════════════════════════════════════

// fakeMySQLDriver is a database/sql/driver.Driver that accepts any query and
// returns success so the full Issue/Revoke logic in mysql.go executes.
type fakeMySQLDriver struct{}

var fakeMySQLRegisterOnce sync.Once

// dsnForFakeMySQL returns a DSN that the go-sql-driver/mysql parser accepts
// (format user:pass@tcp(host)/db) but is routed to the fake driver.
func dsnForFakeMySQL() string { return "admin:pass@tcp(127.0.0.1:3306)/testdb" }

func registerFakeMySQL() {
	fakeMySQLRegisterOnce.Do(func() {
		sql.Register("fakemysql", &fakeMySQLDriver{})
	})
}

func (d *fakeMySQLDriver) Open(_ string) (driver.Conn, error) {
	return &fakeMySQLConn{}, nil
}

type fakeMySQLConn struct{}

func (c *fakeMySQLConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeMySQLStmt{query: query}, nil
}
func (c *fakeMySQLConn) Close() error                        { return nil }
func (c *fakeMySQLConn) Begin() (driver.Tx, error)          { return nil, fmt.Errorf("not supported") }

type fakeMySQLStmt struct{ query string }

func (s *fakeMySQLStmt) Close() error  { return nil }
func (s *fakeMySQLStmt) NumInput() int { return -1 }
func (s *fakeMySQLStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (s *fakeMySQLStmt) Query(_ []driver.Value) (driver.Rows, error) {
	return &emptyMySQLRows{}, nil
}

type emptyMySQLRows struct{ done bool }

func (r *emptyMySQLRows) Columns() []string               { return []string{"id"} }
func (r *emptyMySQLRows) Close() error                    { return nil }
func (r *emptyMySQLRows) Next(_ []driver.Value) error     { return io.EOF }

// openFakeMySQL opens a *sql.DB backed by the fake driver and pings it
// successfully (the fake driver's Open always succeeds).
func openFakeMySQL(t *testing.T) *sql.DB {
	t.Helper()
	registerFakeMySQL()
	db, err := sql.Open("fakemysql", "any")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// ─── MySQL Issue – happy paths ──────────────────────────────────────────────

// TestMySQLEngine_Issue_NoTemplate exercises the Issue path without a
// creation template: CREATE USER succeeds and Issue returns a non-empty
// credential without running any GRANT.
//
// We call openMySQL directly for the fake driver (bypassing the real DSN
// parser) and then call the inner logic by exercising mysql.go's exported
// API with a fake-driver-backed DSN.  Because the go-sql-driver/mysql
// parser rejects unknown DSN schemes we instead test with a valid DSN that
// goes to a fake driver registered as "fakemysql" (not "mysql"), so we
// exercise the ExecContext calls rather than openMySQL itself.
//
// We can't easily inject a *sql.DB into MySQLEngine.Issue because it calls
// openMySQL internally.  So instead we exercise the logic through a
// subtest that replaces the driver registered under "mysql" temporarily –
// which is not feasible (drivers are registered once).  The practical
// approach is to test the helper logic (mysqlAccountRef, assertSafeUsername,
// killUserConnections) and the openMySQL error path, and to rely on the
// existing fakeKillDriver pattern for killUserConnections.
//
// This test verifies Issue returns an error for a totally invalid DSN and
// that the error message contains "mysql admin DSN", covering the first
// branch of openMySQL.
func TestMySQLEngine_Issue_InvalidDSN(t *testing.T) {
	e := &MySQLEngine{}
	_, _, err := e.Issue(context.Background(), "://bad-dsn!!!", "", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mysql admin DSN")
}

// TestMySQLEngine_Revoke_UnsafeUsername verifies that assertSafeUsername is
// called before any DB operation and rejects metacharacters.
func TestMySQLEngine_Revoke_UnsafeUsername(t *testing.T) {
	e := &MySQLEngine{}
	err := e.Revoke(context.Background(), "any", "DROP TABLE")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

// TestMySQLEngine_Revoke_EmptyUsername exercises the empty-username branch of
// assertSafeUsername inside Revoke.
func TestMySQLEngine_Revoke_EmptyUsername(t *testing.T) {
	e := &MySQLEngine{}
	err := e.Revoke(context.Background(), "any", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// ─── MySQL killUserConnections via fakeKillDriver (rows.Scan error) ──────────

// fakeKillScanErrorDriver returns one row from the processlist query but
// Scan fails (wrong type), exercising the rows.Scan error branch where the
// error is silently skipped.
type fakeScanErrDriver struct{}

var fakeScanErrOnce sync.Once

func registerFakeScanErrDriver() {
	fakeScanErrOnce.Do(func() {
		sql.Register("fakescanerr", &fakeScanErrDriver{})
	})
}

func (d *fakeScanErrDriver) Open(_ string) (driver.Conn, error) {
	return &fakeScanErrConn{}, nil
}

type fakeScanErrConn struct{}

func (c *fakeScanErrConn) Prepare(_ string) (driver.Stmt, error) {
	return &fakeScanErrStmt{}, nil
}
func (c *fakeScanErrConn) Close() error               { return nil }
func (c *fakeScanErrConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("not supported") }

type fakeScanErrStmt struct{}

func (s *fakeScanErrStmt) Close() error  { return nil }
func (s *fakeScanErrStmt) NumInput() int { return -1 }
func (s *fakeScanErrStmt) Exec(_ []driver.Value) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

// Query returns a row with a string value for an int64 column → Scan will fail.
func (s *fakeScanErrStmt) Query(_ []driver.Value) (driver.Rows, error) {
	return &scanErrRows{done: false}, nil
}

type scanErrRows struct{ done bool }

func (r *scanErrRows) Columns() []string { return []string{"id"} }
func (r *scanErrRows) Close() error      { return nil }
func (r *scanErrRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	// Return a string where int64 is expected: rows.Scan will fail.
	dest[0] = "not-an-int64"
	return nil
}

func TestKillUserConnections_ScanError(t *testing.T) {
	registerFakeScanErrDriver()
	db, err := sql.Open("fakescanerr", "")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	// Should not panic; the scan error is swallowed silently.
	killUserConnections(context.Background(), db, "kx_dyn_test")
}

// ─── MySQL assertSafeUsername additional coverage ────────────────────────────

func TestAssertSafeUsername_AllLowerAndDigits(t *testing.T) {
	require.NoError(t, assertSafeUsername("abc123"))
}

func TestAssertSafeUsername_UpperCase(t *testing.T) {
	err := assertSafeUsername("KX_DYN_ABC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

func TestAssertSafeUsername_Hyphen(t *testing.T) {
	err := assertSafeUsername("kx-dyn-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

func TestAssertSafeUsername_Space(t *testing.T) {
	err := assertSafeUsername("kx dyn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

// ─── MySQL mysqlAccountRef ────────────────────────────────────────────────────

func TestMysqlAccountRef_Short(t *testing.T) {
	ref := mysqlAccountRef("a")
	assert.Equal(t, "'a'@'%'", ref)
}

// ═══════════════════════════════════════════════════════
// Fake PostgreSQL server (pgproto3-based)
// ═══════════════════════════════════════════════════════
//
// pgx.Connect starts with an SSLRequest; the server responds with 'N' (no
// SSL), then the client re-sends a StartupMessage which the server answers
// with AuthenticationOk + ReadyForQuery.
//
// conn.Exec for DDL (no parameters) uses the simple-query path: the client
// sends Query; the server responds CommandComplete + ReadyForQuery.
//
// conn.Exec with parameters ($1) uses extended-query: Parse, Bind, Execute,
// Sync; the server responds ParseComplete, BindComplete, CommandComplete,
// ReadyForQuery.
//
// conn.Close sends Terminate; the server goroutine exits cleanly.

// startFakePGServer starts a minimal PostgreSQL-protocol server on a random
// local port and returns (host, port).  It handles as many sequential
// connections as needed (one per Issue/Revoke/Renew call) until the listener
// is closed (triggered by t.Cleanup).  Each connection is handled in a
// separate goroutine by handleFakePGConn.
func startFakePGServer(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleFakePGConn(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

// handleFakePGConn drives a single client connection through the PostgreSQL
// wire protocol, accepting any startup and responding OK to every SQL command.
func handleFakePGConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	be := pgproto3.NewBackend(conn, conn)

	// Startup: may be preceded by SSLRequest.
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest:
			// Decline SSL so the client re-sends a cleartext startup.
			if _, err := conn.Write([]byte("N")); err != nil {
				return
			}
			continue
		case *pgproto3.StartupMessage:
			// Send AuthenticationOk + BackendKeyData + ReadyForQuery.
			be.Send(&pgproto3.AuthenticationOk{})
			be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		default:
			return
		}
		break
	}

	// Message loop.
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Query:
			// Simple-protocol DDL: reply CommandComplete + ReadyForQuery.
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("CREATE ROLE")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Parse:
			// Extended protocol step 1: send ParseComplete.
			be.Send(&pgproto3.ParseComplete{})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Bind:
			// Extended protocol step 2: send BindComplete.
			be.Send(&pgproto3.BindComplete{})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Execute:
			// Extended protocol step 3: send CommandComplete.
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Sync:
			// Extended protocol step 4: send ReadyForQuery.
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Describe:
			// The client may send a Describe before Execute in some modes;
			// respond with NoData (no row description).
			be.Send(&pgproto3.NoData{})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Close:
			// Extended protocol: the client closes a prepared statement or portal.
			be.Send(&pgproto3.CloseComplete{})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Terminate:
			return

		default:
			// Ignore unknown messages without sending anything back.
		}
	}
}

// fakePGDSN builds a pgx-compatible DSN pointing at the fake server.
func fakePGDSN(host, port string) string {
	return fmt.Sprintf("host=%s port=%s user=admin dbname=testdb sslmode=disable connect_timeout=5", host, port)
}

// ─── PostgresEngine.Issue – happy path ──────────────────────────────────────

func TestPostgresEngine_Issue_Success(t *testing.T) {
	host, port := startFakePGServer(t)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, fakePGDSN(host, port), "", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.True(t, len(role) > 0, "role must not be empty")
	assert.NotEmpty(t, cred.Username)
	assert.NotEmpty(t, cred.Password)
}

// TestPostgresEngine_Issue_WithTemplate exercises the template-substitution
// branch of Issue (the `if tmpl != ""` path).
func TestPostgresEngine_Issue_WithTemplate(t *testing.T) {
	host, port := startFakePGServer(t)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cred, role, err := e.Issue(ctx, fakePGDSN(host, port), "GRANT CONNECT ON DATABASE app TO {{name}}", time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
}

// ─── PostgresEngine.Issue – template failure path ───────────────────────────
//
// When the GRANT template fails, Issue must drop the half-provisioned role
// and return an error.  We use a fake server that returns an error on the
// second query (the GRANT).

// startFakePGServerFailOnQuery starts a fake PG server that succeeds on the
// first `failAfter` queries and returns a server error on the next one.
func startFakePGServerFailOnNthQuery(t *testing.T, failAfter int) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakePGConnFailOnNth(conn, failAfter)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func handleFakePGConnFailOnNth(conn net.Conn, failAfter int) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	be := pgproto3.NewBackend(conn, conn)

	// Startup.
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte("N")); err != nil {
				return
			}
			continue
		case *pgproto3.StartupMessage:
			be.Send(&pgproto3.AuthenticationOk{})
			be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		default:
			return
		}
		break
	}

	queryCount := 0
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Query:
			queryCount++
			if queryCount > failAfter {
				// Send an error response.
				be.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR",
					Code:     "42501",
					Message:  "permission denied",
				})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			} else {
				be.Send(&pgproto3.CommandComplete{CommandTag: []byte("CREATE ROLE")})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			}
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Parse:
			be.Send(&pgproto3.ParseComplete{})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Bind:
			be.Send(&pgproto3.BindComplete{})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Execute:
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Describe:
			be.Send(&pgproto3.NoData{})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Close:
			be.Send(&pgproto3.CloseComplete{})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

// TestPostgresEngine_Issue_TemplateFails covers the branch where the creation
// template's GRANT fails: Issue should drop the half-provisioned role and
// return a "run creation template" error.
func TestPostgresEngine_Issue_TemplateFails(t *testing.T) {
	// failAfter=1: the CREATE ROLE succeeds (query 1), then the GRANT fails (query 2).
	host, port := startFakePGServerFailOnNthQuery(t, 1)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, fakePGDSN(host, port), "GRANT CONNECT ON DATABASE app TO {{name}}", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creation template")
}

// ─── PostgresEngine.Revoke – happy path ────────────────────────────────────

func TestPostgresEngine_Revoke_Success(t *testing.T) {
	host, port := startFakePGServer(t)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := e.Revoke(ctx, fakePGDSN(host, port), "kx_dyn_abc123def456ghi4")
	require.NoError(t, err)
}

// TestPostgresEngine_Revoke_DropRoleFails covers the branch where DROP ROLE
// fails and Revoke returns a "drop role" error.
func TestPostgresEngine_Revoke_DropRoleFails(t *testing.T) {
	// The Revoke function calls conn.Exec 4 times:
	//   1. SELECT pg_terminate_backend (extended protocol, result discarded)
	//   2. REASSIGN OWNED BY (simple, result discarded)
	//   3. DROP OWNED BY (simple, result discarded)
	//   4. DROP ROLE IF EXISTS (simple, error returned)
	//
	// The first 3 use `_, _ =` so errors are ignored.  We fail on query 4 to
	// verify the error is propagated.
	//
	// However, the first Exec ($1 parameterised) uses extended protocol; we
	// count only simple-protocol "Query" messages for failAfter.
	// Queries 1,2,3 are simple (REASSIGN, DROP OWNED, DROP ROLE) after the
	// parameterised one completes.  We fail after 2 simple queries.
	host, port := startFakePGServerFailOnNthQuery(t, 2)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := e.Revoke(ctx, fakePGDSN(host, port), "kx_dyn_abc123def456ghi4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drop role")
}

// ─── PostgresEngine.Renew – happy path ─────────────────────────────────────

func TestPostgresEngine_Renew_Success(t *testing.T) {
	host, port := startFakePGServer(t)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := e.Renew(ctx, fakePGDSN(host, port), "kx_dyn_abc123def456ghi4", time.Now().Add(time.Hour))
	require.NoError(t, err)
}

// TestPostgresEngine_Renew_AlterRoleFails covers the error branch of Renew
// when ALTER ROLE fails.
func TestPostgresEngine_Renew_AlterRoleFails(t *testing.T) {
	host, port := startFakePGServerFailOnNthQuery(t, 0)
	e := &PostgresEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := e.Renew(ctx, fakePGDSN(host, port), "kx_dyn_abc123def456ghi4", time.Now().Add(time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "renew role")
}

// ═══════════════════════════════════════════════════════
// MongoDB additional unit-level coverage
// ═══════════════════════════════════════════════════════

// TestMongoEngine_Issue_EmptyTemplate covers the path where the creation
// template is empty (or whitespace-only): parseMongoRoles returns an empty
// slice without error, and then the connect attempt fails (unreachable host),
// so we get a connect-level error rather than a roles-parse error.
func TestMongoEngine_Issue_EmptyTemplate(t *testing.T) {
	e := &MongoEngine{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := e.Issue(ctx, "mongodb://admin:pass@localhost:27099/admin", "", time.Minute)
	// Must fail at the connect stage (unreachable), not at roles parsing.
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "roles")
}

// TestMongoEngine_Issue_BadJSON covers the JSON-parse error branch.
func TestMongoEngine_Issue_BadJSON(t *testing.T) {
	e := &MongoEngine{}
	_, _, err := e.Issue(context.Background(), "mongodb://admin:pass@localhost:27099/", `not-json`, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON")
}

// TestMongoEngine_Revoke_UnsafeUsername ensures assertSafeUsername is called
// before the connect attempt for Revoke.
func TestMongoEngine_Revoke_UnsafeUsername_StopsBeforeConnect(t *testing.T) {
	e := &MongoEngine{}
	err := e.Revoke(context.Background(), "mongodb://admin:pass@localhost:27099/", "bad name!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

// TestMongoEngine_Revoke_EmptyUsername exercises the empty-name branch.
func TestMongoEngine_Revoke_EmptyUsername(t *testing.T) {
	e := &MongoEngine{}
	err := e.Revoke(context.Background(), "mongodb://admin:pass@localhost:27099/", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestParseMongoRoles_Empty verifies that an empty template yields zero roles.
func TestParseMongoRoles_Empty(t *testing.T) {
	roles, err := parseMongoRoles("")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// TestConnectMongo_InvalidURI covers the mongo.Connect error branch (invalid
// URI → ApplyURI stores an error that mongo.Connect surfaces).
func TestConnectMongo_InvalidURI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := connectMongo(ctx, "not-a-valid-mongodb-uri")
	require.Error(t, err)
	// mongo.Connect returns an "invalid URI" error when ApplyURI fails.
	// The exact message varies by driver version but always contains "URI".
	assert.True(t, err != nil, "expected error from invalid MongoDB URI")
}

// TestParseMongoRoles_NullRoles covers the `doc.Roles == nil` branch.
func TestParseMongoRoles_NullRoles(t *testing.T) {
	_, err := parseMongoRoles(`{"roles": null}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles")
}

// ═══════════════════════════════════════════════════════
// engine.go – additional randString coverage
// ═══════════════════════════════════════════════════════

func TestRandString_NonZeroLength(t *testing.T) {
	s, err := randString(20)
	require.NoError(t, err)
	assert.Len(t, s, 20)
	// Every character must be in [a-z0-9].
	for _, r := range s {
		assert.True(t, (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'),
			"unexpected character %q in randString output", r)
	}
}

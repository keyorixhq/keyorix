// mysql.go — the MySQL rotation executor (ADR-047). Rotate sets an account's password
// via ALTER USER against an admin connection opened from the backend's DSN. Account
// names and the password are emitted as single-quoted MySQL string literals with
// internal quotes and backslashes doubled, so neither can break out of the statement
// (injection-safe in both the default and NO_BACKSLASH_ESCAPES sql_modes).
package rotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" sql driver
)

// mysqlConn is the slice of a MySQL connection the executor uses — an interface seam so
// the driver stays contained here and tests inject a fake.
type mysqlConn interface {
	Exec(ctx context.Context, query string) error
	Close() error
}

// MySQLExecutor rotates MySQL account passwords.
type MySQLExecutor struct {
	name        string
	dsn         string
	allowedRefs []string
	// newConn opens an admin connection; nil uses the real database/sql conn. Tests inject.
	newConn func(ctx context.Context, dsn string) (mysqlConn, error)
}

// NewMySQLExecutor builds a MySQL rotation executor. dsn is the admin connection string
// (operator-provided, env-sourced, scoped to the accounts it may rotate). allowedRefs,
// when non-empty, restricts which account names this backend will rotate (prefix
// allowlist); a rotation backend must declare one (fail-closed).
func NewMySQLExecutor(name, dsn string, allowedRefs []string) *MySQLExecutor {
	return &MySQLExecutor{name: name, dsn: dsn, allowedRefs: allowedRefs}
}

func (e *MySQLExecutor) Name() string { return e.name }
func (e *MySQLExecutor) Type() string { return "mysql" }

func (e *MySQLExecutor) conn(ctx context.Context) (mysqlConn, error) {
	if e.newConn != nil {
		return e.newConn(ctx, e.dsn)
	}
	db, err := sql.Open("mysql", e.dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql: open: %w", err)
	}
	return &mysqlDBConn{db: db}, nil
}

// Rotate sets account `ref`'s password to newValue via ALTER USER. ref is the account
// name as `user` or `user@host` (host defaults to '%').
func (e *MySQLExecutor) Rotate(ctx context.Context, ref, newValue string) error {
	if ref == "" {
		return fmt.Errorf("mysql: account name (ref) is required")
	}
	if newValue == "" {
		return fmt.Errorf("mysql: new value is required")
	}
	// Fail closed: a rotation backend runs privileged DDL with an admin DSN, so it must
	// carry an explicit allow-list.
	if len(e.allowedRefs) == 0 {
		return fmt.Errorf("mysql: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return fmt.Errorf("mysql: account %q is not permitted by this backend's allowed_refs", ref)
	}
	if e.dsn == "" {
		return fmt.Errorf("mysql: backend %q has no admin DSN configured", e.name)
	}
	c, err := e.conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	user, host, _ := strings.Cut(ref, "@")
	if host == "" {
		host = "%"
	}
	// ALTER USER 'user'@'host' IDENTIFIED BY 'pw' — every component a quoted literal
	// with internal quotes/backslashes doubled, so none can escape the statement.
	q := fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY %s",
		quoteMySQLString(user), quoteMySQLString(host), quoteMySQLString(newValue))
	if err := c.Exec(ctx, q); err != nil {
		// The new password is a quoted literal in q; a driver error can echo the
		// failing statement verbatim. Redact before wrapping so the live credential
		// never egresses via the rotation-failure SIEM audit / notification
		// broadcast (#132).
		return redactSQLError("mysql", ref, err)
	}
	return nil
}

// quoteMySQLString renders s as a single-quoted MySQL string literal with internal
// backslashes and single-quotes doubled — injection-safe under both the default and
// NO_BACKSLASH_ESCAPES sql_modes.
func quoteMySQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return "'" + s + "'"
}

// mysqlDBConn adapts *sql.DB to the mysqlConn seam.
type mysqlDBConn struct{ db *sql.DB }

func (m *mysqlDBConn) Exec(ctx context.Context, query string) error {
	_, err := m.db.ExecContext(ctx, query)
	return err
}
func (m *mysqlDBConn) Close() error { return m.db.Close() }

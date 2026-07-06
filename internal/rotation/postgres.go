// postgres.go — the PostgreSQL rotation executor (ADR-047). Rotate sets a role's
// password via ALTER ROLE against an admin connection opened from the backend's DSN.
// DDL cannot bind parameters, so the role name is quoted as an identifier and the
// password as a string literal, both escaped, so neither can break out of the statement.
package rotation

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// pgConn is the slice of a pgx connection the executor uses — an interface seam so the
// driver stays contained here and tests inject a fake.
type pgConn interface {
	Exec(ctx context.Context, sql string) error
	Close(ctx context.Context)
}

// PostgresExecutor rotates PostgreSQL role passwords.
type PostgresExecutor struct {
	name        string
	dsn         string
	allowedRefs []string
	// newConn opens an admin connection; nil uses the real pgx connection. Tests inject.
	newConn func(ctx context.Context, dsn string) (pgConn, error)
}

// NewPostgresExecutor builds a PostgreSQL rotation executor. dsn is the admin connection
// string (operator-provided, env-sourced, scoped to the roles it may rotate). allowedRefs,
// when non-empty, restricts which role names this backend will rotate (prefix allowlist).
func NewPostgresExecutor(name, dsn string, allowedRefs []string) *PostgresExecutor {
	return &PostgresExecutor{name: name, dsn: dsn, allowedRefs: allowedRefs}
}

func (e *PostgresExecutor) Name() string { return e.name }
func (e *PostgresExecutor) Type() string { return "postgresql" }

func (e *PostgresExecutor) conn(ctx context.Context) (pgConn, error) {
	if e.newConn != nil {
		return e.newConn(ctx, e.dsn)
	}
	c, err := pgx.Connect(ctx, e.dsn)
	if err != nil {
		return nil, fmt.Errorf("postgresql: connect: %w", err)
	}
	return &pgxConn{c: c}, nil
}

// Rotate sets role `ref`'s password to newValue via ALTER ROLE.
func (e *PostgresExecutor) Rotate(ctx context.Context, ref, newValue string) error {
	if ref == "" {
		return fmt.Errorf("postgresql: role name (ref) is required")
	}
	if newValue == "" {
		return fmt.Errorf("postgresql: new value is required")
	}
	// Fail closed: a rotation backend runs privileged DDL with an admin DSN, so it must
	// carry an explicit allow-list — an unbounded backend would let any caller who can
	// configure a secret's rotation_ref rotate every role the DSN can reach.
	if len(e.allowedRefs) == 0 {
		return fmt.Errorf("postgresql: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return fmt.Errorf("postgresql: role %q is not permitted by this backend's allowed_refs", ref)
	}
	if e.dsn == "" {
		return fmt.Errorf("postgresql: backend %q has no admin DSN configured", e.name)
	}
	c, err := e.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)

	// DDL can't bind parameters; quote the identifier and the password literal so neither
	// can escape the statement.
	sql := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", quoteIdentifier(ref), quoteLiteral(newValue))
	if err := c.Exec(ctx, sql); err != nil {
		// The new password is a quoted literal in sql; a driver error can echo the
		// failing statement (e.g. a syntax error near the literal) verbatim. Redact
		// before wrapping so the live credential never egresses via the rotation-
		// failure SIEM audit / notification broadcast (#132).
		return redactSQLError("postgresql", ref, err)
	}
	return nil
}

// quoteIdentifier renders s as a double-quoted PostgreSQL identifier (internal quotes
// doubled), so a crafted role name cannot break out into SQL. This is layer TWO of
// defense in depth: layer ONE is core.validateRotationRef
// (internal/core/rotation_executor.go), which already rejects quotes/backslashes/
// semicolons (plus path/query metacharacters and control characters) in the ref at
// configuration time, before it is ever persisted. Keep both — this quoting must not be
// removed just because the earlier layer also covers it; this function is the only
// defense against a role name reaching this backend through any future write path.
func quoteIdentifier(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// quoteLiteral renders s as a single-quoted PostgreSQL string literal (internal quotes
// doubled). Relies on standard_conforming_strings (the default), so backslashes are
// literal. See quoteIdentifier's comment above: this is layer TWO of defense in depth
// alongside core.validateRotationRef.
func quoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

// pgxConn adapts *pgx.Conn to the pgConn seam.
type pgxConn struct{ c *pgx.Conn }

func (p *pgxConn) Exec(ctx context.Context, sql string) error {
	_, err := p.c.Exec(ctx, sql)
	return err
}
func (p *pgxConn) Close(ctx context.Context) { _ = p.c.Close(ctx) }

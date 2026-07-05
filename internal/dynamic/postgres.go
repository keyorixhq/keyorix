package dynamic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgresEngine mints short-lived LOGIN roles on a target PostgreSQL database
// using the admin DSN, and drops them on revoke.
type PostgresEngine struct{}

func (e *PostgresEngine) BackendType() string      { return "postgres" }
func (e *PostgresEngine) IsEphemeralBackend() bool { return false }

// RevokeInvalidatesCredential is always true: DROP ROLE really removes the
// account, so a subsequent connection attempt with it fails immediately.
func (e *PostgresEngine) RevokeInvalidatesCredential(_ string) bool { return true }

// SupportsNativeExpiry is true: PostgreSQL roles carry a VALID UNTIL, so the
// credential disables itself at expiry even without the auto-revoke sweeper.
func (e *PostgresEngine) SupportsNativeExpiry() bool { return true }

// Issue creates a `kx_dyn_<random>` LOGIN role with a random password and a
// VALID UNTIL of now+ttl, then runs the operator's creation template ({{name}} →
// the role). Role name and password are crypto/rand from an identifier/quote-safe
// alphabet, so neither can break out of the SQL; the role name is additionally
// quoted via pgx.Identifier. The template is operator-authored (trusted) and is
// the documented SQL-injection trust boundary.
func (e *PostgresEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (Credential, string, error) {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return Credential{}, "", fmt.Errorf("connect to target: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	suffix, err := randString(16)
	if err != nil {
		return Credential{}, "", err
	}
	role := "kx_dyn_" + suffix
	password, err := randString(32)
	if err != nil {
		return Credential{}, "", err
	}
	ident := pgx.Identifier{role}.Sanitize()
	validUntil := time.Now().Add(ttl).UTC().Format(time.RFC3339)

	if _, err := conn.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s' VALID UNTIL '%s'", ident, password, validUntil)); err != nil {
		return Credential{}, "", fmt.Errorf("create role: %w", err)
	}

	if tmpl := strings.TrimSpace(creationTemplate); tmpl != "" {
		grant := strings.ReplaceAll(tmpl, "{{name}}", ident)
		if _, err := conn.Exec(ctx, grant); err != nil {
			// Don't leak a half-provisioned role if the template fails.
			_, _ = conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ident))
			return Credential{}, "", fmt.Errorf("run creation template: %w", err)
		}
	}
	return Credential{Username: role, Password: password}, role, nil
}

// Revoke terminates the role's sessions, reassigns/drops its owned objects, then
// drops the role. Each step is best-effort except the final DROP ROLE, whose
// failure is reported so the lease is marked revoke_failed rather than silently
// left active.
func (e *PostgresEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect to target: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	ident := pgx.Identifier{roleName}.Sanitize()
	_, _ = conn.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", roleName)
	_, _ = conn.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", ident))
	_, _ = conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", ident))
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ident)); err != nil {
		return fmt.Errorf("drop role %s: %w", roleName, err)
	}
	return nil
}

// Renew extends the role's VALID UNTIL to expiresAt, so the credential stays
// usable for the renewed window without re-issuing.
func (e *PostgresEngine) Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect to target: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	ident := pgx.Identifier{roleName}.Sanitize()
	validUntil := expiresAt.UTC().Format(time.RFC3339)
	if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s VALID UNTIL '%s'", ident, validUntil)); err != nil {
		return fmt.Errorf("renew role %s: %w", roleName, err)
	}
	return nil
}

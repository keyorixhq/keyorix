package dynamic

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// MySQLEngine mints short-lived MySQL accounts using the admin DSN and drops them
// on revoke. Unlike PostgreSQL (whose roles carry a VALID UNTIL that disables them
// at expiry), MySQL has no per-account expiry timestamp, so a lease's TTL is
// enforced solely by the dynamic-secrets auto-revoke sweeper (ADR-035) — the
// sweeper must be enabled for MySQL credentials to expire. The DROP at revoke is
// the authoritative teardown either way.
//
// The admin DSN is in go-sql-driver/mysql format, e.g.
// "admin:pass@tcp(db.internal:3306)/". Username and password are crypto/rand from
// an identifier/quote-safe alphabet (lowercase+digits), so neither can break out
// of the surrounding quotes; the creation template is operator-authored (trusted)
// and is the documented SQL-injection trust boundary.
type MySQLEngine struct{}

func (e *MySQLEngine) BackendType() string      { return "mysql" }
func (e *MySQLEngine) IsEphemeralBackend() bool { return false }

// RevokeInvalidatesCredential is always true: DROP USER really removes the
// account, so a subsequent connection attempt with it fails immediately.
func (e *MySQLEngine) RevokeInvalidatesCredential(_ string) bool { return true }

// SupportsNativeExpiry is false: MySQL users have no VALID UNTIL, so lease expiry
// is enforced only by the auto-revoke sweeper (which must be enabled).
func (e *MySQLEngine) SupportsNativeExpiry() bool { return false }

// mysqlHost is the host part of the created account ('user'@'%'). Restricting it
// further is a deployment concern best expressed via the creation template/grants.
const mysqlHost = "%"

// mysqlAccountRef renders the quoted account reference 'user'@'%' used in CREATE
// USER / GRANT / DROP USER. user is crypto/rand from a quote-free alphabet, so it
// cannot break out of the quotes. assertSafeUsername is a fail-closed second layer
// (MySQL has no pgx.Identifier.Sanitize equivalent): even if the alphabet were
// ever widened, an unexpected character aborts before any SQL is built.
func mysqlAccountRef(user string) string {
	return fmt.Sprintf("'%s'@'%s'", user, mysqlHost)
}

// assertSafeUsername rejects any username containing a character outside the
// generated alphabet ([a-z0-9_]), so the fmt.Sprintf'd account name can never be
// an injection vector regardless of where the name came from.
// assertSafeUsername is a shared defense-in-depth guard for every engine: a
// dynamic username must be the quote-free [a-z0-9_] alphabet the generator
// produces, so a tampered stored role name can never carry injection metacharacters
// into a target command. Backend-agnostic (used by MySQL, MongoDB, Redis).
func assertSafeUsername(user string) error {
	if user == "" {
		return fmt.Errorf("empty dynamic-secret username")
	}
	for _, r := range user {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return fmt.Errorf("refusing unsafe dynamic-secret username %q", user)
		}
	}
	return nil
}

func (e *MySQLEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (Credential, string, error) {
	db, err := openMySQL(ctx, adminDSN)
	if err != nil {
		return Credential{}, "", err
	}
	defer func() { _ = db.Close() }()

	suffix, err := randString(16)
	if err != nil {
		return Credential{}, "", err
	}
	user := "kx_dyn_" + suffix // 7+16 = 23 chars, within MySQL's 32-char limit
	if err := assertSafeUsername(user); err != nil {
		return Credential{}, "", err
	}
	password, err := randString(32)
	if err != nil {
		return Credential{}, "", err
	}

	ref := mysqlAccountRef(user)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE USER %s IDENTIFIED BY '%s'", ref, password)); err != nil {
		return Credential{}, "", fmt.Errorf("create user: %w", err)
	}

	if tmpl := strings.TrimSpace(creationTemplate); tmpl != "" {
		// {{name}} → the full account reference, e.g. 'kx_dyn_xxx'@'%', so templates
		// read naturally: GRANT SELECT ON app.* TO {{name}};
		grant := strings.ReplaceAll(tmpl, "{{name}}", ref)
		if _, err := db.ExecContext(ctx, grant); err != nil {
			// Don't leak a half-provisioned account if the template fails.
			_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s", ref))
			return Credential{}, "", fmt.Errorf("run creation template: %w", err)
		}
	}
	return Credential{Username: user, Password: password}, user, nil
}

// Revoke kills the account's live sessions (best-effort), then drops it. DROP USER
// removes the account and all its privileges. roleName is the bare username.
func (e *MySQLEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	if err := assertSafeUsername(roleName); err != nil {
		return err
	}
	db, err := openMySQL(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	killUserConnections(ctx, db, roleName)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s", mysqlAccountRef(roleName))); err != nil {
		return fmt.Errorf("drop user %s: %w", roleName, err)
	}
	return nil
}

// Renew is a no-op for MySQL: accounts carry no VALID UNTIL, so the renewed expiry
// is enforced entirely by the lease's updated ExpiresAt + the auto-revoke sweep.
func (e *MySQLEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

// openMySQL opens and verifies a connection to the target using the admin DSN.
func openMySQL(ctx context.Context, adminDSN string) (*sql.DB, error) {
	if _, err := mysql.ParseDSN(adminDSN); err != nil {
		return nil, fmt.Errorf("invalid mysql admin DSN: %w", err)
	}
	db, err := sql.Open("mysql", adminDSN)
	if err != nil {
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	return db, nil
}

// killUserConnections terminates the account's active sessions so a revoke takes
// effect immediately. Best-effort: errors are ignored (the authoritative teardown
// is DROP USER). The user filter is parameterized.
func killUserConnections(ctx context.Context, db *sql.DB, user string) {
	rows, err := db.QueryContext(ctx, "SELECT id FROM information_schema.processlist WHERE user = ?", user)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("KILL %d", id))
	}
}

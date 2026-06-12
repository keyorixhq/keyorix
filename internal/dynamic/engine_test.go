package dynamic

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Backends(t *testing.T) {
	pg, err := New("postgres")
	require.NoError(t, err)
	assert.Equal(t, "postgres", pg.BackendType())

	my, err := New("mysql")
	require.NoError(t, err)
	assert.Equal(t, "mysql", my.BackendType())

	_, err = New("redis")
	require.Error(t, err, "an unsupported backend is rejected")
}

func TestMySQLAccountRef(t *testing.T) {
	// The {{name}} substitution renders a properly-quoted account reference, and a
	// quote-free username (as randString produces) cannot escape the quotes.
	ref := mysqlAccountRef("kx_dyn_abc123")
	assert.Equal(t, "'kx_dyn_abc123'@'%'", ref)

	grant := strings.ReplaceAll("GRANT SELECT ON app.* TO {{name}};", "{{name}}", ref)
	assert.Equal(t, "GRANT SELECT ON app.* TO 'kx_dyn_abc123'@'%';", grant)
}

func TestAssertSafeUsername(t *testing.T) {
	require.NoError(t, assertSafeUsername("kx_dyn_abc123"))
	for _, bad := range []string{"", "kx'dyn", "kx`dyn", "kx dyn", "kx-dyn", "KXDYN", "kx\\dyn"} {
		assert.Error(t, assertSafeUsername(bad), "must reject %q", bad)
	}
}

func TestMySQLEngine_RevokeRejectsUnsafeRole(t *testing.T) {
	// Defense-in-depth: a tampered/unsafe role name from storage is rejected before
	// any SQL is constructed or any connection is opened.
	err := (&MySQLEngine{}).Revoke(context.Background(), "admin:p@tcp(h:3306)/", "evil'; DROP")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe mysql username")
}

func TestMySQLEngine_InvalidDSNRejected(t *testing.T) {
	e := &MySQLEngine{}
	// A malformed DSN is rejected by ParseDSN before any connection attempt.
	_, _, err := e.Issue(context.Background(), "not a valid dsn at all", "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mysql admin DSN")
}

func TestRandString_QuoteFreeAlphabet(t *testing.T) {
	// The credential alphabet must never contain a quote/backslash, which is what
	// makes the fmt.Sprintf'd SQL safe in both engines.
	s, err := randString(256)
	require.NoError(t, err)
	require.Len(t, s, 256)
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Fatalf("unexpected character %q in randString output", r)
		}
	}
}

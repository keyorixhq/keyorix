// Package pgpriv gates Postgres tests that need a database role allowed to
// SET session_replication_role (a superuser, or a role with GRANT SET ON
// PARAMETER). The sandbox kpg role has neither, so those tests cannot pass
// there; CI's Postgres is a superuser, where they must run.
package pgpriv

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
)

// EnvRequire makes a missing privilege fatal instead of a skip (any CI sets
// CI=true as well). Set it wherever the Postgres role is meant to be a
// superuser, so a skip can never hide these tests.
const EnvRequire = "KEYORIX_REQUIRE_PG_SUPERUSER"

// probeSQL is what the probe runs; SET LOCAL makes the change end with the tx.
const probeSQL = "SET LOCAL session_replication_role = replica"

// RequireReplicationRolePrivilege returns when the connected role may
// SET session_replication_role = replica. Otherwise it skips the test naming
// the missing privilege, or fails it when CI=true or KEYORIX_REQUIRE_PG_SUPERUSER=1.
//
// db is a *sql.DB or anything with a DB() (*sql.DB, error) method (*gorm.DB).
// The probe runs in a rolled-back transaction, once per process: every test of
// a run uses the same role.
func RequireReplicationRolePrivilege(t testing.TB, db any) {
	t.Helper()
	sqlDB, err := toSQLDB(db)
	if err != nil {
		t.Fatalf("pgpriv: cannot get *sql.DB to probe session_replication_role: %v", err)
	}
	requireWith(t, cachedProbe(func() error { return probeReplicationRole(sqlDB) }), os.Getenv)
}

// requireWith applies the skip/fail policy to a probe result (nil = allowed).
func requireWith(t testing.TB, probe func() error, getenv func(string) string) {
	t.Helper()
	err := probe()
	if err == nil {
		return
	}
	msg := fmt.Sprintf("this Postgres role may not SET session_replication_role = replica "+
		"(needs SUPERUSER or GRANT SET ON PARAMETER session_replication_role): %v", err)
	if getenv("CI") == "true" || getenv(EnvRequire) == "1" {
		t.Fatalf("%s; refusing to skip because CI=true or %s=1, the CI Postgres role must be a superuser", msg, EnvRequire)
	}
	t.Skip(msg + " (set " + EnvRequire + "=1 to make this a failure)")
}

var (
	probeMu     sync.Mutex
	probeDone   bool
	probeResult error
)

// cachedProbe runs p on the first call and returns the same result afterwards.
func cachedProbe(p func() error) func() error {
	return func() error {
		probeMu.Lock()
		defer probeMu.Unlock()
		if !probeDone {
			probeResult, probeDone = p(), true
		}
		return probeResult
	}
}

func probeReplicationRole(db *sql.DB) error {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, probeSQL)
	return err
}

func toSQLDB(db any) (*sql.DB, error) {
	switch v := db.(type) {
	case *sql.DB:
		return v, nil
	case interface{ DB() (*sql.DB, error) }:
		return v.DB()
	}
	return nil, fmt.Errorf("unsupported type %T", db)
}

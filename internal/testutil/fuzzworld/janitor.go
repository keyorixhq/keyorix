package fuzzworld

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Janitor cleans up PostgreSQL schemas that OpenPostgres left behind when a fuzz
// worker died before its tb.Cleanup ran (a panic, an OOM-kill, a SIGKILL). On a
// SHARED server used by other sessions this matters: leaked schemas accumulate
// and eventually exhaust the catalog.
//
// SAFETY, by construction: the janitor only ever considers a schema whose name
// starts with prefix+"_" AND parses as OpenPostgres's own "<prefix>_<pid>_<seq>"
// shape. It REFUSES (drops nothing, returns an error) if prefix is empty, is
// "public"/"pg_*"/"information_schema", or contains a character that is not safe
// in an identifier — so it can never touch another session's or the system's
// schemas. It preserves keepPID (pass os.Getpid()), the live worker's own
// schemas. See JanitorSchemas.
//
// Schemas carry no creation timestamp in the catalog, so age is derived from the
// pid embedded in the name, not from a clock: a schema whose pid is neither the
// caller's nor a live process is from a dead worker. keepPID covers the common
// single-live-process case; LivePIDs lets a caller preserve several.

// ErrUnsafePrefix is returned when a janitor prefix could match a schema the
// janitor must never drop.
var ErrUnsafePrefix = errors.New("fuzzworld janitor: refusing an unsafe/empty prefix")

var reservedSchemaPrefixes = []string{"public", "pg_", "information_schema"}

// JanitorSchemas drops every PostgreSQL schema under prefix that belongs to a
// pid other than one in keepPIDs. It returns the dropped schema names. dsn is a
// server DSN (any database); schemas are server-scoped per database, so the DSN
// must point at the same database the workers used.
func JanitorSchemas(dsn, prefix string, keepPIDs ...int) ([]string, error) {
	if err := validatePrefix(prefix); err != nil {
		return nil, err
	}
	keep := map[int]bool{}
	for _, p := range keepPIDs {
		keep[p] = true
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, err
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()

	var names []string
	// starts_with is index-safe and avoids LIKE metacharacter pitfalls.
	if err := db.Raw(
		"SELECT nspname FROM pg_namespace WHERE starts_with(nspname, ?) ORDER BY nspname",
		prefix+"_",
	).Scan(&names).Error; err != nil {
		return nil, err
	}

	var dropped []string
	for _, name := range names {
		pid, ok := pidFromSchemaName(name, prefix)
		if !ok {
			continue // not OpenPostgres's shape; leave it alone
		}
		if keep[pid] {
			continue
		}
		// Re-assert the prefix on the exact name we are about to drop: belt and
		// suspenders against a catalog row that slipped past starts_with.
		if !strings.HasPrefix(name, prefix+"_") {
			continue
		}
		if err := db.Exec("DROP SCHEMA IF EXISTS " + quoteSchemaIdent(name) + " CASCADE").Error; err != nil {
			return dropped, fmt.Errorf("drop schema %s: %w", name, err)
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

// validatePrefix rejects empty, reserved and unsafe prefixes.
func validatePrefix(prefix string) error {
	if prefix == "" {
		return ErrUnsafePrefix
	}
	for _, r := range reservedSchemaPrefixes {
		if prefix == strings.TrimSuffix(r, "_") || strings.HasPrefix(prefix, r) {
			return fmt.Errorf("%w: %q is reserved", ErrUnsafePrefix, prefix)
		}
	}
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("%w: %q has a non-identifier character", ErrUnsafePrefix, prefix)
		}
	}
	return nil
}

// pidFromSchemaName parses OpenPostgres's "<prefix>_<pid>_<seq>" and returns the
// pid. ok is false if the name is not that shape.
func pidFromSchemaName(name, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(name, prefix+"_")
	if !ok {
		return 0, false
	}
	parts := strings.Split(rest, "_")
	if len(parts) != 2 {
		return 0, false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return 0, false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return 0, false
	}
	return pid, true
}

// quoteSchemaIdent double-quotes a schema identifier. The name has already been
// validated to be of the "<prefix>_<pid>_<seq>" shape (prefix is identifier-safe,
// pid and seq are digits), so this is defence in depth, not the only guard.
func quoteSchemaIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// SelfPID is os.Getpid(), the pid a live harness passes as keepPID.
func SelfPID() int { return os.Getpid() }

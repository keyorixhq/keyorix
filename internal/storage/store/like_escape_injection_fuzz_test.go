package store

// FuzzLikeEscapeInjection is a Go-vs-SQL differential over the LIKE-injection escaper (#r124):
// escapeLIKE / escapeLike neutralise the SQL LIKE metacharacters (%, _, \) so a caller-supplied
// search term written into a `... LIKE '%' || term || '%' ESCAPE '\'` filter (ListSecrets,
// GetAuditLogs, user search) matches only the literal term and cannot widen the result set with an
// injected wildcard. The escapers had integration unit tests but no fuzzer.
//
// Two sound oracles:
//
//   - ESCAPER CONSISTENCY: the two independent implementations (escapeLIKE's sequential
//     ReplaceAll in entry.go and escapeLike's strings.Replacer in local_users.go) must produce the
//     same output for every input. A divergence between the copies is a drift bug.
//   - LIKE-INJECTION DIFFERENTIAL (the headline): under a REAL SQLite engine, a substring search
//     built exactly as production builds it -- `%` + escapeLIKE(s) + `%` with `ESCAPE '\'` -- must
//     match candidate c precisely when c literally contains s (Go's strings.Contains). SQL LIKE
//     matching where Contains does not means an unescaped %/_ injected a wildcard (the injection
//     bug); the reverse means over-escaping broke a legitimate literal match. case_sensitive_like
//     is ON so the wildcard-escaping property is tested in isolation from LIKE's default
//     case-folding. Only the equality is asserted, so it cannot false-positive.
//
// DB-backed (in-memory SQLite) but lightweight -- one reused connection. NUL bytes and invalid
// UTF-8 are skipped: SQLite's C-string / UTF-8 handling of those differs from Go's byte semantics
// for reasons unrelated to wildcard escaping, and admitting them would be an unsound confound.

import (
	"strings"
	"testing"
	"unicode/utf8"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func FuzzLikeEscapeInjection(f *testing.F) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1) // one connection so the PRAGMA below persists across queries
	}
	if e := db.Exec("PRAGMA case_sensitive_like = ON").Error; e != nil {
		f.Fatalf("pragma case_sensitive_like: %v", e)
	}

	sqlLikeMatch := func(candidate, pattern string) bool {
		var m int
		if e := db.Raw("SELECT (? LIKE ? ESCAPE '\\')", candidate, pattern).Scan(&m).Error; e != nil {
			f.Fatalf("LIKE query (candidate=%q pattern=%q): %v", candidate, pattern, e)
		}
		return m == 1
	}

	for _, sd := range []struct{ s, c string }{
		{"abc", "xabcy"}, {"a%c", "axyzc"}, {"a_c", "abc"}, {"100%", "you win 100% today"},
		{"under_score", "an under_score here"}, {"back\\slash", "a back\\slash b"},
		{"", "anything"}, {"%", "no percent here"}, {"_", "z"}, {"a", "A"}, {"secret.", "secret_backup.read"},
	} {
		f.Add(sd.s, sd.c)
	}

	f.Fuzz(func(t *testing.T, s, c string) {
		// SQLite text handling of NUL / invalid UTF-8 diverges from Go byte semantics for reasons
		// unrelated to wildcard escaping — skip, to keep the SQL differential sound.
		if strings.IndexByte(s, 0) >= 0 || strings.IndexByte(c, 0) >= 0 || !utf8.ValidString(s) || !utf8.ValidString(c) {
			return
		}

		// Oracle 1: the two escaper implementations must agree.
		if a, b := escapeLIKE(s), escapeLike(s); a != b {
			t.Fatalf("ESCAPER DRIFT: escapeLIKE(%q)=%q but escapeLike(%q)=%q", s, a, s, b)
		}

		// Oracle 2: SQL LIKE with the production-shaped escaped pattern must agree with a literal
		// substring search.
		pattern := "%" + escapeLIKE(s) + "%"
		got := sqlLikeMatch(c, pattern)
		want := strings.Contains(c, s)
		if got != want {
			t.Fatalf("LIKE-INJECTION DIFFERENTIAL: s=%q c=%q pattern=%q -> SQL LIKE=%v but strings.Contains=%v", s, c, pattern, got, want)
		}
	})
}

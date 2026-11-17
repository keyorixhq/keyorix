package pgdsn

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

var appNameCounter atomic.Int64

// UniqueApplicationName returns an application_name no other test process or
// call shares: <prefix>_<pid>_<n>.
//
// A test that counts or waits on backends (pg_stat_activity) must count only
// its own. datname = current_database() is not enough: go test runs packages in
// parallel against the one KEYORIX_TEST_PG_DSN database, and schema isolation
// does not separate backends, so another package's lock waiters, snapshots and
// connections all match it (PG-TEST-ISOLATION-1, after AUDIT-LONGREADER-PG-1).
// Tag the connections under test with WithApplicationName and filter
// pg_stat_activity on application_name = <this name>.
func UniqueApplicationName(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), appNameCounter.Add(1))
}

// WithApplicationName returns dsn with application_name set to name, in either
// DSN form KEYORIX_TEST_PG_DSN may take (postgres:// URL or keyword/value). An
// application_name the DSN already carries is replaced.
func WithApplicationName(dsn, name string) string {
	if isURLDSN(dsn) {
		u, err := url.Parse(dsn)
		if err != nil {
			// Same fixed message as replaceURLDBName: the error text can quote the password.
			panic("pgdsn: cannot parse URL DSN (details withheld: the error text can contain the password; percent-encode reserved characters in the password)")
		}
		q := u.Query()
		q.Set("application_name", name)
		u.RawQuery = q.Encode()
		return u.String()
	}
	var kept []string
	for _, t := range scanKeywordValue(dsn) {
		if t.key != "application_name" {
			kept = append(kept, dsn[t.start:t.end])
		}
	}
	kept = append(kept, "application_name="+quoteKVValue(name))
	return strings.Join(kept, " ")
}

//go:build taintoverlay

package dynamic_test

// Input-to-sink taint harness for the dynamic-secret engines (see
// internal/fuzzutil/taint). The fuzz input picks a backend, a DSN option name
// from a mechanically mined vocabulary (testdata/taint-keys.txt: every
// identifier-like string literal in the pgx, mongo-driver and go-sql-driver
// sources) and the oracle marker is the option's value. The harness does not
// know which options read files: any option whose value reaches a file path,
// command or query fails the iteration, and so does a host flow from any option
// other than the ones in taintHostKeys (which name the destination itself).
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintAdminDSN ./internal/dynamic

import (
	"context"
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

//go:embed testdata/taint-keys.txt
var taintKeysRaw string

var taintKeys = strings.Fields(taintKeysRaw)

// taintHostKeys are the DSN options that name the destination host. Every DSN
// below dials the literal 127.0.0.1, so the marker can reach a host sink only
// through an option value; for these options that is the admin's chosen
// destination (SSRF-guarded at dial time). A host flow from any other option
// redirects the connection and fails the iteration.
var taintHostKeys = map[string]bool{"host": true, "hostaddr": true}

func FuzzTaintAdminDSN(f *testing.F) {
	for sel := uint8(0); sel < 4; sel++ {
		f.Add(sel, uint16(0), "a") // no seed names a file option
	}
	f.Fuzz(func(t *testing.T, sel uint8, keyIdx uint16, extra string) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		defer taint.Check(t.Fatalf)
		key := taintKeys[int(keyIdx)%len(taintKeys)]
		// Rules are package-global and FuzzTaintMySQLServerInfile resets them, so
		// each iteration installs its own.
		taint.ResetRules()
		if taintHostKeys[key] {
			taint.Allow(taint.Rule{Class: taint.Host, Why: "option " + key + " names the admin_dsn destination host"})
		}
		m := taint.Marker()
		x := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, extra)
		var backend, dsn string
		switch sel % 4 {
		case 0:
			backend, dsn = "postgres", "postgres://u:p@127.0.0.1:1/db?sslmode=disable&"+key+"="+m+"&x="+x
		case 1:
			backend, dsn = "postgres", "host=127.0.0.1 port=1 user=u password=p dbname=db sslmode=disable "+key+"="+m
		case 2:
			backend, dsn = "mongodb", "mongodb://u:p@127.0.0.1:1/db?tls=true&"+key+"="+m+"&x="+x
		default:
			backend, dsn = "mysql", "u:p@tcp(127.0.0.1:1)/db?"+key+"="+m
		}
		eng, err := dynamic.New(backend, true, true)
		if err != nil {
			t.Skip(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		// A driver panic on a hostile DSN (e.g. go-sql-driver "strict mode has
		// been removed") is a separate defect class from a taint flow; contain it
		// here so it does not mask the oracle, and count it.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("driver panic contained: %v", r)
				}
			}()
			_ = eng.Revoke(ctx, dsn, "r")
		}()
	})
}

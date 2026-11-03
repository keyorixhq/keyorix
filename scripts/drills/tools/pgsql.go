//go:build ignore

// pgsql is a minimal psql stand-in for the drills, for hosts without a psql client (the sandboxed
// sessions): it runs ONE SQL string against a PostgreSQL database behind the server's back.
//
// Usage: PGPASSWORD=... go run pgsql.go <exec|query> <postgres-url-without-password> <sql>
//
//	exec   runs the statement, prints nothing, exits non-zero on error (psql -q -v ON_ERROR_STOP=1)
//	query  prints each row's columns joined by "|", one row per line, no header (psql -At)
//
// The password travels in the environment, never on argv (ps shows argv).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	if len(os.Args) != 4 || (os.Args[1] != "exec" && os.Args[1] != "query") {
		fmt.Fprintln(os.Stderr, "usage: pgsql <exec|query> <postgres-url> <sql>")
		os.Exit(2)
	}
	mode, url, sql := os.Args[1], os.Args[2], os.Args[3]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgsql: bad url:", err)
		os.Exit(2)
	}
	if pw := os.Getenv("PGPASSWORD"); pw != "" {
		cfg.Password = pw
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgsql: connect:", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
	// The simple query protocol returns every value in text form, as psql prints it.
	results, err := conn.PgConn().Exec(ctx, sql).ReadAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgsql:", err)
		os.Exit(1)
	}
	if mode == "exec" {
		return
	}
	for _, r := range results {
		for _, row := range r.Rows {
			cols := make([]string, len(row))
			for i, v := range row {
				cols[i] = string(v)
			}
			fmt.Println(strings.Join(cols, "|"))
		}
	}
}

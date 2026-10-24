package rotation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestQuoteLiteral_StandardConformingStringsOff_Postgres is the real-server twin of
// quote.TestQuoteLiteral_SafeWithStandardConformingStringsOff: on a session with
// standard_conforming_strings=off it sends "SELECT <quoteLiteral(p)>" the way
// PostgresExecutor.Rotate sends its ALTER ROLE (pgx Exec with no arguments, so the
// simple query protocol, which runs every ;-separated statement) and requires exactly
// one result whose value is p. Read-only: the payload's second statement is a SELECT.
// Gated on KEYORIX_TEST_PG_DSN.
func TestQuoteLiteral_StandardConformingStringsOff_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.Exec(ctx, "SET standard_conforming_strings = off"); err != nil {
		t.Fatalf("SET standard_conforming_strings: %v", err)
	}

	for _, p := range []string{
		`\'; SELECT 4242; --`,
		`x\`,
		`a'b\'c`,
		"plain-Alnum_123!@#$%^&*-_=+",
	} {
		results, err := c.PgConn().Exec(ctx, "SELECT "+quoteLiteral(p)).ReadAll()
		if err != nil {
			t.Errorf("quoteLiteral(%q) = %s: server error %v", p, quoteLiteral(p), err)
			continue
		}
		if len(results) != 1 {
			t.Errorf("quoteLiteral(%q) = %s: server ran %d statements, want 1", p, quoteLiteral(p), len(results))
			continue
		}
		rows := results[0].Rows
		if len(rows) != 1 || len(rows[0]) != 1 || string(rows[0][0]) != p {
			t.Errorf("quoteLiteral(%q) = %s: server decoded %q", p, quoteLiteral(p), rows)
		}
	}
}

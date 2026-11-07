package solewriter

import "testing"

// TestClassifyStatement_SemicolonInALiteralIsARead covers #3978: a read whose
// literal holds a ';' (the role-permission trigger-integrity check's
// concat_ws('; ', ...), rolled back every 30 s) is a read, not a string of
// several statements. Red before the lexer: every row was a fenced write.
func TestClassifyStatement_SemicolonInALiteralIsARead(t *testing.T) {
	for _, sql := range []string{
		`SELECT pg_catalog.concat_ws('; ', CASE WHEN c.relkind <> 'r' THEN 'x' END) AS problem FROM pg_catalog.pg_class c WHERE c.oid = (pg_catalog.quote_ident($2) || '.system_metadata')::pg_catalog.regclass`,
		// The integrity check's own shapes: '' inside a literal, a function body
		// compared as a literal.
		`SELECT 'system_metadata has triggers other than the retention-anchor one and the single_writer fence''s (' || 'a; b' || ')'`,
		`SELECT 1 FROM pg_catalog.pg_proc fp WHERE fp.prosrc = 'BEGIN PERFORM 1; RETURN NULL; END;'`,
		`SELECT 'a;b';`,
		`SELECT 'a;b' ;; ` + "\n",
		`SELECT E'a\'; b'`,
		`SELECT e'\\;'`,
		`SELECT $$a; b$$`,
		`SELECT $fn$ BEGIN DELETE FROM roles; END $fn$`,
		`SELECT $a$ $$ ; $b$ $a$`,
		`SELECT "a;b" FROM t`,
		`SELECT "a""; DELETE FROM roles" FROM t`,
		"SELECT 1 -- ; DELETE FROM roles\n",
		"SELECT 1 /* ; DELETE FROM roles */",
		"SELECT 1 /* /* */ ; DELETE FROM roles */",
		`SELECT B'1;0', X'3b', N'n;n', U&'u;u'`,
		`SELECT a$b FROM t WHERE x = $1`,
		// A backslash not right before a quote ends a plain string in the same
		// place whatever standard_conforming_strings says (the integrity check's
		// pg_get_triggerdef regex).
		`SELECT pg_catalog.substring(d, ' FOR EACH ROW WHEN \((.*)\) EXECUTE ')`,
		`SELECT 'a\b;c'`,
	} {
		if got := classifyStatement(sql, nil); got != stmtRead {
			t.Errorf("classifyStatement(%q) = %d, want a read (%d)", sql, got, stmtRead)
		}
	}
}

// TestClassifyStatement_AdversarialStaysFenced is the safety side of the
// lexer: a second statement hidden behind a literal or a comment, and any text
// the lexer cannot read with certainty, stays a fenced write. The rows marked
// "pre-#3978" were classified as reads before the lexer (a verb glued to a
// comment, a line comment ended by \r, a nested block comment).
func TestClassifyStatement_AdversarialStaysFenced(t *testing.T) {
	for _, sql := range []string{
		// A real second statement after a literal.
		`SELECT 'a;b'; DELETE FROM roles`,
		`SELECT 'a;b'; SELECT 1`,
		`SELECT $$a;b$$; DELETE FROM roles`,
		`SELECT "a;b"; DELETE FROM roles`,
		`SELECT E'a\\'; DELETE FROM roles`,
		`SELECT 'it''s'; DELETE FROM roles`,
		`SELECT 1; -- trailing comment`,
		// A backslash right before a quote outside an E-prefixed string: with
		// standard_conforming_strings off, \' does not end the literal.
		`SELECT 'a\'; DELETE FROM roles; --'`,
		`SELECT xE'a\'; DELETE FROM roles; --'`,
		`SELECT 'a\''; DELETE FROM roles; --'`,
		`SELECT 'a\\'; DELETE FROM roles`,
		// Unterminated quotes, dollar quotes, identifiers, comments.
		`SELECT 'a; DELETE FROM roles`,
		`SELECT E'a\`,
		`SELECT $$a; DELETE FROM roles`,
		`SELECT $a$ x $b$; DELETE FROM roles`,
		`SELECT "a; DELETE FROM roles`,
		`SELECT 1 /* ; DELETE FROM roles`,
		`SELECT 1 /* /* */ ; DELETE FROM roles`,
		// A '$' that is not a parameter, an identifier's or a dollar quote.
		`SELECT $ ; DELETE FROM roles`,
		`SELECT $a ; DELETE FROM roles`,
		// '$' inside an identifier opens no dollar quote.
		`SELECT a$b$ ; DELETE FROM roles; SELECT $b$`,
		// Comments do not hide what follows them.
		"SELECT 1 -- x\n; DELETE FROM roles",
		"SELECT 1 -- x\r; DELETE FROM roles",
		"SELECT 1 /* /* */ */ ; DELETE FROM roles",
		// pre-#3978: a leading comment ended by \r, a nested leading comment,
		// a verb glued to a comment or to unusual white space.
		"-- x\rDELETE FROM roles",
		"/* /* */ SELECT 1 */ DELETE FROM roles",
		"DELETE/**/FROM roles",
		"DELETE\fFROM roles",
		"DELETE\rFROM roles",
		"/**/DELETE FROM roles",
		// Names spelled with escapes.
		`DELETE FROM U&"\0072oles"`,
		`SELECT U&"a;b"; DELETE FROM roles`,
		// A literal inside a bookkeeping-only SET list.
		`UPDATE "machine_identity_credentials" SET "last_used_at"='x where y', "revoked"=true WHERE id = 1`,
		`UPDATE "machine_identity_credentials" SET "last_used_at"=$q$ where $q$, "revoked"=true WHERE id = 1`,
		// Transaction control behind a comment stays itself.
		"ROLLBACK /* x */ TO SAVEPOINT sp1; DELETE FROM roles",
	} {
		if got := classifyStatement(sql, nil); got != stmtFencedWrite {
			t.Errorf("classifyStatement(%q) = %d, want a fenced write (%d)", sql, got, stmtFencedWrite)
		}
	}
}

// TestClassifyStatement_CommentsDoNotChangeTransactionControl: with comments
// blanked out, a comment inside ROLLBACK TO or AND CHAIN does not turn it into
// a plain end (which would count the outer transaction's writes as committed
// before its COMMIT).
func TestClassifyStatement_CommentsDoNotChangeTransactionControl(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want stmtKind
	}{
		{"ROLLBACK /* x */ TO SAVEPOINT sp1", stmtRead},
		{"ROLLBACK -- x\nTO sp1", stmtRead},
		{"COMMIT AND CHAIN /* x */", stmtEndChain},
		{"/* c */ BEGIN", stmtBegin},
	} {
		if got := classifyStatement(tc.sql, nil); got != tc.want {
			t.Errorf("classifyStatement(%q) = %d, want %d", tc.sql, got, tc.want)
		}
	}
}

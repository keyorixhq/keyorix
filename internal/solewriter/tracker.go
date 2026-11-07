package solewriter

// tracker.go — the server's own writes to the security tables, seen
// synchronously (docs/specs/single-writer-cache.md §1.6).
//
// Authoritative caches (PR 3) may skip their confirming read only if every
// write this process makes to a fenced table invalidates them before the call
// that made it returns. Per-call-site eviction has missed sites before
// (INV-MW-08, #2518), so this does not rely on it. Instead a pgx QueryTracer,
// installed on every connection a single-writer server opens
// (config.ResolvePostgresConnConfig), watches every statement's SQL:
//
//   - a statement that can write and names a fenced table (classifyWrite)
//     marks its connection dirty and raises Inflight at once, before it runs;
//   - when the connection's transaction ends (COMMIT/ROLLBACK, or the
//     statement itself when it runs outside a transaction), Gen is bumped and
//     Inflight lowered.
//
// A cache entry is valid only if Inflight is 0 and the entry was filled at the
// current Gen; a fill that overlapped any such write is not stored
// (Tracker.BeginFill). So a revocation through the server is effective for
// every request that starts after the revoking call returned.
//
// A savepoint rollback (ROLLBACK TO, GORM's failed nested Transaction) is not
// an end: the outer transaction goes on and its writes stay in flight until
// its COMMIT. COMMIT / ROLLBACK ... AND CHAIN ends one transaction and opens
// the next.
//
// What this does not see, stated: pgx batches (SendBatch: only the audit
// pipeline, which writes no fenced table), pgconn-level calls, SQL-level
// PREPARE / EXECUTE (unused), a SELECT of a function that writes a fenced
// table, and a trigger on an unfenced table that writes a fenced one (the
// server defines neither; adding one needs CREATE or the TRIGGER privilege,
// and either runs in the server's tagged session, so the fence lets it
// through). A string holding several statements is counted as a fenced write
// whatever it holds. The database side catches anything missed:
// every fenced write bumps the epoch, and the poller flushes all entries on
// every epoch move it sees; one this process did not account for is also
// counted as an unattributed bump (Guard.UnattributedBumps). A
// cascading foreign key from an unfenced parent into a fenced table would be
// such a write; TestFencedTables_NoCascadeFromUnfencedParent forbids it.

import (
	"context"
	"database/sql/driver"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// Tracker counts this process's committed writes to fenced tables.
type Tracker struct {
	gen      atomic.Uint64
	inflight atomic.Int64
	// commits counts finished fenced transactions; the poller compares it with
	// epoch movement to find unattributed bumps.
	commits atomic.Uint64

	mu    sync.Mutex
	conns map[*pgx.Conn]*connState
}

type connState struct {
	inTx  bool
	dirty bool
}

// NewTracker returns an idle tracker.
func NewTracker() *Tracker { return &Tracker{conns: map[*pgx.Conn]*connState{}} }

// Gen is the current generation: it moves after every finished fenced write.
func (t *Tracker) Gen() uint64 { return t.gen.Load() }

// Inflight is the number of connections inside a fenced write right now.
func (t *Tracker) Inflight() int64 { return t.inflight.Load() }

// Flush invalidates every entry (an unattributed bump, a lapse).
func (t *Tracker) Flush() { t.gen.Add(1) }

// Fill is an in-progress cache fill: Store reports whether the result may be
// kept, i.e. no fenced write started or finished while it was read.
type Fill struct {
	t   *Tracker
	gen uint64
	ok  bool
}

// BeginFill starts a fill. Read the database after calling it.
func (t *Tracker) BeginFill() Fill {
	return Fill{t: t, gen: t.gen.Load(), ok: t.inflight.Load() == 0}
}

// Gen is the generation the entry is stored under.
func (f Fill) Gen() uint64 { return f.gen }

// Store reports whether the fill may be stored.
func (f Fill) Store() bool {
	return f.ok && f.t.inflight.Load() == 0 && f.t.gen.Load() == f.gen
}

// Valid reports whether an entry filled at gen may be served now.
func (t *Tracker) Valid(gen uint64) bool {
	return t.inflight.Load() == 0 && t.gen.Load() == gen
}

// TraceQueryStart implements pgx.QueryTracer.
func (t *Tracker) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	kind := classifyStatement(data.SQL, data.Args)
	if kind == stmtRead {
		return ctx
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.conns[conn]
	switch kind {
	case stmtBegin:
		if st == nil {
			st = &connState{}
			t.conns[conn] = st
		}
		st.inTx = true
	case stmtFencedWrite:
		if st == nil {
			st = &connState{}
			t.conns[conn] = st
		}
		if !st.dirty {
			st.dirty = true
			t.inflight.Add(1)
		}
	}
	return context.WithValue(ctx, traceKindKey{}, kind)
}

type traceKindKey struct{}

// TraceQueryEnd implements pgx.QueryTracer.
func (t *Tracker) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, _ pgx.TraceQueryEndData) {
	kind, _ := ctx.Value(traceKindKey{}).(stmtKind)
	// A connection that died during any statement, a read included, ends
	// its transaction: left in the map, its write would stay in flight for
	// good (caches off, the canary blind).
	closed := conn.IsClosed()
	if (kind == stmtRead || kind == 0) && !closed {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.conns[conn]
	if st == nil {
		return
	}
	end := kind == stmtEnd || kind == stmtEndChain || (kind == stmtFencedWrite && !st.inTx) || closed
	if !end {
		return
	}
	if st.dirty {
		// Gen moves before Inflight drops, so a reader never sees the write
		// finished at the old generation.
		t.gen.Add(1)
		t.commits.Add(1)
		t.inflight.Add(-1)
	}
	delete(t.conns, conn)
	if kind == stmtEndChain && !conn.IsClosed() {
		t.conns[conn] = &connState{inTx: true}
	}
}

type stmtKind int

const (
	stmtRead stmtKind = iota + 1
	stmtBegin
	stmtEnd
	stmtFencedWrite
	stmtOtherWrite
	// stmtEndChain ends the transaction and starts the next one at once
	// (COMMIT / ROLLBACK ... AND CHAIN).
	stmtEndChain
)

// endKind sorts a statement that starts with a transaction-ending verb.
// ROLLBACK TO [SAVEPOINT] (GORM's failed nested Transaction) undoes part of a
// transaction that goes on: not an end, or the outer transaction's writes
// would count as committed before its COMMIT (REVIEW-SINGLE-WRITER-1 F3).
func endKind(s string) stmtKind {
	f := strings.Fields(strings.ToLower(strings.TrimRight(s, "; \t\n")))
	if len(f) > 0 && f[0] == "rollback" {
		i := 1
		if i < len(f) && (f[i] == "work" || f[i] == "transaction") {
			i++
		}
		if i < len(f) && f[i] == "to" {
			return stmtRead
		}
	}
	if n := len(f); n >= 2 && f[n-2] == "and" && f[n-1] == "chain" {
		return stmtEndChain
	}
	return stmtEnd
}

var writeVerbs = map[string]bool{
	"insert": true, "update": true, "delete": true, "truncate": true, "merge": true,
	"with": true, "copy": true, "alter": true, "drop": true, "create": true, "call": true, "do": true,
}

var dmlInsideRE = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(insert|update|delete|merge)([^a-z0-9_]|$)`)

var fencedNameRE = func() *regexp.Regexp {
	var alts []string
	for _, t := range FencedTables {
		alts = append(alts, regexp.QuoteMeta(t.Name))
	}
	return regexp.MustCompile(`(?i)(^|[^a-z0-9_])("?)(` + strings.Join(alts, "|") + `)("?)([^a-z0-9_]|$)`)
}()

// classifyStatement sorts one statement. Conservative: anything that can
// write and names a fenced table is a fenced write, except the two shapes the
// fence's triggers do not count either (an UPDATE of a table's bookkeeping
// columns only; a system_metadata write that does not touch the fenced key).
func classifyStatement(sql string, args []any) stmtKind {
	// Several statements in one string (the simple protocol allows it) are
	// not parsed one by one: any of them may write a fenced table. Neither is
	// text the lexer cannot read with certainty. What is classified below is
	// the statement with its comments blanked out.
	clean, ok := lexStatement(sql)
	if !ok {
		return stmtFencedWrite
	}
	s := strings.TrimSpace(clean)
	verb := strings.ToLower(firstWord(s))
	switch verb {
	case "begin", "start":
		return stmtBegin
	case "commit", "rollback", "end", "abort":
		return endKind(s)
	case "select", "show", "set", "savepoint", "release", "fetch", "explain", "values", "":
		return stmtRead
	}
	if !writeVerbs[verb] {
		return stmtRead
	}
	if verb == "with" && !dmlInsideRE.MatchString(s) {
		return stmtRead // a read-only CTE
	}
	m := fencedNameRE.FindAllStringSubmatch(s, -1)
	if m == nil {
		return stmtOtherWrite
	}
	for _, mm := range m {
		if fencedWriteOf(strings.ToLower(mm[3]), verb, s, args) {
			return stmtFencedWrite
		}
	}
	return stmtOtherWrite
}

func fencedWriteOf(table, verb, s string, args []any) bool {
	for _, t := range FencedTables {
		if t.Name != table {
			continue
		}
		if t.Key != "" && !mentionsKey(s, args, t.Key) {
			return false
		}
		if verb == "update" && len(t.UpdateIgnores) > 0 && onlySets(s, t.UpdateIgnores) {
			return false
		}
		return true
	}
	return false
}

func mentionsKey(s string, args []any, key string) bool {
	if strings.Contains(s, key) {
		return true
	}
	for _, a := range args {
		if argIsKey(a, key, 0) {
			return true
		}
	}
	return false
}

// argIsKey reports whether a bind argument can carry key: a string of any
// named type, a []byte, a pointer to either, a driver.Valuer whose value does,
// or a slice/array holding one (= ANY($1)). A Valuer that fails is counted as
// the key (fail closed: the write stays fenced).
func argIsKey(a any, key string, depth int) bool {
	if a == nil || depth > 4 {
		return false
	}
	rv := reflect.ValueOf(a)
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return false
	}
	if v, ok := a.(driver.Valuer); ok {
		dv, err := v.Value()
		if err != nil {
			return true
		}
		if dv == nil {
			return false
		}
		if _, same := dv.(driver.Valuer); !same {
			return argIsKey(dv, key, depth+1)
		}
	}
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.String:
		return rv.String() == key
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			if rv.Kind() == reflect.Slice {
				return string(rv.Bytes()) == key
			}
			return false
		}
		for i := range rv.Len() {
			if argIsKey(rv.Index(i).Interface(), key, depth+1) {
				return true
			}
		}
	}
	return false
}

// onlySets reports whether an UPDATE's SET list assigns only cols.
func onlySets(s string, cols []string) bool {
	low := strings.ToLower(s)
	_, after, ok := strings.Cut(low, " set ")
	if !ok {
		return false
	}
	setList, _, _ := strings.Cut(after, " where ")
	// A parenthesis is a subquery, a row constructor or a function call, and
	// a string or dollar-quoted literal can hold any text: its own " where "
	// or "," would cut the list in the wrong place. Count it as a write of the
	// table (the safe side).
	if strings.ContainsAny(setList, "('") || dollarQuoteRE.MatchString(setList) {
		return false
	}
	for part := range strings.SplitSeq(setList, ",") {
		lhs, _, ok := strings.Cut(part, "=")
		if !ok {
			return false
		}
		name := strings.Trim(strings.TrimSpace(lhs), `"`)
		allowed := false
		for _, c := range cols {
			if name == c {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

// dollarQuoteRE matches a dollar-quote delimiter ($$ or $tag$; not $1), and
// dollarQuoteStartRE one at the start of the text.
var (
	dollarQuoteRE      = regexp.MustCompile(dollarQuoteDelim)
	dollarQuoteStartRE = regexp.MustCompile(`^` + dollarQuoteDelim)
)

const dollarQuoteDelim = `\$([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)?\$`

// firstWord is the keyword s starts with: its leading run of identifier
// characters, so a verb is read whatever follows it (white space of any kind,
// a parenthesis, an operator).
func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if !identCont(s[i]) || s[i] == '$' {
			return s[:i]
		}
	}
	return s
}

// lexStatement reads sql the way PostgreSQL's lexer does and returns it with
// every comment replaced by one space and the statement-ending semicolons cut
// off. ok is false, and the caller counts a fenced write, when sql holds a
// semicolon outside a literal, quoted identifier or comment with anything but
// semicolons and white space after it (a second statement), or anything the
// lexer cannot read with certainty: an unterminated string, quoted
// identifier, dollar quote or block comment; a backslash right before a
// quote in a string without the E prefix (whether it escapes that quote
// depends on standard_conforming_strings); a U& identifier; a '$' that
// neither continues an identifier, starts a parameter nor opens a dollar
// quote.
//
// It recognises: '...' with doubled quotes (any prefix: B, X, N, U&),
// E'...' with doubled quotes and backslash escapes, $tag$...$tag$, "..."
// with doubled quotes, -- to the end of the line (\n or \r), and /* */
// nested as PostgreSQL nests them. A literal's text stays in the result, so
// a table name or verb inside one still counts towards a write (the safe
// side). Only ever widening: a construct this misses is text that stays
// outside every literal, where a semicolon ends the statement.
func lexStatement(sql string) (clean string, ok bool) {
	var b strings.Builder
	b.Grow(len(sql))
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			j := strings.IndexAny(sql[i:], "\n\r")
			if j < 0 {
				j = len(sql) - i
			}
			b.WriteByte(' ')
			i += j
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			j, ok := blockCommentEnd(sql, i)
			if !ok {
				return "", false
			}
			b.WriteByte(' ')
			i = j
		case c == '\'':
			j, ok := stringEnd(sql, i, ePrefixed(sql, i))
			if !ok {
				return "", false
			}
			b.WriteString(sql[i:j])
			i = j
		case c == '"':
			if i > 0 && sql[i-1] == '&' {
				return "", false // U&"...": a name spelled with escapes
			}
			j, ok := quotedIdentEnd(sql, i)
			if !ok {
				return "", false
			}
			b.WriteString(sql[i:j])
			i = j
		case c == '$':
			switch {
			case i > 0 && identCont(sql[i-1]):
				// Part of an identifier (a$b) or of what follows a number:
				// no dollar quote opens here.
				b.WriteByte(c)
				i++
			case i+1 < len(sql) && sql[i+1] >= '0' && sql[i+1] <= '9':
				b.WriteByte(c) // a parameter ($1)
				i++
			default:
				delim := dollarQuoteStartRE.FindString(sql[i:])
				if delim == "" {
					return "", false
				}
				k := strings.Index(sql[i+len(delim):], delim)
				if k < 0 {
					return "", false
				}
				j := i + 2*len(delim) + k
				b.WriteString(sql[i:j])
				i = j
			}
		case c == ';':
			if strings.Trim(sql[i:], "; \t\n\r\f\v") != "" {
				return "", false
			}
			return b.String(), true
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), true
}

// identCont reports whether c can continue an identifier (PostgreSQL's
// ident_cont: letters, digits, _, $ and every byte of a multi-byte
// character).
func identCont(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c >= 0x80
}

// ePrefixed reports whether the quote at sql[i] opens an E-prefixed string: an E
// (or e) right before it that does not end a longer identifier.
func ePrefixed(sql string, i int) bool {
	if i == 0 || (sql[i-1] != 'e' && sql[i-1] != 'E') {
		return false
	}
	return i == 1 || !identCont(sql[i-2])
}

// stringEnd returns the index just past the string literal opening at
// sql[i]. ok is false when it does not end, or when a string without the E
// prefix has a backslash right before a quote. Only there do the two
// standard_conforming_strings settings end it in different places: with the
// setting off a backslash escapes the next byte, and as long as that byte is
// never a quote, every quote means the same under both.
func stringEnd(sql string, i int, escapes bool) (int, bool) {
	for j := i + 1; j < len(sql); j++ {
		switch sql[j] {
		case '\\':
			if !escapes {
				if j+1 < len(sql) && sql[j+1] == '\'' {
					return 0, false
				}
				continue
			}
			j++ // the escaped byte, a quote included
		case '\'':
			if j+1 < len(sql) && sql[j+1] == '\'' {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return 0, false
}

// quotedIdentEnd returns the index just past the quoted identifier opening
// at sql[i], where "" stands for one quote.
func quotedIdentEnd(sql string, i int) (int, bool) {
	for j := i + 1; j < len(sql); j++ {
		if sql[j] != '"' {
			continue
		}
		if j+1 < len(sql) && sql[j+1] == '"' {
			j++
			continue
		}
		return j + 1, true
	}
	return 0, false
}

// blockCommentEnd returns the index just past the block comment opening at
// sql[i], counting nested /* */ pairs as PostgreSQL does.
func blockCommentEnd(sql string, i int) (int, bool) {
	depth := 0
	for j := i; j+1 < len(sql); {
		switch sql[j : j+2] {
		case "/*":
			depth++
			j += 2
		case "*/":
			depth--
			j += 2
			if depth == 0 {
				return j, true
			}
		default:
			j++
		}
	}
	return 0, false
}

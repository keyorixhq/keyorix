// role_permission_generation_integrity.go — the periodic check that the
// cache-validating triggers are still the ones this binary installed
// (TRIGGER-ROWDIGEST-1, docs/design/trigger-rowdigest.md): the role-permission
// generation triggers, and the secret_nodes cache-epoch trigger
// (STARTUP-GUARD-TAILS-1).
//
// The per-statement proofs (rolePermGenerationExpr, nodeTriggerExistsExpr)
// show that the triggers exist and are ENABLE ALWAYS. They do not show what
// the triggers run. The owner of the function (the server's own database
// role, no superuser needed) can replace its body with one that bumps nothing,
// re-create a trigger of the same name on fewer events, or DISABLE, write and
// ENABLE ALWAYS again inside one transaction, and every proof still passes. A
// permission then removed by direct SQL keeps authorizing from every warm
// replica's cache; a secret suspended by direct SQL keeps reading as active.
//
// Every rolePermGenerationIntegrityInterval this check reads, per target, in
// one catalog statement:
//
//   - the definition: every trigger present, ENABLE ALWAYS, of the shape the
//     installer creates, calling a function whose body, language and settings
//     are this binary's, read on a connection whose session_replication_role
//     is 'origin' (the per-statement proofs' condition,
//     pgTriggerFiresForEveryWriter);
//   - the row versions: tgfoid and xmin of the pg_trigger rows and of the
//     function's pg_proc row. No SQL statement can set a row's xmin back, so a
//     change undone before the next tick (the DISABLE/write/ENABLE sandwich, a
//     body replaced and restored) still shows as a new xmin. The installers
//     rewrite neither row when they are already correct, so a clean boot of
//     another replica changes nothing here.
//
// A bad definition: log, count, re-install (under a lock_timeout) and
// invalidate. Changed row versions with a good definition: log, count and
// invalidate. Each target invalidates every replica's cache through the
// database, not this process's memory:
//
//   - role-permission generation: bump role_permissions_generation. The first
//     bump commits in its own transaction before the repair, so a repair that
//     cannot get its lock or fails outright never holds the invalidation back,
//     and the repair's transaction bumps again. Until a repair commits and the
//     re-read is clean every tick invalidates again.
//   - secret_nodes cache epoch (checkRepairFirst): move cache_epoch on every
//     live row. That bump goes through the trigger it is checking (a BEFORE
//     trigger overwrites NEW.cache_epoch), so it runs only after the repair,
//     which commits in its own transaction first: a row lock the bump waits
//     on never rolls the repair back. The bump is an UPDATE per live row, so
//     it runs in committed batches by id that keep their place across ticks
//     (pending is cleared after the last one), and a problem the repair
//     cannot fix (a session not in 'origin') is invalidated once per reading,
//     not every tick.
//
// The role-permission reading also covers the table the generation triggers
// and every invalidation write, system_metadata (systemMetadataWriteTargetSQL,
// #3713): a trigger, rule or row level security there could make every bump,
// this check's own included, a no-op while the triggers read as correct. The
// repair removes them (restoreSystemMetadataWriteTarget).
//
// Releases: each function carries a version marker (pgTriggerDef.marker,
// #3717). A newer release's self-consistent definition, at most one version
// ahead, is invalidated once and warned about under its own counter label, and
// left in place by the check and the installers, so a rolling upgrade that
// changes a definition does not have both releases re-installing their own
// every tick. The rule and its residual are at triggerDefMaxNewerSkew.
//
// A false alarm (a catalog rewrite this file does not foresee, such as a
// pg_upgrade or a replica of a release from before the markers rewriting the
// function at boot during a rolling upgrade) changes no decision. It costs one cache refill:
// for the role-permission target one bump; for the cache epoch one UPDATE of
// every live secret_nodes row per replica per detection, in batches of secretNodeCacheEpochInvalidateBatch rows, spread
// over as many ticks as the table needs.
//
// Limits, stated: the window is one interval (plus at most one tick timeout)
// for deliberate DDL only (the accidental states keep the per-statement
// proofs' zero window). For the role-permission target that holds also while
// a repair keeps failing, since its bump commits first. The cache-epoch target
// bumps nothing until a repair commits, so a session with the server's role
// that keeps the repair failing every tick (a transaction left open holding a
// lock the repair's DDL waits on: an ACCESS SHARE lock on secret_nodes is
// enough for its DROP TRIGGER or ALTER TABLE) leaves warm replicas serving
// stale nodes under a replaced body until secretMetaCacheTTL (5 minutes)
// expires them, the bound before this check. So does a row lock held for good
// inside one invalidation batch: the bump never gets past it. A superuser below SQL
// (native code, the data directory, a replaced plpgsql handler or a
// redefined pg_catalog function the body calls) is not detected. A session
// whose replication role is not 'origin' is reported every tick and cannot
// be repaired from here (it is a setting: ALTER ROLE/DATABASE ... SET, a DSN
// option). PostgreSQL only: on SQLite whoever can write the database file
// controls everything.
package store

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/gorm"
)

// rolePermGenerationIntegrityInterval is the time between two checks (a var so
// tests can shorten it).
var rolePermGenerationIntegrityInterval = 30 * time.Second

// rolePermGenerationIntegrityTickTimeout bounds one tick, so a statement that
// hangs cannot stop the ticks after it.
var rolePermGenerationIntegrityTickTimeout = 10 * time.Second

// rolePermGenerationRepairLockTimeout is the repair's lock_timeout: how long
// its DROP TRIGGER may queue for the table's lock (stalling the table's
// readers behind it) before the repair gives up until the next tick. Each
// cache-epoch invalidation batch's row locks use it too.
var rolePermGenerationRepairLockTimeout = time.Second

// secretNodeCacheEpochInvalidateBatch is how many secret_nodes rows one
// committed invalidation batch moves (a var so tests can shrink it). Small
// enough that a batch holds its row locks briefly and fits a tick many times
// over; the batches of one invalidation continue across ticks.
var secretNodeCacheEpochInvalidateBatch = 5000

// rolePermGenerationNewerDefinitionRewarn is how often a checker repeats its
// warning while a newer release's definition stays installed.
var rolePermGenerationNewerDefinitionRewarn = time.Hour

// The reason label of both counters: tamper (changed outside any release:
// restored, flushed) or newer_definition (a newer release's definition, read
// during a rolling upgrade: flushed, not restored).
const (
	triggerIntegrityReasonTamper = "tamper"
	triggerIntegrityReasonNewer  = "newer_definition"
)

var rolePermGenerationTamperVec = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_role_permission_generation_tamper_total",
	Help: "Times the role-permission generation triggers or the system_metadata row they write were found changed and every replica's permission cache was invalidated. reason: tamper (changed outside a release; restored) or newer_definition (a newer release's definition during a rolling upgrade; left in place).",
}, []string{"reason"})

var (
	rolePermGenerationTamperTotal          = rolePermGenerationTamperVec.WithLabelValues(triggerIntegrityReasonTamper)
	rolePermGenerationNewerDefinitionTotal = rolePermGenerationTamperVec.WithLabelValues(triggerIntegrityReasonNewer)
)

var secretNodeCacheEpochTamperVec = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_secret_node_cache_epoch_tamper_total",
	Help: "Times the secret_nodes cache-epoch trigger was found changed and every replica's secret metadata cache was invalidated. reason: tamper (changed outside a release; restored) or newer_definition (a newer release's definition during a rolling upgrade; left in place).",
}, []string{"reason"})

var (
	secretNodeCacheEpochTamperTotal          = secretNodeCacheEpochTamperVec.WithLabelValues(triggerIntegrityReasonTamper)
	secretNodeCacheEpochNewerDefinitionTotal = secretNodeCacheEpochTamperVec.WithLabelValues(triggerIntegrityReasonNewer)
)

// pgTriggerDef is one release's definition of a trigger function and the
// triggers that call it: what the installer creates and the check compares.
// version moves whenever body, settings or trigger shape change, and is
// written next to the function as its version marker (marker).
type pgTriggerDef struct {
	version  int
	funcName string
	body     string
	triggers []triggerSpec
	tgtype   int // every trigger's pg_trigger.tgtype
	// sql reads one row per trigger (see triggerIntegritySQL); $1 is body.
	sql string
}

// triggerIntegrityTarget is one set of triggers and their function that the
// check watches.
type triggerIntegrityTarget struct {
	what  string // log noun: "role-permission generation"
	cache string // what invalidate flushes: "permission cache"
	def   *pgTriggerDef
	// invalidate makes every replica's cache miss, inside tx.
	invalidate func(ctx context.Context, tx *gorm.DB) error
	// invalidateFrom, set instead of invalidate, is an invalidation that goes
	// through the trigger being checked and whose cost grows with the table:
	// inside tx it makes the next limit live rows with an id above after miss
	// and returns their ids. Such a target is checked by checkRepairFirst.
	invalidateFrom func(ctx context.Context, tx *gorm.DB, after uint, limit int) ([]uint, error)
	// repair re-installs the triggers of def inside tx (and restores the row
	// they write, where the reading covers it). It leaves a newer release's
	// definition in place.
	repair   func(tx *gorm.DB, def *pgTriggerDef) error
	tamper   prometheus.Counter
	newerDef prometheus.Counter
}

type triggerSpec struct{ table, trigger string }

// Version markers (#3717). The installer writes
//
//	keyorix-trigger-def <function> v<version> sha256:<digest>
//
// as the function's COMMENT (pg_description), not into its body: a release
// from before markers compares prosrc exactly, so a marker in the body would
// read as tampering to it, and the upgrade that ships markers would ping-pong
// like the ones markers stop. <digest> is triggerDefDigest of the definition
// the marker names: the function's language, settings, SECURITY DEFINER flag
// and body, and each checked trigger's table, name and shape.
//
// A checker accepts its own version only as exactly its own definition (the
// body, settings and shape comparisons plus the marker string), so a
// definition at or below its version is restored as before. A higher version,
// at most triggerDefMaxNewerSkew above its own, whose digest matches what the
// catalog holds, is a newer release's definition: the checker invalidates once
// and warns, and neither the check nor the installer restores its own over it.
// Anything else (no marker, a malformed one, an older or equal version that is
// not exactly this release's, a version further ahead, a digest that does not
// match the catalog) is tampering.
//
// The digest is not a signature: the owner who can replace the function can
// also write a self-consistent marker one version ahead. Older replicas then
// leave that definition alone (they warn, and the newer_definition counter
// moves), until a release at that version, which compares exactly, restores
// its own. The skew bound keeps a forged marker from outranking every future
// release.
const triggerDefMaxNewerSkew = 1

var triggerDefMarkerRE = regexp.MustCompile(`^keyorix-trigger-def ([a-z_][a-z0-9_]*) v(0|[1-9][0-9]{0,8}) sha256:([0-9a-f]{64})$`)

// triggerDefFacts is what a definition digest covers, as the catalog holds it.
type triggerDefFacts struct {
	lang, config, body string
	secdef             bool
	triggers           []triggerShapeFacts
}

// triggerShapeFacts is one trigger's shape: pg_trigger.tgtype (timing, level,
// events), its argument count, its UPDATE OF column count, whether it has a
// WHEN clause and whether it is a constraint trigger.
type triggerShapeFacts struct {
	table, name         string
	tgtype, nargs, cols int
	when, constraint    bool
}

// triggerDefDigest is the hex SHA-256 of a canonical text of funcName's
// definition at version; the triggers are taken in (table, name) order.
func triggerDefDigest(funcName string, version int, f triggerDefFacts) string {
	trig := slices.Clone(f.triggers)
	slices.SortFunc(trig, func(a, b triggerShapeFacts) int {
		return cmp.Or(cmp.Compare(a.table, b.table), cmp.Compare(a.name, b.name))
	})
	text := fmt.Sprintf("keyorix-trigger-def\nfunction %q\nversion %d\nlanguage %q\nconfig %q\nsecurity-definer %t\nbody %q\n",
		funcName, version, f.lang, f.config, f.secdef, f.body)
	for _, t := range trig {
		text += fmt.Sprintf("trigger %q on %q type %d nargs %d columns %d when %t constraint %t\n",
			t.name, t.table, t.tgtype, t.nargs, t.cols, t.when, t.constraint)
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// pgTriggerFuncConfigText is pg_proc.proconfig::text for the pinned search_path.
const pgTriggerFuncConfigText = `{"search_path=` + pgTriggerFuncSearchPath + `"}`

// marker is the version marker of d as the installer creates it.
func (d *pgTriggerDef) marker() string {
	f := triggerDefFacts{lang: "plpgsql", config: pgTriggerFuncConfigText, body: d.body}
	for _, t := range d.triggers {
		f.triggers = append(f.triggers, triggerShapeFacts{table: t.table, name: t.trigger, tgtype: d.tgtype})
	}
	m := fmt.Sprintf("keyorix-trigger-def %s v%d sha256:%s", d.funcName, d.version, triggerDefDigest(d.funcName, d.version, f))
	if !triggerDefMarkerRE.MatchString(m) {
		panic("pgTriggerDef: marker " + m + " does not parse") // it is also inlined into COMMENT ON
	}
	return m
}

// newerThan reports whether marker names a newer release's definition of
// d's function that the reading (proname, pronargs, sameNS, facts) holds, and
// otherwise why not.
func (d *pgTriggerDef) newerThan(marker, proname string, pronargs int64, sameNS bool, facts triggerDefFacts) (string, bool) {
	m := triggerDefMarkerRE.FindStringSubmatch(marker)
	if m == nil {
		if marker == "" {
			return d.funcName + "() carries no version marker", false
		}
		return fmt.Sprintf("%s() carries a malformed version marker %q", d.funcName, marker), false
	}
	v, err := strconv.Atoi(m[2])
	switch {
	case err != nil || m[1] != d.funcName || proname != d.funcName || pronargs != 0 || !sameNS:
		return fmt.Sprintf("version marker %q does not name %s() in this schema", marker, d.funcName), false
	case v <= d.version:
		return fmt.Sprintf("%s() is marked v%d but is not this release's v%d definition", d.funcName, v, d.version), false
	case v > d.version+triggerDefMaxNewerSkew:
		return fmt.Sprintf("%s() is marked v%d, more than %d ahead of this release's v%d", d.funcName, v, triggerDefMaxNewerSkew, d.version), false
	case triggerDefDigest(d.funcName, v, facts) != m[3]:
		return fmt.Sprintf("%s() is marked v%d but its body, settings or triggers do not match the marker's digest", d.funcName, v), false
	}
	return fmt.Sprintf("v%d", v), true
}

// triggerIntegritySQL reads one row per trigger: its enabled state, whether
// its definition and its function are this binary's, the facts a version
// marker's digest covers, the marker, and its row versions, joined to this
// connection's session_replication_role and to writeTargetSQL's
// (problem, version) row so a row comes back even when no trigger does.
// writeTargetSQL ("" for none) checks the table the triggers write. Two
// native binds: $1, the expected body, which is funcOK's single `?`, and $2,
// the schema of the server's tables, which names every table
// (catalogRelSQL): the statement runs under readCatalog's search_path, which
// holds no schema but pg_catalog. triggerDefOK and writeTargetSQL take no
// `?`, and a `?` in them panics at package init instead of silently taking
// the body's place.
func triggerIntegritySQL(triggers []triggerSpec, triggerDefOK, funcOK, writeTargetSQL string) string {
	if strings.Contains(triggerDefOK, "?") || strings.Contains(writeTargetSQL, "?") || strings.Count(funcOK, "?") != 1 {
		panic("triggerIntegritySQL: the trigger shape and write target take no bind and the function check exactly one (the body)")
	}
	if writeTargetSQL == "" {
		writeTargetSQL = "SELECT ''::text AS problem, ''::text AS version"
	}
	var conds []string
	for _, t := range triggers {
		conds = append(conds, "(t.tgrelid = "+catalogRelSQL("$2", t.table)+" AND t.tgname = '"+t.trigger+"')")
	}
	funcOK = strings.Replace(funcOK, "?", "$1", 1)
	return `SELECT s.repl, s.write_problem, s.write_version, g.name, g.state, g.def_ok, g.func_ok, g.version,
  g.relname, g.tgtype, g.tgnargs, g.cols, g.has_when, g.is_constraint,
  g.proname, g.pronargs, g.same_ns, g.lang, g.config, g.secdef, g.body, g.marker
FROM (SELECT pg_catalog.current_setting('session_replication_role') AS repl, w.problem AS write_problem, w.version AS write_version
  FROM (` + writeTargetSQL + `) w) s
LEFT JOIN (
  SELECT t.tgname::text AS name, t.tgenabled::text AS state,
    (` + triggerDefOK + `) AS def_ok,
    COALESCE(` + funcOK + ` AND p.pronamespace = c.relnamespace, false) AS func_ok,
    t.tgfoid::text || ':' || t.xmin::text || ':' || COALESCE(p.xmin::text, '-') || ':' || COALESCE(d.xmin::text, '-') AS version,
    c.relname::text AS relname, t.tgtype::int AS tgtype, t.tgnargs::int AS tgnargs,
    COALESCE(pg_catalog.array_length(t.tgattr::pg_catalog.int2[], 1), 0) AS cols,
    t.tgqual IS NOT NULL AS has_when, t.tgconstraint <> 0 AS is_constraint,
    p.proname::text AS proname, p.pronargs::int AS pronargs, COALESCE(p.pronamespace = c.relnamespace, false) AS same_ns,
    l.lanname::text AS lang, COALESCE(p.proconfig::text, '') AS config, COALESCE(p.prosecdef, false) AS secdef,
    p.prosrc AS body, d.description AS marker
  FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  LEFT JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
  LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
  LEFT JOIN pg_catalog.pg_description d ON d.objoid = p.oid AND d.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objsubid = 0
  WHERE NOT t.tgisinternal AND (` + strings.Join(conds, " OR ") + `)
) g ON true
ORDER BY g.name`
}

// systemMetadataAnchorTriggerOK is true, over pg_trigger t on pg_class c
// (system_metadata), for the one trigger that table may carry: the audit
// retention-anchor trigger (audit_retention_anchor_trigger.go) as its
// installer creates it, BEFORE UPDATE FOR EACH ROW (tgtype 19) calling
// keyorix_keep_retention_anchor_v2() and limited by its WHEN clause to the
// anchor row, so whatever its function does never reaches the generation row.
// The function's body is not compared: its installer rewrites it on every
// boot, and the WHEN clause, not the body, is what keeps it off that row.
// The WHEN clause is read from pg_get_triggerdef, which deparses any clause a
// trigger can carry: pg_get_expr(tgqual, tgrelid) raises an error for one
// that references NEW, and that error failed the whole reading on every tick
// (REVIEW-3841-DEEP-2 N1). The text between the first " FOR EACH ROW WHEN ("
// and the last ") EXECUTE FUNCTION " (PROCEDURE before PostgreSQL 11) must be
// the installer's clause exactly; what follows is the function, checked by
// oid below, and the trigger has no arguments. Never NULL (a trigger without
// a WHEN clause does not match): it is negated to find the other triggers.
const systemMetadataAnchorTriggerOK = "COALESCE(t.tgname = '" + AuditRetentionAnchorTrigger + "' AND t.tgtype = 19 AND t.tgnargs = 0 AND t.tgconstraint = 0" +
	" AND COALESCE(pg_catalog.array_length(t.tgattr::pg_catalog.int2[], 1), 0) = 0" +
	" AND pg_catalog.substring(pg_catalog.pg_get_triggerdef(t.oid), ' FOR EACH ROW WHEN \\((.*)\\) EXECUTE (FUNCTION|PROCEDURE) ') = '(old.key = ''audit_retention_anchor''::text)'" +
	" AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc ap WHERE ap.oid = t.tgfoid AND ap.proname = '" + auditRetentionAnchorFunc + "' AND ap.pronargs = 0 AND ap.pronamespace = c.relnamespace), false)"

// The single_writer fence's (internal/solewriter) trigger prefix, guard
// function and that function's body as pg_proc.prosrc stores it. The fence
// installs AFTER triggers on system_metadata that execute it, and the
// write-target check must tell them from foreign ones. A copy, because store
// cannot import solewriter (solewriter's tests import store);
// solewriter's TestFenceGuard_MatchesTheStore fails when they drift.
const (
	SoleWriterFenceTriggerPrefix = "trg_ksw_"
	SoleWriterGuardFunc          = "keyorix_sole_writer_guard"
	SoleWriterGuardFuncBody      = `
BEGIN
  EXECUTE pg_catalog.format('SELECT %I.keyorix_sole_writer_check($1)', TG_TABLE_SCHEMA) USING TG_TABLE_SCHEMA::text;
  EXECUTE pg_catalog.format('UPDATE %I.keyorix_write_epoch SET n = n + 1 WHERE id = 1 AND xmin <> pg_catalog.xid(pg_catalog.pg_current_xact_id())', TG_TABLE_SCHEMA);
  RETURN NULL;
END;
`
)

// systemMetadataFenceTriggerOK is true, over pg_trigger t on pg_class c
// (system_metadata), for a single_writer fence trigger (internal/solewriter,
// which fences the generation row): named with the fence's prefix, AFTER
// (an AFTER trigger cannot change the row it fires for), calling the fence's
// guard function in this schema with exactly that package's body, plpgsql,
// not SECURITY DEFINER. The fence rewrites that function on every
// single-writer start, so its row version is not part of the fingerprint.
// What the guard calls (keyorix_sole_writer_check, keyorix_write_epoch) and
// its settings are not compared here: the fence's own census checks them, and
// only while it runs. So this is allowed only in single_writer mode
// (systemMetadataAllowedTriggerOK); without it no fence exists, and a trigger
// of this shape is foreign. Never NULL.
var systemMetadataFenceTriggerOK = "COALESCE(pg_catalog.left(t.tgname::text, " + strconv.Itoa(len(SoleWriterFenceTriggerPrefix)) + ") = '" + SoleWriterFenceTriggerPrefix + "' AND t.tgtype & 66 = 0" +
	" AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc fp JOIN pg_catalog.pg_language fl ON fl.oid = fp.prolang" +
	" WHERE fp.oid = t.tgfoid AND fp.proname = '" + SoleWriterGuardFunc + "' AND fp.pronargs = 0 AND fp.pronamespace = c.relnamespace" +
	" AND fl.lanname = 'plpgsql' AND NOT fp.prosecdef AND fp.prosrc = '" + strings.ReplaceAll(SoleWriterGuardFuncBody, "'", "''") + "'), false)"

// systemMetadataAllowedTriggerOK is true, over pg_trigger t on pg_class c
// (system_metadata), for a trigger that table may carry: the retention-anchor
// one, and with singleWriter (storage.database.single_writer) the fence's.
// Never NULL.
func systemMetadataAllowedTriggerOK(singleWriter bool) string {
	if singleWriter {
		return systemMetadataAnchorTriggerOK + " OR " + systemMetadataFenceTriggerOK
	}
	return systemMetadataAnchorTriggerOK
}

// systemMetadataWriteTargetSQL is the role-permission generation target's
// write-target check (#3713): one (problem, version) row for system_metadata,
// the table the generation triggers and every invalidation, the check's own
// included, UPDATE. A BEFORE UPDATE trigger that keeps OLD.value, a rule that
// rewrites or drops the UPDATE, or row level security that hides the row
// from the server's role turns every bump into a no-op (or an error), while
// every trigger and function this file compares still reads as correct. So:
// a plain table without inheritance children, no non-internal trigger but a
// correct retention-anchor one (and, with singleWriter, single_writer fence
// triggers), no rule, relrowsecurity and relforcerowsecurity both false.
// version carries the xmin of its pg_class row and of each trigger and rule
// row, so an object added and removed again between two ticks still shows.
func systemMetadataWriteTargetSQL(singleWriter bool) string {
	allowed := "the retention-anchor one"
	if singleWriter {
		allowed += " and the single_writer fence''s"
	}
	return `SELECT pg_catalog.concat_ws('; ',
    CASE WHEN c.relkind <> 'r' OR EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhparent = c.oid) THEN 'system_metadata is not a plain table without inheritance children' END,
    CASE WHEN c.relrowsecurity OR c.relforcerowsecurity THEN 'system_metadata has row level security enabled' END,
    (SELECT 'system_metadata has rules (' || pg_catalog.string_agg(r.rulename::text, ', ' ORDER BY r.rulename) || ')' FROM pg_catalog.pg_rewrite r WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN'),
    (SELECT 'system_metadata has triggers other than ` + allowed + ` (' || pg_catalog.string_agg(t.tgname::text, ', ' ORDER BY t.tgname) || ')'
       FROM pg_catalog.pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND NOT (` + systemMetadataAllowedTriggerOK(singleWriter) + `))
  ) AS problem,
  c.xmin::text
    || '|' || COALESCE((SELECT pg_catalog.string_agg(t.tgname::text || '@' || t.xmin::text, ',' ORDER BY t.tgname) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal), '')
    || '|' || COALESCE((SELECT pg_catalog.string_agg(r.rulename::text || '@' || r.xmin::text, ',' ORDER BY r.rulename) FROM pg_catalog.pg_rewrite r WHERE r.ev_class = c.oid), '') AS version
FROM pg_catalog.pg_class c WHERE c.oid = ` + catalogRelSQL("$2", "system_metadata")
}

// restoreSystemMetadataWriteTarget undoes, inside tx, what
// systemMetadataWriteTargetSQL reports and this server can undo: it drops
// every non-internal trigger on system_metadata but a correct retention-anchor
// one and, with singleWriter, correct single_writer fence ones (re-creating
// the anchor trigger when it was the one dropped; the fence re-installs its
// own at its next start), drops
// every rule and turns row level security off. A table that is not a plain
// table is left to an operator: the re-read after the repair reports it again,
// every tick. Nothing in Keyorix puts any of these on system_metadata, and
// the repair's lock_timeout bounds the DROP's ACCESS EXCLUSIVE wait.
func restoreSystemMetadataWriteTarget(tx *gorm.DB, singleWriter bool) error {
	var triggers, rules []string
	var rls []struct{ Enabled, Forced bool }
	if err := readCatalog(tx, func(schema string) error {
		if err := tx.Raw(`SELECT t.tgname::text FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
WHERE c.oid = `+catalogRelSQL("?", "system_metadata")+` AND NOT t.tgisinternal AND NOT (`+systemMetadataAllowedTriggerOK(singleWriter)+`) ORDER BY 1`, schema).Scan(&triggers).Error; err != nil {
			return fmt.Errorf("read system_metadata triggers: %w", err)
		}
		if err := tx.Raw(`SELECT r.rulename::text FROM pg_catalog.pg_rewrite r
WHERE r.ev_class = `+catalogRelSQL("?", "system_metadata")+` AND r.rulename <> '_RETURN' ORDER BY 1`, schema).Scan(&rules).Error; err != nil {
			return fmt.Errorf("read system_metadata rules: %w", err)
		}
		if err := tx.Raw(`SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced FROM pg_catalog.pg_class c
WHERE c.oid = `+catalogRelSQL("?", "system_metadata"), schema).Scan(&rls).Error; err != nil {
			return fmt.Errorf("read system_metadata row level security: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	var stmts []string
	for _, t := range triggers {
		stmts = append(stmts, "DROP TRIGGER "+pgx.Identifier{t}.Sanitize()+" ON system_metadata")
	}
	for _, r := range rules {
		stmts = append(stmts, "DROP RULE "+pgx.Identifier{r}.Sanitize()+" ON system_metadata")
	}
	if len(rls) == 1 && rls[0].Forced {
		stmts = append(stmts, "ALTER TABLE system_metadata NO FORCE ROW LEVEL SECURITY")
	}
	if len(rls) == 1 && rls[0].Enabled {
		stmts = append(stmts, "ALTER TABLE system_metadata DISABLE ROW LEVEL SECURITY")
	}
	for _, s := range stmts {
		log.Printf("role-permission generation: %s (it can make the generation bump a no-op)", s)
		if err := tx.Exec(s).Error; err != nil { // #nosec G202 -- identifiers from the catalog, quoted by pgx.Identifier; DDL takes no binds
			return fmt.Errorf("restore system_metadata: %s: %w", s, err)
		}
	}
	if slices.Contains(triggers, AuditRetentionAnchorTrigger) {
		return EnsureAuditRetentionAnchorTrigger(tx)
	}
	return nil
}

// rolePermGenerationDef is this release's role-permission generation
// definition. Its version moves with any change to the body, the settings or
// the trigger shape (#3717). Its reading allows no single_writer fence
// trigger on system_metadata; rolePermGenerationSingleWriterDef is the same
// definition read in single_writer mode.
var rolePermGenerationDef = newRolePermGenerationDef(false)

var rolePermGenerationSingleWriterDef = newRolePermGenerationDef(true)

func newRolePermGenerationDef(singleWriter bool) *pgTriggerDef {
	return newPGTriggerDef(&pgTriggerDef{
		version:  1,
		funcName: rolePermGenerationFunc,
		body:     postgresRolePermGenerationFuncBody,
		triggers: func() []triggerSpec {
			var triggers []triggerSpec
			for _, t := range rolePermGenerationTables {
				triggers = append(triggers, triggerSpec{t.table, t.trigger})
			}
			return triggers
		}(),
		tgtype: 60, // pgRolePermGenerationTriggerDefOK
	}, pgRolePermGenerationTriggerDefOK, pgRolePermGenerationFuncOK, systemMetadataWriteTargetSQL(singleWriter))
}

// secretNodeCacheEpochDef is this release's secret_nodes cache-epoch
// definition, versioned the same way (declared with its target, whose
// invalidation is the one statement here that touches the table's rows).
var secretNodeCacheEpochDef = secretNodeCacheEpochIntegrityTarget.def

// newPGTriggerDef fills d's reading statement.
func newPGTriggerDef(d *pgTriggerDef, triggerDefOK, funcOK, writeTargetSQL string) *pgTriggerDef {
	d.sql = triggerIntegritySQL(d.triggers, triggerDefOK, funcOK, writeTargetSQL)
	d.marker() // panics at init on a marker that does not parse
	return d
}

// leaveNewerTriggerDef is the installers' first step after their advisory
// lock: when the installed definition is a newer release's, it only turns
// back to ENABLE ALWAYS a trigger that is not (that state is no part of any
// definition), logs, and reports true, and the installer installs nothing.
func leaveNewerTriggerDef(tx *gorm.DB, d *pgTriggerDef, what string) (bool, error) {
	st, err := readInstalledTriggerDef(tx, d)
	if err != nil {
		return false, fmt.Errorf("read the installed %s() definition: %w", d.funcName, err)
	}
	if st.newer == "" {
		return false, nil
	}
	log.Printf("%s: leaving a newer release's %s() in place (%q; this release writes v%d)", what, d.funcName, st.newer, d.version)
	for _, t := range d.triggers {
		var state []string
		if err := readCatalog(tx, func(schema string) error {
			return tx.Raw("SELECT t.tgenabled::text FROM pg_catalog.pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid = "+catalogRelSQL("?", t.table)+" AND t.tgname = ?",
				schema, t.trigger).Scan(&state).Error
		}); err != nil {
			return true, fmt.Errorf("failed to read %s state: %w", t.trigger, err)
		}
		if len(state) == 1 && state[0] != "A" {
			if err := tx.Exec("ALTER TABLE " + t.table + " ENABLE ALWAYS TRIGGER " + t.trigger).Error; err != nil {
				return true, fmt.Errorf("failed to enable %s: %w", t.trigger, err)
			}
		}
	}
	return true, nil
}

// ensureTriggerDefMarker writes d's version marker as its function's comment
// when the comment differs. A correct comment is left alone, so a replica's
// boot does not move its pg_description row's xmin, which the check reads.
func ensureTriggerDefMarker(tx *gorm.DB, d *pgTriggerDef) error {
	want := d.marker()
	var cur []sql.NullString
	if err := tx.Raw("SELECT pg_catalog.obj_description(?::pg_catalog.regprocedure, 'pg_proc')", d.funcName+"()").Scan(&cur).Error; err != nil {
		return fmt.Errorf("failed to read the %s() version marker: %w", d.funcName, err)
	}
	if len(cur) == 1 && cur[0].Valid && cur[0].String == want {
		return nil
	}
	// No binds in DDL: the marker is this file's text and matches
	// triggerDefMarkerRE (no quote can occur in it).
	if err := tx.Exec("COMMENT ON FUNCTION " + d.funcName + "() IS '" + want + "'").Error; err != nil {
		return fmt.Errorf("failed to write the %s() version marker: %w", d.funcName, err)
	}
	return nil
}

// rolePermGenerationIntegrityTarget is the role-permission generation target
// of a server without storage.database.single_writer;
// rolePermGenerationSingleWriterIntegrityTarget, of one with it, also leaves
// the fence's triggers on system_metadata alone.
var (
	rolePermGenerationIntegrityTarget             = newRolePermGenerationIntegrityTarget(rolePermGenerationDef, false)
	rolePermGenerationSingleWriterIntegrityTarget = newRolePermGenerationIntegrityTarget(rolePermGenerationSingleWriterDef, true)
)

func newRolePermGenerationIntegrityTarget(def *pgTriggerDef, singleWriter bool) *triggerIntegrityTarget {
	return &triggerIntegrityTarget{
		what:  "role-permission generation",
		cache: "permission cache",
		def:   def,
		invalidate: func(ctx context.Context, tx *gorm.DB) error {
			return bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx})
		},
		repair: func(tx *gorm.DB, def *pgTriggerDef) error {
			if err := restoreSystemMetadataWriteTarget(tx, singleWriter); err != nil {
				return err
			}
			return installPostgresRolePermGenerationTriggers(tx, def)
		},
		tamper:   rolePermGenerationTamperTotal,
		newerDef: rolePermGenerationNewerDefinitionTotal,
	}
}

var secretNodeCacheEpochIntegrityTarget = &triggerIntegrityTarget{
	what:  "secret_nodes cache-epoch",
	cache: "secret metadata cache",
	def: newPGTriggerDef(&pgTriggerDef{
		version:  1,
		funcName: secretNodeCacheEpochFunc,
		body:     postgresCacheEpochFuncBody,
		triggers: []triggerSpec{{"secret_nodes", SecretNodeCacheEpochTrigger}},
		tgtype:   19, // pgCacheEpochTriggerDefOK
	}, pgCacheEpochTriggerDefOK, pgCacheEpochFuncOK, ""),
	// Every live row: a soft-deleted row never hits (readLiveNodeStamp), and
	// undeleting it is an UPDATE the restored trigger stamps. A row an earlier
	// batch already passed is stamped by that trigger when it changes again.
	invalidateFrom: func(ctx context.Context, tx *gorm.DB, after uint, limit int) ([]uint, error) {
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
			return nil, err
		}
		var ids []uint
		err := tx.WithContext(ctx).Raw(`WITH b AS (SELECT id FROM secret_nodes WHERE deleted_at IS NULL AND id > ? ORDER BY id LIMIT ?)
UPDATE secret_nodes s SET cache_epoch = s.cache_epoch + 1 FROM b WHERE s.id = b.id RETURNING s.id`, after, limit).Scan(&ids).Error
		return ids, err
	},
	repair:   installPostgresCacheEpochTrigger,
	tamper:   secretNodeCacheEpochTamperTotal,
	newerDef: secretNodeCacheEpochNewerDefinitionTotal,
}

// triggerIntegrityState is one reading: problem is "" when the definition is
// this binary's (or a newer release's, then named by newer) and the session
// is in 'origin', version the concatenated row versions.
type triggerIntegrityState struct {
	problem string
	version string
	newer   string
}

// pinCatalogSearchPathSQL sets, for the rest of the transaction, the
// session's search_path with pg_catalog taken out of it (and pg_temp put
// last): pg_catalog is then searched first, implicitly, and every other
// schema keeps its place, so current_schema() and what the statements after
// it create or name stay the same. The repair's DDL runs under it, so the
// anchor trigger it re-creates calls pg_catalog's `=` on (text, text) even
// when the role's search_path lists a schema holding another one first
// (REVIEW-3841-DEEP-3 B2). It is not a defence for a read: an operator whose
// argument types match exactly is picked before one reached by a coercion,
// wherever it sits in the search_path, and the server's schema is on it. The
// catalog reads run under readCatalog instead. This statement is itself
// parsed under the session's search_path: every function and operator in it
// is qualified.
const pinCatalogSearchPathSQL = `SELECT pg_catalog.set_config('search_path', pg_catalog.array_to_string(pg_catalog.array_append(ARRAY(
  SELECT pg_catalog.quote_ident(s.n) FROM pg_catalog.unnest(pg_catalog.current_schemas(false)) WITH ORDINALITY AS s(n, i)
  WHERE s.n OPERATOR(pg_catalog.<>) 'pg_catalog' AND pg_catalog.left(s.n::text, 7) OPERATOR(pg_catalog.<>) 'pg_temp' ORDER BY s.i), 'pg_temp'), ', '), true)`

// pinCatalogSearchPath runs pinCatalogSearchPathSQL in tx.
func pinCatalogSearchPath(tx *gorm.DB) error {
	if err := tx.Exec(pinCatalogSearchPathSQL).Error; err != nil {
		return fmt.Errorf("pin the search_path: %w", err)
	}
	return nil
}

// readCatalog runs read in tx's transaction with the search_path
// pg_catalog, pg_temp (pgTriggerFuncSearchPath), handing it the schema of the
// server's tables (current_schema() under pinCatalogSearchPathSQL), and then
// gives the transaction its search_path back. With no other schema on the
// path, read resolves every operator, function and type in pg_catalog
// (pg_temp is never searched for operators or functions, and is searched
// after pg_catalog for types): an operator the server's role creates in its
// own schema, with argument types that match a comparison exactly where
// pg_catalog's needs a coercion (`=` on (oid, regclass) for
// `tgrelid = 'system_metadata'::regclass`, PR #3841 fourth review C1), cannot
// take part. read names a table through catalogRelSQL. tx must be a
// transaction.
func readCatalog(tx *gorm.DB, read func(schema string) error) error {
	ctx := tx.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return readCatalogConn(ctx, tx.Statement.ConnPool, read)
}

// readCatalogConn is readCatalog on a transaction's connection.
func readCatalogConn(ctx context.Context, conn gorm.ConnPool, read func(schema string) error) error {
	var saved string
	if err := conn.QueryRowContext(ctx, "SELECT pg_catalog.current_setting('search_path')").Scan(&saved); err != nil {
		return fmt.Errorf("read the search_path: %w", err)
	}
	if _, err := conn.ExecContext(ctx, pinCatalogSearchPathSQL); err != nil {
		return fmt.Errorf("pin the search_path: %w", err)
	}
	var schema sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT pg_catalog.current_schema()").Scan(&schema); err != nil {
		return fmt.Errorf("read the schema: %w", err)
	}
	if !schema.Valid {
		return fmt.Errorf("the search_path %q names no existing schema", saved)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_catalog.set_config('search_path', $1, true)", pgTriggerFuncSearchPath); err != nil {
		return fmt.Errorf("set the catalog search_path: %w", err)
	}
	if err := read(schema.String); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_catalog.set_config('search_path', $1, true)", saved); err != nil {
		return fmt.Errorf("restore the search_path: %w", err)
	}
	return nil
}

// catalogRelSQL is table, in the schema bound at bind ($2 or ?), as a regclass
// under readCatalog's search_path, which holds none of the server's tables.
func catalogRelSQL(bind, table string) string {
	return "(pg_catalog.quote_ident(" + bind + ") || '." + table + "')::pg_catalog.regclass"
}

// readTriggerIntegrity goes through the underlying *sql.DB, not GORM: the
// background job would otherwise run GORM's callback chain concurrently with
// anything that registers a callback on the shared *gorm.DB (tests count
// queries that way), a data race inside GORM. Only the repair path, which is
// rare, uses GORM. It reads in a transaction of its own, under readCatalog's
// search_path; the transaction writes nothing and is rolled back.
func readTriggerIntegrity(ctx context.Context, db *gorm.DB, target *triggerIntegrityTarget) (triggerIntegrityState, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return triggerIntegrityState{}, err
	}
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return triggerIntegrityState{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var st triggerIntegrityState
	err = readCatalogConn(ctx, tx, func(schema string) error {
		rs, err := tx.QueryContext(ctx, target.def.sql, target.def.body, schema)
		if err != nil {
			return err
		}
		st, err = scanTriggerIntegrity(rs, target.def)
		return err
	})
	return st, err
}

// readInstalledTriggerDef is readTriggerIntegrity inside an installer's
// transaction, on that transaction's connection, under readCatalog.
func readInstalledTriggerDef(tx *gorm.DB, d *pgTriggerDef) (triggerIntegrityState, error) {
	var st triggerIntegrityState
	err := readCatalog(tx, func(schema string) error {
		ctx := tx.Statement.Context
		if ctx == nil {
			ctx = context.Background()
		}
		rs, err := tx.Statement.ConnPool.QueryContext(ctx, d.sql, d.body, schema)
		if err != nil {
			return err
		}
		st, err = scanTriggerIntegrity(rs, d)
		return err
	})
	return st, err
}

// scanTriggerIntegrity turns triggerIntegritySQL's rows into a reading of d.
func scanTriggerIntegrity(rs *sql.Rows, d *pgTriggerDef) (triggerIntegrityState, error) {
	defer func() { _ = rs.Close() }()
	var versions, problems, defProblems []string
	var facts triggerDefFacts
	repl, writeProblem, writeVersion, foid, marker, proname := "", "", "", "", "", ""
	present, pronargs, sameNS, oneFunc := 0, int64(-1), true, true
	for rs.Next() {
		var name, state, version, relname, pname, lang, config, body, mark sql.NullString
		var defOK, funcOK, hasWhen, isConstraint, sameNs, secdef sql.NullBool
		var tgtype, nargs, cols, pnargs sql.NullInt64
		if err := rs.Scan(&repl, &writeProblem, &writeVersion, &name, &state, &defOK, &funcOK, &version,
			&relname, &tgtype, &nargs, &cols, &hasWhen, &isConstraint,
			&pname, &pnargs, &sameNs, &lang, &config, &secdef, &body, &mark); err != nil {
			return triggerIntegrityState{}, err
		}
		if !name.Valid {
			continue // the LEFT JOIN's row when no trigger exists
		}
		present++
		versions = append(versions, name.String+"="+version.String)
		if state.String != "A" {
			problems = append(problems, fmt.Sprintf("%s is not ENABLE ALWAYS (tgenabled %q)", name.String, state.String))
		}
		switch {
		case !defOK.Bool:
			defProblems = append(defProblems, name.String+" was re-created with a different definition")
		case !funcOK.Bool:
			defProblems = append(defProblems, name.String+" calls a function that is not this release's "+d.funcName+"()")
		}
		f, _, _ := strings.Cut(version.String, ":")
		if foid != "" && f != foid {
			problems = append(problems, "the triggers call different functions")
			oneFunc = false
		}
		foid = f
		facts.triggers = append(facts.triggers, triggerShapeFacts{table: relname.String, name: name.String,
			tgtype: int(tgtype.Int64), nargs: int(nargs.Int64), cols: int(cols.Int64), when: hasWhen.Bool, constraint: isConstraint.Bool})
		facts.lang, facts.config, facts.body, facts.secdef = lang.String, config.String, body.String, secdef.Bool
		marker, proname, pronargs, sameNS = mark.String, pname.String, pnargs.Int64, sameNS && sameNs.Bool
		if !pname.Valid {
			pronargs = -1
		}
	}
	if err := rs.Err(); err != nil {
		return triggerIntegrityState{}, err
	}
	if present != len(d.triggers) {
		problems = append(problems, fmt.Sprintf("%d of %d triggers present", present, len(d.triggers)))
	}
	newer := ""
	if present > 0 && (len(defProblems) > 0 || marker != d.marker()) {
		// A newer release's definition only with every trigger present and on
		// one function: the digest covers each of them.
		why, ok := "", false
		if present == len(d.triggers) && oneFunc {
			why, ok = d.newerThan(marker, proname, pronargs, sameNS, facts)
		}
		if ok {
			newer, defProblems = marker, nil
		} else if why != "" {
			defProblems = append(defProblems, why)
		}
	}
	problems = append(problems, defProblems...)
	if repl != "origin" {
		problems = append(problems, fmt.Sprintf("this server's database session runs with session_replication_role %q, not origin (ALTER ROLE/DATABASE ... SET or a connection option), so ordinary triggers and foreign keys do not fire for it", repl))
	}
	if writeProblem != "" {
		problems = append(problems, writeProblem)
	}
	v := strings.Join(versions, ",")
	if writeVersion != "" {
		v += ";write-target=" + writeVersion
	}
	return triggerIntegrityState{problem: strings.Join(problems, "; "), version: v, newer: newer}, nil
}

// readRolePermGenerationIntegrity reads the role-permission generation target.
func readRolePermGenerationIntegrity(ctx context.Context, db *gorm.DB) (triggerIntegrityState, error) {
	return readTriggerIntegrity(ctx, db, rolePermGenerationIntegrityTarget)
}

// triggerIntegrityChecker holds the last good reading of one target on one
// store's database.
type triggerIntegrityChecker struct {
	ls       *LocalStorage
	logf     func(string, ...any)
	target   *triggerIntegrityTarget
	baseline string
	// pending is set when a tick has seen a change and cleared only once the
	// repair and invalidation have committed and the definition reads as
	// this release's again. While it is set every tick repairs and
	// invalidates, whatever the catalog now shows: a failed repair must not
	// let the next tick adopt whatever it reads as a fresh baseline, or a
	// replace that is restored after the failed attempt leaves every warm
	// cache stale with nothing left to see (fail closed).
	pending bool
	// checkRepairFirst only: round is the reading (integrityKey) the
	// invalidation under way is for, cursor the last id its committed batches
	// reached, and doneFor a reading the repair could not fix whose
	// invalidation has finished.
	round   string
	cursor  uint
	doneFor string
	// newerWarned is when the checker last warned that a newer release's
	// definition is installed.
	newerWarned time.Time
	// readFailures counts the ticks in a row whose reading failed
	// (readFailed).
	readFailures int
}

// triggerIntegrityReadFailureLimit is how many ticks in a row a reading may
// fail before the checker reports it as tampering: one failure can be a
// dropped connection, a reading that keeps failing can be catalog state the
// server's role planted to blind the check.
const triggerIntegrityReadFailureLimit = 2

// readFailed fails closed on a reading that errors (err). The role-permission
// invalidation does not depend on the reading, so every failed tick runs it;
// from triggerIntegrityReadFailureLimit failures in a row on, the tick is
// also reported (SECURITY, counted as tamper once per run of failures) and an
// invalidation is owed (pending), so the first reading that works again is
// re-verified and invalidated before it becomes the baseline. A target with
// invalidateFrom (checkRepairFirst) runs no invalidation here: its batches
// are complete only behind a verified trigger, so the owed one runs from the
// first row once the reading works. A cancelled tick (shutdown) changes
// nothing; a reading that ran out of time is a failed reading like any other,
// since the server's role can make the reading slow.
func (c *triggerIntegrityChecker) readFailed(ctx context.Context, err error) (bool, error) {
	t := c.target
	err = fmt.Errorf("read the %s triggers: %w", t.what, err)
	if errors.Is(ctx.Err(), context.Canceled) {
		return false, err
	}
	c.readFailures++
	if c.readFailures >= triggerIntegrityReadFailureLimit {
		c.logf("SECURITY: the %s triggers could not be read %d ticks in a row (%v). Invalidating every replica's %s until they can be read and verified; find who has DDL on this schema.", t.what, c.readFailures, err, t.cache)
		if c.readFailures == triggerIntegrityReadFailureLimit {
			t.tamper.Inc()
		}
		c.pending, c.round = true, ""
	}
	if t.invalidateFrom != nil {
		return false, err
	}
	if ierr := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return t.invalidate(ctx, tx)
	}); ierr != nil {
		return false, fmt.Errorf("%w; invalidate the %s: %v", err, t.cache, ierr)
	}
	return true, err
}

// warnNewer repeats, at most every rolePermGenerationNewerDefinitionRewarn, the
// warning that st holds a newer release's definition: outside a rolling
// upgrade to that release it is a forged marker (pgTriggerDef.newerThan).
func (c *triggerIntegrityChecker) warnNewer(st triggerIntegrityState) {
	if st.newer == "" || time.Since(c.newerWarned) < rolePermGenerationNewerDefinitionRewarn {
		return
	}
	c.newerWarned = time.Now()
	c.logf("%s triggers: a newer release's definition is installed (%q; this release writes v%d), as during a rolling upgrade to it. This replica leaves it in place and cannot verify it; if no such upgrade is under way, treat it as tampering.", c.target.what, st.newer, c.target.def.version)
}

// newerDefinitionLog is the line for a newly read newer definition.
func (c *triggerIntegrityChecker) newerDefinitionLog(st triggerIntegrityState) {
	c.newerWarned = time.Now()
	c.logf("%s triggers: a newer release's definition was installed (%q; this release writes v%d; catalog row versions %s, were %s), as during a rolling upgrade to it. Leaving it in place and invalidating every replica's %s once; if no such upgrade is under way, treat it as tampering.", c.target.what, st.newer, c.target.def.version, st.version, c.baseline, c.target.cache)
}

// readTickIntegrity is a tick's reading. It gets half of the tick's remaining
// time, so a reading that runs out of it (readFailed) leaves the other half
// for the invalidation.
func (c *triggerIntegrityChecker) readTickIntegrity(ctx context.Context) (triggerIntegrityState, error) {
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
		defer cancel()
	}
	return readTriggerIntegrity(ctx, c.ls.db, c.target)
}

// preRepairInvalidate is check's invalidation before a repair. It writes
// through system_metadata, so it fires what the repair is about to drop, and
// a planted object there can make it slow: it gets half of the tick's
// remaining time, so the repair keeps the other half (REVIEW-3841-DEEP-2 N1).
// The server enforces the budget (statement_timeout ends the statement and
// releases its locks before the repair's DROP TRIGGER queues for them); a
// cancelled context only drops the connection while the statement runs on.
func (c *triggerIntegrityChecker) preRepairInvalidate(ctx context.Context) error {
	var budget time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline) / 2
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	return c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if budget > 0 {
			// 0 would turn the timeout off.
			if err := tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = %d", max(budget.Milliseconds(), 1))).Error; err != nil {
				return err
			}
		}
		return c.target.invalidate(ctx, tx)
	})
}

// integrityKey identifies a reading, problem included.
func integrityKey(st triggerIntegrityState) string { return st.problem + "\x00" + st.version }

// check runs one tick and reports whether it invalidated the caches. The
// first tick records the baseline (and repairs a bad definition like any
// other tick).
func (c *triggerIntegrityChecker) check(ctx context.Context) (bool, error) {
	t := c.target
	if t.invalidateFrom != nil {
		return c.checkRepairFirst(ctx)
	}
	st, err := c.readTickIntegrity(ctx)
	if err != nil {
		return c.readFailed(ctx, err)
	}
	c.readFailures = 0
	switch {
	case st.problem != "":
		c.logf("SECURITY: %s triggers cannot be trusted: %s. Restoring them and invalidating every replica's %s; find who has DDL on this schema or changed the server role's database settings.", t.what, st.problem, t.cache)
	case c.pending:
		c.logf("SECURITY: retrying the %s invalidation after a failed attempt (catalog row versions %s, last good %s).", t.cache, st.version, c.baseline)
	case c.baseline == "" || st.version == c.baseline:
		c.baseline = st.version
		c.warnNewer(st)
		return false, nil
	case st.newer != "":
		c.newerDefinitionLog(st)
	default:
		c.logf("SECURITY: %s trigger or function rewritten outside this server (catalog row versions %s, were %s), now matching this release again. Invalidating every replica's %s; find who has DDL on this schema.", t.what, st.version, c.baseline, t.cache)
	}
	if st.problem == "" && st.newer != "" {
		t.newerDef.Inc()
	} else {
		t.tamper.Inc()
	}
	c.pending = true
	// The invalidation commits on its own first: it never waits on, or rolls
	// back with, a repair that cannot finish.
	flushed := true
	var ierr error
	if st.problem != "" {
		ierr = c.preRepairInvalidate(ctx)
	} else {
		ierr = c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return t.invalidate(ctx, tx)
		})
	}
	if ierr != nil {
		if st.problem == "" {
			// pending stays set and the baseline is left alone: the next tick
			// invalidates again, never adopts the current reading.
			return false, fmt.Errorf("invalidate the %s: %w", t.cache, ierr)
		}
		// What the repair restores can be what made this fail (a rule or
		// forced row level security on system_metadata): repair anyway, and
		// the repair's own invalidation is the one that counts.
		c.logf("%s: the invalidation before the repair failed (%v); the repair invalidates again", t.what, ierr)
		flushed = false
	}
	if st.problem != "" {
		// The repair invalidates again in its own transaction, so a write made
		// through the wrong trigger after the first invalidation is flushed
		// when the repair commits. lock_timeout: its DROP TRIGGER takes an
		// ACCESS EXCLUSIVE lock on the table, and a request queued behind an
		// open transaction would stall every reader of the table behind it.
		// The search_path is pinned for the repair's DDL, so the triggers it
		// re-creates call pg_catalog's operators; its catalog reads run under
		// readCatalog, as the reading does.
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
				return err
			}
			if err := pinCatalogSearchPath(tx); err != nil {
				return err
			}
			if err := t.repair(tx, t.def); err != nil {
				return err
			}
			return t.invalidate(ctx, tx)
		}); err != nil {
			// The triggers are still wrong: pending stays set, so every tick
			// invalidates again until a repair commits.
			return flushed, fmt.Errorf("restore the %s triggers: %w", t.what, err)
		}
		flushed = true
	}
	// The repair rewrote catalog rows: the next tick compares against them.
	after, err := readTriggerIntegrity(ctx, c.ls.db, t)
	if err != nil || after.problem != "" {
		// The invalidation committed, but the state after it is not known
		// good: keep pending, so the next tick invalidates and re-reads again.
		return flushed, fmt.Errorf("%s triggers still not this release's after the repair: %q %v", t.what, after.problem, err)
	}
	c.baseline = after.version
	c.pending = false
	return flushed, nil
}

// checkRepairFirst is check for a target whose invalidation goes through the
// trigger being checked and costs an UPDATE per live row (invalidateFrom):
//
//   - a bad definition is repaired in its own transaction, committed before
//     any invalidation. After it the trigger is this release's, so an
//     invalidation that follows is as complete as one inside the repair, and
//     a row lock the invalidation waits on can neither roll the repair back
//     nor keep the repair's ACCESS EXCLUSIVE lock on the table;
//   - the invalidation runs in committed batches of
//     secretNodeCacheEpochInvalidateBatch rows by id and keeps its place
//     across ticks; pending is cleared only after the last batch. A different
//     reading, or a repair that commits, starts it again from the first row;
//   - a reading the repair cannot fix (a session not in 'origin') is reported
//     every tick but invalidated once, not again on every tick.
func (c *triggerIntegrityChecker) checkRepairFirst(ctx context.Context) (bool, error) {
	t := c.target
	st, err := c.readTickIntegrity(ctx)
	if err != nil {
		return c.readFailed(ctx, err)
	}
	c.readFailures = 0
	switch {
	case st.problem != "":
		c.logf("SECURITY: %s triggers cannot be trusted: %s. Restoring them and invalidating every replica's %s; find who has DDL on this schema or changed the server role's database settings.", t.what, st.problem, t.cache)
	case c.pending && integrityKey(st) == c.round:
		c.logf("SECURITY: continuing the %s invalidation after id %d (catalog row versions %s, last good %s).", t.cache, c.cursor, st.version, c.baseline)
	case c.pending:
		c.logf("SECURITY: %s triggers read as this release's (catalog row versions %s, last good %s) while an invalidation is owed. Invalidating every replica's %s from the first row.", t.what, st.version, c.baseline, t.cache)
	case c.baseline == "" || st.version == c.baseline:
		c.baseline = st.version
		c.warnNewer(st)
		return false, nil
	case st.newer != "":
		c.newerDefinitionLog(st)
	default:
		c.logf("SECURITY: %s trigger or function rewritten outside this server (catalog row versions %s, were %s), now matching this release again. Invalidating every replica's %s; find who has DDL on this schema.", t.what, st.version, c.baseline, t.cache)
	}
	if !c.pending || integrityKey(st) != c.round {
		if st.problem == "" && st.newer != "" {
			t.newerDef.Inc()
		} else {
			t.tamper.Inc()
		}
	}
	c.pending = true
	if st.problem != "" {
		// lock_timeout: its DROP TRIGGER takes an ACCESS EXCLUSIVE lock on the
		// table, and a request queued behind an open transaction would stall
		// every reader of the table behind it. The search_path is pinned for
		// the repair's DDL; its catalog reads run under readCatalog.
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
				return err
			}
			if err := pinCatalogSearchPath(tx); err != nil {
				return err
			}
			return t.repair(tx, t.def)
		}); err != nil {
			// The trigger may have been wrong while earlier batches ran: the
			// invalidation starts again once a repair commits.
			c.round = ""
			return false, fmt.Errorf("restore the %s triggers: %w", t.what, err)
		}
		if st, err = readTriggerIntegrity(ctx, c.ls.db, t); err != nil {
			c.round = ""
			return false, fmt.Errorf("re-read the %s triggers after the repair: %w", t.what, err)
		}
		if st.problem == "" {
			c.round = "" // the repair rewrote the definition: from the first row
		}
	}
	if key := integrityKey(st); key != c.round {
		c.round, c.cursor = key, 0
	}
	unfixed := func() error {
		return fmt.Errorf("%s triggers still not this release's after the repair: %q", t.what, st.problem)
	}
	if st.problem != "" && c.doneFor == c.round {
		return false, unfixed() // invalidated once for this reading already
	}
	flushed := false
	for {
		var ids []uint
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			ids, err = t.invalidateFrom(ctx, tx, c.cursor, secretNodeCacheEpochInvalidateBatch)
			return err
		}); err != nil {
			// pending stays set and the committed batches stay done: the next
			// tick continues after c.cursor.
			return flushed, fmt.Errorf("invalidate the %s (continuing after id %d at the next tick): %w", t.cache, c.cursor, err)
		}
		flushed = true
		if len(ids) > 0 {
			c.cursor = slices.Max(ids)
		}
		if len(ids) < secretNodeCacheEpochInvalidateBatch {
			break
		}
	}
	if st.problem != "" {
		c.doneFor = c.round
		return flushed, unfixed()
	}
	// A change made while the batches ran shows as a new version at the next
	// tick, which compares against this one.
	c.baseline = st.version
	c.pending, c.round, c.cursor, c.doneFor = false, "", 0, ""
	return flushed, nil
}

// SetSingleWriter records storage.database.single_writer, before
// StartTriggerIntegrityCheck. It comes from the configuration, not from the
// running fence (swstate), so the check never drops the fence's triggers in
// the window between InstallFence and the guard's Run.
func (ls *LocalStorage) SetSingleWriter(on bool) {
	ls.singleWriter = on
}

// rolePermGenerationTarget is the role-permission generation target for
// this store's mode.
func (ls *LocalStorage) rolePermGenerationTarget() *triggerIntegrityTarget {
	if ls.singleWriter {
		return rolePermGenerationSingleWriterIntegrityTarget
	}
	return rolePermGenerationIntegrityTarget
}

// StartTriggerIntegrityCheck runs the check of every target whose tables
// exist every rolePermGenerationIntegrityInterval in the background, the
// first one now. In single_writer mode (SetSingleWriter) the role-permission
// target leaves the fence's triggers on system_metadata alone; without it
// they are foreign. PostgreSQL only (a no-op on SQLite); Close stops it. A
// failed check is logged and retried at the next tick, never fatal: the
// per-statement proofs still fail closed for a missing or disabled trigger
// in the meantime.
func (ls *LocalStorage) StartTriggerIntegrityCheck(logf func(string, ...any)) {
	if ls.db.Dialector.Name() != "postgres" || ls.rolePermIntegrity != nil {
		return
	}
	var checkers []*triggerIntegrityChecker
	if storeTableExists(ls.db, "role_permissions") && storeTableExists(ls.db, "permissions") && storeTableExists(ls.db, "system_metadata") {
		checkers = append(checkers, &triggerIntegrityChecker{ls: ls, logf: logf, target: ls.rolePermGenerationTarget()})
	}
	if secretNodesTableExists(ls.db) {
		checkers = append(checkers, &triggerIntegrityChecker{ls: ls, logf: logf, target: secretNodeCacheEpochIntegrityTarget})
	}
	if len(checkers) == 0 {
		return
	}
	ctx, job := newBackgroundJob()
	ls.rolePermIntegrity = job
	go func() {
		defer job.exit()
		tick := time.NewTicker(rolePermGenerationIntegrityInterval)
		defer tick.Stop()
		for {
			for _, c := range checkers {
				tctx, tcancel := context.WithTimeout(ctx, rolePermGenerationIntegrityTickTimeout)
				_, err := c.check(tctx)
				tcancel()
				if err != nil && ctx.Err() == nil {
					logf("%s trigger integrity check: %v", c.target.what, err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

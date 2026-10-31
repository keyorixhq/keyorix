// trigger_integrity_exact_match_operator_postgres_test.go — TRIGGER-INTEGRITY-1
// review fix (PR #3841 fourth review, C1): PostgreSQL picks an operator whose
// argument types match exactly before it considers one reached by a
// coercion, wherever the exact one sits in the search_path. pg_catalog has
// no `=` on (oid, regclass), so `t.tgrelid = 'system_metadata'::regclass`
// reaches oideq only through a coercion, and an `=` on (oid, regclass) the
// server's role creates in its own schema (always on the search_path) wins
// over it, with the default search_path and no ALTER ROLE. Pointed at a decoy
// table, the write-target reading read clean while a BEFORE UPDATE trigger on
// the real system_metadata made every generation bump a no-op. The same holds
// for every cross-type operator in the catalog reads (`tgconstraint = 0`,
// `tgtype & 66`, `proconfig IS NOT DISTINCT FROM text[]`, ...): the reads
// must not resolve any operator outside pg_catalog.
package store

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// plantDecoyWriteTarget creates sm_decoy, a copy of system_metadata without
// triggers, an `=` on (oid, regclass) in w's schema that answers for
// sm_decoy when asked about system_metadata (oideq otherwise), and a BEFORE
// UPDATE trigger on the real system_metadata that keeps the generation row.
func plantDecoyWriteTarget(t *testing.T, db *gorm.DB) {
	t.Helper()
	var schema string
	require.NoError(t, db.Raw("SELECT pg_catalog.current_schema()").Scan(&schema).Error)
	require.NoError(t, db.Exec(`CREATE TABLE sm_decoy (LIKE system_metadata)`).Error)
	require.NoError(t, db.Exec(`CREATE FUNCTION `+schema+`.oideqrc(a oid, b regclass) RETURNS boolean LANGUAGE sql STABLE AS
$x$ SELECT CASE WHEN b::oid OPERATOR(pg_catalog.=) pg_catalog.to_regclass('system_metadata')::oid
  THEN a OPERATOR(pg_catalog.=) pg_catalog.to_regclass('sm_decoy')::oid
  ELSE a OPERATOR(pg_catalog.=) b::oid END $x$`).Error)
	require.NoError(t, db.Exec(`CREATE OPERATOR `+schema+`.= (LEFTARG = oid, RIGHTARG = regclass, FUNCTION = `+schema+`.oideqrc)`).Error)
	require.NoError(t, db.Exec(`CREATE FUNCTION keep_generation() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key OPERATOR(pg_catalog.=) 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`).Error)
	require.NoError(t, db.Exec("CREATE TRIGGER keep_generation BEFORE UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE keep_generation()").Error)
}

// dropDecoyOperator removes plantDecoyWriteTarget's operator, which would
// also answer the test helpers' own unqualified catalog queries.
func dropDecoyOperator(t *testing.T, db *gorm.DB) {
	t.Helper()
	var schema string
	require.NoError(t, db.Raw("SELECT pg_catalog.current_schema()").Scan(&schema).Error)
	require.NoError(t, db.Exec("DROP FUNCTION "+schema+".oideqrc(oid, regclass) CASCADE").Error)
}

// A checker that boots after the plant must not adopt it.
func TestRolePermGenerationIntegrity_SystemMetadataDecoyOperatorSeenAtBoot_Postgres(t *testing.T) {
	w, _ := smWriteTargetWorld(t)
	db := w.writer.db
	plantDecoyWriteTarget(t, db)
	fresh := &triggerIntegrityChecker{ls: w.writer, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, fresh)
	dropDecoyOperator(t, db)
	requireSystemMetadataClean(t, db)
}

// A running checker must remove the planted trigger, not take the decoy's
// reading as its new baseline after a flush the trigger swallowed.
func TestRolePermGenerationIntegrity_SystemMetadataDecoyOperatorIsRemovedAndFlushed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	plantDecoyWriteTarget(t, db)
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	dropDecoyOperator(t, db)
	requireSystemMetadataClean(t, db)
}

// exactMatchOperatorTypes are the types the catalog reads compare: the
// catalog columns' own and those of the literals next to them.
var exactMatchOperatorTypes = []string{"oid", "regclass", "regprocedure", "smallint", "integer", "text", "name", `"char"`, "text[]", "boolean", "xid"}

// plantFailingOperators creates in db's schema, for each operator name the
// catalog reads use and each pair of exactMatchOperatorTypes pg_catalog has
// no exact operator for, an operator that raises when called. A read that
// resolves any of them fails. It returns the function names, to drop them
// (and their operators) again.
func plantFailingOperators(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var schema string
	require.NoError(t, db.Raw("SELECT pg_catalog.current_schema()").Scan(&schema).Error)
	var funcs []string
	n := 0
	for _, l := range exactMatchOperatorTypes {
		for _, r := range exactMatchOperatorTypes {
			n++
			fn := schema + ".kx_shadow_" + strconv.Itoa(n)
			created := false
			for _, op := range []string{"=", "<>", "&", "||"} {
				var catalogHas bool
				require.NoError(t, db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_operator o
WHERE o.oprname OPERATOR(pg_catalog.=) ?::pg_catalog.name AND o.oprleft OPERATOR(pg_catalog.=) ?::pg_catalog.regtype::pg_catalog.oid
  AND o.oprright OPERATOR(pg_catalog.=) ?::pg_catalog.regtype::pg_catalog.oid AND o.oprnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace::pg_catalog.oid)`,
					op, l, r).Scan(&catalogHas).Error)
				if catalogHas {
					continue // pg_catalog is searched first: its exact one wins
				}
				if !created {
					require.NoError(t, db.Exec(`CREATE FUNCTION `+fn+`(a `+l+`, b `+r+`) RETURNS boolean LANGUAGE plpgsql AS
$x$ BEGIN RAISE EXCEPTION 'shadow operator on (%, %) resolved', pg_catalog.pg_typeof(a), pg_catalog.pg_typeof(b); END $x$`).Error)
					funcs = append(funcs, fn)
					created = true
				}
				require.NoError(t, db.Exec(`CREATE OPERATOR `+schema+`.`+op+` (LEFTARG = `+l+`, RIGHTARG = `+r+`, FUNCTION = `+fn+`)`).Error)
			}
		}
	}
	return funcs
}

func dropFailingOperators(t *testing.T, db *gorm.DB, funcs []string) {
	t.Helper()
	for _, fn := range funcs {
		require.NoError(t, db.Exec("DROP FUNCTION "+fn+" CASCADE").Error)
	}
}

// Class guard: with an exact-match operator planted for every cross-type
// pair the catalog reads could compare, the check's reading, a tick with its
// repair, and the boot installers' readings and catalog reads must still
// work, so none of them resolves an operator outside pg_catalog. The
// role-permission generation target and the write target here, the
// secret_nodes cache-epoch target below.
func TestTriggerIntegrity_CatalogReadsIgnoreExactMatchOperators_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec(`CREATE FUNCTION keep_generation() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key OPERATOR(pg_catalog.=) 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`).Error)
	require.NoError(t, db.Exec("CREATE TRIGGER keep_generation BEFORE UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE keep_generation()").Error)
	require.NoError(t, db.Exec("ALTER FUNCTION "+rolePermGenerationFunc+"() SET search_path = public").Error)
	funcs := plantFailingOperators(t, db)
	require.NotEmpty(t, funcs)

	ctx := context.Background()
	st, err := readRolePermGenerationIntegrity(ctx, db)
	require.NoError(t, err, "the check's reading")
	require.Contains(t, st.problem, "system_metadata has triggers other than the retention-anchor one")
	require.Contains(t, st.problem, rolePermGenerationFunc+"()")

	flushed, err := c.check(ctx)
	require.NoError(t, err, "a tick and its repair")
	require.True(t, flushed)

	// EnsureAuditRetentionAnchorTrigger is not covered: its own state read
	// decides only whether to re-create the #3359 anchor guard, which the
	// write-target check allows but does not require.
	require.NoError(t, db.Transaction(ensurePostgresRolePermGenerationTriggers), "the boot installer")

	dropFailingOperators(t, db, funcs)
	requireSystemMetadataClean(t, db)
	st, err = readRolePermGenerationIntegrity(ctx, db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the repair restored the definition and the write target")
}

func TestSecretNodeCacheEpochIntegrity_CatalogReadsIgnoreExactMatchOperators_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("ALTER FUNCTION "+secretNodeCacheEpochFunc+"() SET search_path = public").Error)
	funcs := plantFailingOperators(t, w.db)

	ctx := context.Background()
	st, err := readTriggerIntegrity(ctx, w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err, "the check's reading")
	require.Contains(t, st.problem, secretNodeCacheEpochFunc+"()")
	flushed, err := w.c.check(ctx)
	require.NoError(t, err, "a tick and its repair")
	require.True(t, flushed)
	require.NoError(t, w.db.Transaction(ensurePostgresCacheEpochTrigger), "the boot installer")

	dropFailingOperators(t, w.db, funcs)
	st, err = readTriggerIntegrity(ctx, w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the repair restored the definition")
}

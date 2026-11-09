// upgrade_pg_state_test.go -- the PostgreSQL side of upgrade_snapshot_state_test.go:
// the generated old-schema state and the old-version authorization model, plus
// the catalog dumper and snapshot writer/replayer the PG leg of the upgrade fuzz
// uses.
//
// Standard library only, like the SQLite side, and for the same reason: the
// snapshot generator (testdata/upgrade-snapshots-pg/generator) copies this file
// into a checkout of each old release, so ugModel over pgBuildModel is checked
// against that release's own Authorize on Postgres before a snapshot is
// accepted. It shares ugCursor, ugModel, ugConfig and the id ranges with the
// SQLite side and duplicates only what differs in SQL text (no quote(), no
// pragma_table_info, boolean literals, bytea literals, sequences); that file is
// left untouched so the SQLite leg's corpus keeps its meaning.
package storage

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

func pgLit(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case string:
		return "'" + strings.ReplaceAll(t, "'", "''") + "'"
	case []byte:
		return `'\x` + hex.EncodeToString(t) + `'`
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case bool:
		if t {
			return "TRUE"
		}
		return "FALSE"
	}
	panic(fmt.Sprintf("pgLit: unsupported %T", v))
}

func pgColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query("SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = " + pgLit(table) + " ORDER BY ordinal_position")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func pgHasColumn(db *sql.DB, table, column string) (bool, error) {
	cols, err := pgColumns(db, table)
	if err != nil {
		return false, err
	}
	return slices.Contains(cols, column), nil
}

// pgClone inserts a copy of the first row matching where, with overrides applied
// (an override naming a column this schema lacks is ignored). quote_nullable over
// the text form keeps every copied value exact; the literal stays unknown-typed,
// so the column's own type parses it.
func pgClone(db *sql.DB, table, where string, overrides map[string]any) error {
	cols, err := pgColumns(db, table)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return fmt.Errorf("clone into %s: no such table", table)
	}
	exprs := make([]string, len(cols))
	for i, c := range cols {
		exprs[i] = `quote_nullable("` + c + `"::text)`
	}
	raw := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	q := "SELECT " + strings.Join(exprs, ",") + ` FROM "` + table + `" WHERE ` + where + " LIMIT 1"
	if err := db.QueryRow(q).Scan(ptrs...); err != nil {
		return fmt.Errorf("clone template from %s (%s): %w", table, where, err)
	}
	vals := make([]string, len(cols))
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
		if v, ok := overrides[c]; ok {
			vals[i] = pgLit(v)
			continue
		}
		vals[i] = raw[i].String
	}
	ins := `INSERT INTO "` + table + `" (` + strings.Join(quoted, ",") + ") VALUES (" + strings.Join(vals, ",") + ")"
	if _, err := db.Exec(ins); err != nil {
		return fmt.Errorf("clone into %s: %w", table, err)
	}
	return nil
}

// pgFixSequences advances every serial sequence past the largest id the
// generator inserted, as a real old release's own inserts would have.
func pgFixSequences(db *sql.DB) error {
	rows, err := db.Query(`SELECT c.relname, a.attname, pg_get_serial_sequence(quote_ident(c.relname), a.attname)
		FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		AND pg_get_serial_sequence(quote_ident(c.relname), a.attname) IS NOT NULL`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type seq struct{ table, col, name string }
	var all []seq
	for rows.Next() {
		var s seq
		if err := rows.Scan(&s.table, &s.col, &s.name); err != nil {
			return err
		}
		all = append(all, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range all {
		q := fmt.Sprintf(`SELECT setval(%s, GREATEST((SELECT COALESCE(MAX("%s"),0) FROM "%s"), (SELECT last_value FROM %s)))`, pgLit(s.name), s.col, s.table, s.name)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("advancing sequence %s: %w", s.name, err)
		}
	}
	return nil
}

// pgApplyState is ugApplyState on a Postgres old-schema database. Same choices
// over the same cursor, so a seed means the same state on either backend.
func pgApplyState(db *sql.DB, data []byte, cfg ugConfig) (*ugExpect, error) {
	c := &ugCursor{data: data}
	exp := &ugExpect{}
	if cfg.Fold == nil {
		cfg.Fold = func(string) string { return "" }
	}

	type env struct{ id, project uint }
	var projects []uint
	var envs []env
	nProjects := 1 + c.next(3)
	for i := range nProjects {
		id := uint(ugProjectBase + i)
		name := ugNameVariant(c, "proj", i)
		ov := map[string]any{"id": id, "name": name, "name_folded": cfg.Fold(name), "created_at": ugTime, "updated_at": ugTime}
		deleted := c.next(5) == 0
		if deleted {
			ov["deleted_at"] = ugTime
		}
		if err := pgClone(db, "projects", "id = 1", ov); err != nil {
			return nil, err
		}
		projects = append(projects, id)
		for j := range 2 {
			eid := uint(ugEnvBase + i*10 + j)
			eov := map[string]any{"id": eid, "project_id": id, "name": "env" + strconv.Itoa(j), "created_at": ugTime, "updated_at": ugTime}
			if c.next(6) == 0 {
				eov["deleted_at"] = ugTime
			}
			if err := pgClone(db, "environments", "project_id = 1", eov); err != nil {
				return nil, err
			}
			envs = append(envs, env{eid, id})
		}
	}

	var users []uint
	nUsers := 2 + c.next(4)
	for i := range nUsers {
		id := uint(ugUserBase + i)
		name := ugNameVariant(c, "user", i)
		email := "u" + strconv.Itoa(i) + "@example.com"
		if err := pgClone(db, "users", "id = 1", map[string]any{
			"id": id, "username": name, "username_folded": cfg.Fold(name), "email": email, "email_folded": cfg.Fold(email),
			"external_id": nil, "display_name": name, "created_at": ugTime, "updated_at": ugTime,
		}); err != nil {
			return nil, err
		}
		users = append(users, id)
	}

	permIDs, err := ugIDs(db, "SELECT id FROM permissions ORDER BY id")
	if err != nil {
		return nil, err
	}
	seededRoles, err := ugIDs(db, "SELECT id FROM roles ORDER BY id")
	if err != nil {
		return nil, err
	}
	if len(permIDs) == 0 || len(seededRoles) == 0 {
		return nil, fmt.Errorf("template database has no seeded RBAC rows")
	}
	roles := slices.Clone(seededRoles)
	nCustom := c.next(4)
	for i := range nCustom {
		id := uint(ugRoleBase + i)
		name := ugNameVariant(c, "fuzzrole", i)
		ov := map[string]any{"id": id, "name": name, "name_folded": cfg.Fold(name), "description": "generated", "created_at": ugTime, "updated_at": ugTime, "bypasses_permission_checks": false}
		if err := pgClone(db, "roles", "name = 'viewer'", ov); err != nil {
			return nil, err
		}
		roles = append(roles, id)
		for _, p := range permIDs {
			if c.flag() {
				if err := ugExec(db, fmt.Sprintf("INSERT INTO role_permissions (role_id, permission_id) VALUES (%d, %d)", id, p)); err != nil {
					return nil, err
				}
			}
		}
	}

	pickScope := func() (uint, uint) {
		switch c.next(3) {
		case 1:
			return projects[c.next(len(projects))], 0
		case 2:
			e := envs[c.next(len(envs))]
			return e.project, e.id
		}
		return 0, 0
	}

	urHasExpiry, err := pgHasColumn(db, "user_roles", "expires_at")
	if err != nil {
		return nil, err
	}
	seenUR := map[string]bool{}
	nGrants := c.next(10)
	for range nGrants {
		u := users[c.next(len(users))]
		r := roles[c.next(len(roles))]
		p, e := pickScope()
		key := fmt.Sprint(u, "/", r, "/", p, "/", e)
		if seenUR[key] {
			continue
		}
		seenUR[key] = true
		q := fmt.Sprintf("INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (%d, %d, %d, %d)", u, r, p, e)
		if urHasExpiry && c.flag() {
			q = fmt.Sprintf("INSERT INTO user_roles (user_id, role_id, project_id, environment_id, expires_at) VALUES (%d, %d, %d, %d, '2099-01-01 00:00:00+00:00')", u, r, p, e)
		}
		if err := ugExec(db, q); err != nil {
			return nil, err
		}
	}

	nGroups := c.next(3)
	for i := range nGroups {
		id := uint(ugGroupBase + i)
		name := ugNameVariant(c, "group", i)
		ov := map[string]any{"id": id, "name": name, "name_folded": cfg.Fold(name), "description": "generated", "created_at": ugTime, "updated_at": ugTime}
		if c.next(5) == 0 {
			ov["deleted_at"] = ugTime
		}
		if err := pgClone(db, "groups", "1 = 1", ov); err != nil {
			return nil, err
		}
		seenUG := map[uint]bool{}
		for range 1 + c.next(3) {
			u := users[c.next(len(users))]
			if seenUG[u] {
				continue
			}
			seenUG[u] = true
			mp := uint(0)
			if c.next(4) == 0 {
				mp = projects[c.next(len(projects))]
			}
			if err := ugExec(db, fmt.Sprintf("INSERT INTO user_groups (user_id, group_id, project_id) VALUES (%d, %d, %d)", u, id, mp)); err != nil {
				return nil, err
			}
		}
		seenGR := map[string]bool{}
		for range 1 + c.next(3) {
			r := roles[c.next(len(roles))]
			p, e := pickScope()
			key := fmt.Sprint(r, "/", p, "/", e)
			if seenGR[key] {
				continue
			}
			seenGR[key] = true
			if err := ugExec(db, fmt.Sprintf("INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (%d, %d, %d, %d)", id, r, p, e)); err != nil {
				return nil, err
			}
		}
	}

	if cfg.Encrypt != nil {
		nSecrets := 1 + c.next(5)
		for i := range nSecrets {
			id := uint(ugSecretBase + i)
			var project, envID uint
			if c.flag() {
				e := envs[c.next(len(envs))]
				project, envID = e.project, e.id
			} else {
				project, envID = 1, 1
			}
			name := ugNameVariant(c, "secret", i)
			deleted := c.next(5) == 0
			sov := map[string]any{"id": id, "project_id": project, "environment_id": envID, "name": name, "created_at": ugTime, "updated_at": ugTime}
			if deleted {
				sov["deleted_at"] = ugTime
			}
			if err := pgClone(db, "secret_nodes", "id = 1", sov); err != nil {
				return nil, err
			}
			s := ugSecret{ID: id, ProjectID: project, EnvironmentID: envID, Name: name, Deleted: deleted}
			nVersions := 1 + c.next(3)
			for v := 1; v <= nVersions; v++ {
				pt := make([]byte, 1+c.next(40))
				for k := range pt {
					pt[k] = byte(c.next(256))
				}
				pt = fmt.Appendf(pt, "-%d-%d", id, v)
				ct, meta, err := cfg.Encrypt(pt, cfg.AAD(id, project, v))
				if err != nil {
					return nil, fmt.Errorf("encrypt generated secret %d v%d: %w", id, v, err)
				}
				if err := pgClone(db, "secret_versions", "secret_node_id = 1", map[string]any{
					"id": int64(100000 + i*10 + v), "secret_node_id": id, "version_number": v,
					"encrypted_value": ct, "encryption_metadata": meta, "read_count": 0, "created_at": ugTime,
				}); err != nil {
					return nil, err
				}
				s.Versions = append(s.Versions, ugVersion{Number: v, Plaintext: pt})
			}
			exp.Secrets = append(exp.Secrets, s)
		}
	}

	if cfg.SealAudit != nil {
		var head string
		var lastID int64
		if err := db.QueryRow("SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&lastID, &head); err != nil {
			return nil, fmt.Errorf("read audit chain head: %w", err)
		}
		n := c.next(6)
		for i := range n {
			id := lastID + 1 + int64(i)
			at := time.Date(2026, 3, 4, 5, 6, i, 0, time.UTC).Format("2006-01-02 15:04:05.000000-07:00")
			if err := pgClone(db, "audit_events", fmt.Sprintf("id = %d", lastID), map[string]any{
				"id": id, "event_type": "fuzz.generated", "description": "generated-" + strconv.Itoa(i),
				"event_time": at, "prev_hash": head, "entry_hash": "",
			}); err != nil {
				return nil, err
			}
			next, err := cfg.SealAudit(db, id, head)
			if err != nil {
				return nil, err
			}
			if err := ugExec(db, fmt.Sprintf("UPDATE audit_events SET entry_hash = %s WHERE id = %d", pgLit(next), id)); err != nil {
				return nil, err
			}
			head = next
			exp.AuditAdded++
		}
	}
	return exp, pgFixSequences(db)
}

// pgBuildModel is ugBuildModel on Postgres: the same rule over the same rows.
func pgBuildModel(db *sql.DB) (*ugModel, error) {
	m := &ugModel{
		direct: map[uint][]ugGrant{}, groupGrants: map[uint][]ugGrant{},
		membership: map[uint]map[uint]uint{}, groupLive: map[uint]bool{},
		rolePerm: map[uint]map[string]bool{}, bypass: map[uint]bool{},
	}
	live := func(table string) (map[uint]bool, error) {
		out := map[uint]bool{}
		rows, err := db.Query(`SELECT id, deleted_at IS NULL FROM "` + table + `"`)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uint
			var ok bool
			if err := rows.Scan(&id, &ok); err != nil {
				return nil, err
			}
			out[id] = ok
		}
		return out, rows.Err()
	}
	projects, err := live("projects")
	if err != nil {
		return nil, err
	}
	envs, err := live("environments")
	if err != nil {
		return nil, err
	}
	if m.groupLive, err = live("groups"); err != nil {
		return nil, err
	}
	if m.Users, err = ugIDs(db, "SELECT id FROM users WHERE deleted_at IS NULL ORDER BY id"); err != nil {
		return nil, err
	}

	grantRows := func(table, owner string, sink func(uint, ugGrant)) error {
		expiry := "TRUE"
		has, err := pgHasColumn(db, table, "expires_at")
		if err != nil {
			return err
		}
		if has {
			expiry = "expires_at IS NULL OR expires_at > '2026-06-01'"
		}
		q := fmt.Sprintf(`SELECT %s, role_id, COALESCE(project_id,0), COALESCE(environment_id,0), %s FROM "%s"`, owner, expiry, table)
		rows, err := db.Query(q)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var o uint
			var g ugGrant
			if err := rows.Scan(&o, &g.role, &g.project, &g.env, &g.notExpired); err != nil {
				return err
			}
			g.projectLive = g.project == 0 || projects[g.project]
			g.environmentLve = g.env == 0 || envs[g.env]
			sink(o, g)
		}
		return rows.Err()
	}
	if err := grantRows("user_roles", "user_id", func(o uint, g ugGrant) { m.direct[o] = append(m.direct[o], g) }); err != nil {
		return nil, err
	}
	if err := grantRows("group_roles", "group_id", func(o uint, g ugGrant) { m.groupGrants[o] = append(m.groupGrants[o], g) }); err != nil {
		return nil, err
	}

	mrows, err := db.Query("SELECT user_id, group_id, COALESCE(project_id,0) FROM user_groups")
	if err != nil {
		return nil, err
	}
	defer func() { _ = mrows.Close() }()
	for mrows.Next() {
		var u, g, p uint
		if err := mrows.Scan(&u, &g, &p); err != nil {
			return nil, err
		}
		if m.membership[u] == nil {
			m.membership[u] = map[uint]uint{}
		}
		m.membership[u][g] = p
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}

	prows, err := db.Query("SELECT rp.role_id, p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = prows.Close() }()
	for prows.Next() {
		var r uint
		var n string
		if err := prows.Scan(&r, &n); err != nil {
			return nil, err
		}
		if m.rolePerm[r] == nil {
			m.rolePerm[r] = map[string]bool{}
		}
		m.rolePerm[r][n] = true
	}
	if err := prows.Err(); err != nil {
		return nil, err
	}
	rrows, err := db.Query("SELECT id, name FROM roles")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rrows.Close() }()
	for rrows.Next() {
		var id uint
		var n string
		if err := rrows.Scan(&id, &n); err != nil {
			return nil, err
		}
		m.bypass[id] = slices.Contains(ugBypassNames, n)
	}
	if err := rrows.Err(); err != nil {
		return nil, err
	}

	m.Scopes = append(m.Scopes, [2]uint{0, 0})
	pids := make([]uint, 0, len(projects))
	for id := range projects {
		pids = append(pids, id)
	}
	slices.Sort(pids)
	for _, p := range pids {
		m.Scopes = append(m.Scopes, [2]uint{p, 0})
		eids, err := ugIDs(db, fmt.Sprintf("SELECT id FROM environments WHERE project_id = %d ORDER BY id", p))
		if err != nil {
			return nil, err
		}
		for _, e := range eids {
			m.Scopes = append(m.Scopes, [2]uint{p, e})
		}
	}
	return m, nil
}

// pgStmtSep ends each statement of a snapshot script; function bodies contain
// semicolons, so the replay splits on this line rather than parsing SQL.
const pgStmtSep = "\n-- end-of-statement\n"

// pgDumpFuncs is the catalog queries shared by the dumper and the schema diff.
const (
	pgTablesQ = `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r' ORDER BY 1`
	pgColumnsQ = `SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		COALESCE(pg_get_expr(d.adbin, d.adrelid), '') FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE n.nspname = current_schema() AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY c.relname, a.attnum`
	pgConstraintsQ = `SELECT rel.relname, con.conname, con.contype::text, pg_get_constraintdef(con.oid)
		FROM pg_constraint con JOIN pg_class rel ON rel.oid = con.conrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
		WHERE n.nspname = current_schema() AND rel.relkind = 'r' ORDER BY 1, 2`
	pgIndexesQ = `SELECT i.relname, pg_get_indexdef(idx.indexrelid), idx.indisvalid FROM pg_index idx
		JOIN pg_class i ON i.oid = idx.indexrelid JOIN pg_class t ON t.oid = idx.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = current_schema() AND t.relkind = 'r'
		AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = idx.indexrelid AND con.conrelid = idx.indrelid AND con.contype IN ('p','u','x'))
		ORDER BY 1`
	pgSequencesQ = `SELECT s.relname, COALESCE(tc.relname, ''), COALESCE(a.attname, ''), seq.seqstart, seq.seqincrement, seq.seqmax, seq.seqmin, seq.seqcache, seq.seqcycle
		FROM pg_sequence seq JOIN pg_class s ON s.oid = seq.seqrelid JOIN pg_namespace n ON n.oid = s.relnamespace
		LEFT JOIN pg_depend d ON d.objid = s.oid AND d.deptype = 'a' AND d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
		LEFT JOIN pg_class tc ON tc.oid = d.refobjid LEFT JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		WHERE n.nspname = current_schema() ORDER BY 1`
	pgTriggersQ = `SELECT t.tgname, c.relname, pg_get_triggerdef(t.oid) FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND NOT t.tgisinternal ORDER BY 2, 1`
	pgFunctionsQ = `SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', pg_get_functiondef(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = current_schema() AND p.prokind = 'f' ORDER BY 1`
)

// pgQueryLines runs q and renders each row as one line of NUL-free text.
func pgQueryLines(db *sql.DB, q, prefix string) ([]string, error) {
	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = v.String
		}
		out = append(out, prefix+" "+strings.Join(parts, " | "))
	}
	return out, rows.Err()
}

// pgDumpDB renders the schema and every row deterministically, so two calls
// differ exactly when the database does. Sequence values are part of it: a
// migration that consumes one has changed the database.
func pgDumpDB(db *sql.DB) ([]byte, error) {
	var out bytes.Buffer
	for _, s := range []struct{ q, prefix string }{
		{pgColumnsQ, "column"}, {pgConstraintsQ, "constraint"}, {pgIndexesQ, "index"},
		{pgSequencesQ, "sequence"}, {pgTriggersQ, "trigger"}, {pgFunctionsQ, "function"},
	} {
		lines, err := pgQueryLines(db, s.q, s.prefix)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			out.WriteString(l + "\n")
		}
	}
	seqs, err := pgQueryLines(db, `SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND relkind = 'S' ORDER BY 1`, "")
	if err != nil {
		return nil, err
	}
	for _, s := range seqs {
		name := strings.TrimSpace(s)
		var v int64
		var called bool
		if err := db.QueryRow(`SELECT last_value, is_called FROM "`+name+`"`).Scan(&v, &called); err != nil {
			return nil, fmt.Errorf("reading sequence %s: %w", name, err)
		}
		fmt.Fprintf(&out, "seqval %s %d %v\n", name, v, called)
	}
	tables, err := pgTableNames(db)
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		lines, err := pgQueryLines(db, `SELECT to_jsonb(r)::text FROM "`+t+`" r ORDER BY 1`, "row "+t)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			out.WriteString(l + "\n")
		}
	}
	return out.Bytes(), nil
}

func pgTableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(pgTablesQ)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// pgSnapshotSQL writes the whole of db's current schema as a script that recreates
// it exactly when replayed. The generator emits it; pgDumpDB over the replayed
// copy compared to pgDumpDB over the source is its fidelity check.
func pgSnapshotSQL(db *sql.DB) (string, error) {
	var w strings.Builder
	stmt := func(s string) { w.WriteString(s); w.WriteString(pgStmtSep) }

	seqs, err := pgQueryRows(db, pgSequencesQ, 9)
	if err != nil {
		return "", err
	}
	for _, s := range seqs {
		cycle := ""
		if s[8] == "true" {
			cycle = " CYCLE"
		}
		stmt(fmt.Sprintf(`CREATE SEQUENCE "%s" START WITH %s INCREMENT BY %s MAXVALUE %s MINVALUE %s CACHE %s%s`, s[0], s[3], s[4], s[5], s[6], s[7], cycle))
	}

	cols, err := pgQueryRows(db, pgColumnsQ, 5)
	if err != nil {
		return "", err
	}
	var currentT string
	var defs []string
	flush := func() {
		if currentT != "" {
			stmt(`CREATE TABLE "` + currentT + `" (` + strings.Join(defs, ", ") + `)`)
		}
		defs = nil
	}
	for _, c := range cols {
		if c[0] != currentT {
			flush()
			currentT = c[0]
		}
		d := `"` + c[1] + `" ` + c[2]
		if c[4] != "" {
			d += " DEFAULT " + c[4]
		}
		if c[3] == "true" {
			d += " NOT NULL"
		}
		defs = append(defs, d)
	}
	flush()

	for _, s := range seqs {
		if s[1] != "" {
			stmt(fmt.Sprintf(`ALTER SEQUENCE "%s" OWNED BY "%s"."%s"`, s[0], s[1], s[2]))
		}
	}

	tables, err := pgTableNames(db)
	if err != nil {
		return "", err
	}
	for _, t := range tables {
		tcols, err := pgColumns(db, t)
		if err != nil {
			return "", err
		}
		exprs := make([]string, len(tcols))
		quoted := make([]string, len(tcols))
		for i, c := range tcols {
			exprs[i] = `quote_nullable("` + c + `"::text)`
			quoted[i] = `"` + c + `"`
		}
		rows, err := pgQueryRows(db, `SELECT `+strings.Join(exprs, ",")+` FROM "`+t+`" ORDER BY `+pgRowOrder(tcols), len(tcols))
		if err != nil {
			return "", fmt.Errorf("dumping %s: %w", t, err)
		}
		for _, r := range rows {
			stmt(`INSERT INTO "` + t + `" (` + strings.Join(quoted, ",") + `) VALUES (` + strings.Join(r, ",") + `)`)
		}
	}

	cons, err := pgQueryRows(db, pgConstraintsQ, 4)
	if err != nil {
		return "", err
	}
	for _, kinds := range []string{"pcx", "uf"} { // primary/check/exclude, then unique and foreign key
		for _, c := range cons {
			if !strings.Contains(kinds, c[2]) || c[2] == "n" {
				continue
			}
			stmt(`ALTER TABLE "` + c[0] + `" ADD CONSTRAINT "` + c[1] + `" ` + c[3])
		}
	}
	idx, err := pgQueryRows(db, pgIndexesQ, 3)
	if err != nil {
		return "", err
	}
	for _, i := range idx {
		if i[2] != "true" {
			return "", fmt.Errorf("index %s is invalid in the source database", i[0])
		}
		stmt(i[1])
	}
	funcs, err := pgQueryRows(db, pgFunctionsQ, 2)
	if err != nil {
		return "", err
	}
	for _, f := range funcs {
		stmt(f[1])
	}
	trigs, err := pgQueryRows(db, pgTriggersQ, 3)
	if err != nil {
		return "", err
	}
	for _, t := range trigs {
		stmt(t[2])
	}
	vals, err := pgSeqValues(db)
	if err != nil {
		return "", err
	}
	for _, v := range vals {
		stmt(fmt.Sprintf("SELECT setval(%s, %d, %v)", pgLit(v.name), v.val, v.called))
	}
	return w.String(), nil
}

// pgRowOrder sorts on every column so the script is byte-stable however the
// heap happens to be laid out.
func pgRowOrder(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = `"` + c + `"`
	}
	return strings.Join(q, ",")
}

func pgQueryRows(db *sql.DB, q string, n int) ([][]string, error) {
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, n)
		ptrs := make([]any, n)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := make([]string, n)
		for i, v := range vals {
			r[i] = v.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type pgSeqValue struct {
	name   string
	val    int64
	called bool
}

func pgSeqValues(db *sql.DB) ([]pgSeqValue, error) {
	names, err := pgQueryRows(db, `SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND relkind = 'S' ORDER BY 1`, 1)
	if err != nil {
		return nil, err
	}
	var out []pgSeqValue
	for _, n := range names {
		v := pgSeqValue{name: n[0]}
		if err := db.QueryRow(`SELECT last_value, is_called FROM "`+n[0]+`"`).Scan(&v.val, &v.called); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// pgReplaySnapshot replays a pgSnapshotSQL script in one transaction, so a bad
// script leaves nothing behind.
func pgReplaySnapshot(db *sql.DB, script string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for s := range strings.SplitSeq(script, pgStmtSep) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("replaying statement %.120q: %w", s, err)
		}
	}
	return tx.Commit()
}

// upgrade_snapshot_state_test.go -- the deterministic old-schema state generator
// and the old-version authorization model behind FuzzUpgradeFromOldSchema.
//
// This file deliberately imports only the standard library. The snapshot
// generator copies it (with the package clause rewritten) into a checkout of
// each old release, where the same code runs against that release's schema and
// that release's own core.Authorize. That is what makes ugModel an old-version
// model rather than a guess at one: every snapshot under
// testdata/upgrade-snapshots was only produced after the model agreed with the
// release's real decision on every probe of every generator seed. See
// testdata/upgrade-snapshots/README.md.
//
// What the model does NOT cover, on purpose: a grant naming a project or
// environment row that does not exist. v0.93.0's query admitted such a grant
// (projects.deleted_at IS NULL is true for a missing row) and HEAD's refuses it
// (projects.id IS NOT NULL), a deliberate tightening unrelated to migration, so
// the generator never writes one. It also models neither machine identities,
// PAT restrictions, SecretACLs nor shares; those never enter a probe.
package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ugCursor turns fuzz bytes into small bounded choices. An exhausted input reads
// as all zeros, so every byte string decodes to some valid state.
type ugCursor struct {
	data []byte
	i    int
}

func (c *ugCursor) next(n int) int {
	if n <= 0 || c.i >= len(c.data) {
		return 0
	}
	v := int(c.data[c.i]) % n
	c.i++
	return v
}

func (c *ugCursor) flag() bool { return c.next(2) == 1 }

// ugConfig supplies what differs between HEAD and an old release's tree.
type ugConfig struct {
	// Encrypt and AAD produce a version row exactly as core.encryptVersionValue
	// does. Nil Encrypt leaves generated secrets out entirely.
	Encrypt func(plaintext, aad []byte) (ciphertext, metadata []byte, err error)
	AAD     func(secretID, projectID uint, version int) []byte
	// Fold returns a name's folded form, or "" where the release has none.
	Fold func(name string) string
	// SealAudit computes the entry hash for the row just cloned at id, given the
	// prior chain head. Nil leaves generated audit rows out.
	SealAudit func(db *sql.DB, id int64, prev string) (string, error)
}

// ugVersion and ugSecret are what a generated secret must still decrypt to.
type ugVersion struct {
	Number    int
	Plaintext []byte
}

type ugSecret struct {
	ID, ProjectID, EnvironmentID uint
	Name                         string
	Deleted                      bool
	Versions                     []ugVersion
}

// ugExpect is the generated state's expected content.
type ugExpect struct {
	Secrets    []ugSecret
	AuditAdded int
}

const ugTime = "2026-01-02 03:04:05+00:00"

// Fixed id ranges keep generated rows clear of the snapshot's own.
const (
	ugProjectBase = 1000
	ugEnvBase     = 2000
	ugUserBase    = 3000
	ugRoleBase    = 4000
	ugGroupBase   = 5000
	ugSecretBase  = 6000
)

func ugLit(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case string:
		return "'" + strings.ReplaceAll(t, "'", "''") + "'"
	case []byte:
		return "X'" + hex.EncodeToString(t) + "'"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case bool:
		if t {
			return "1"
		}
		return "0"
	}
	panic(fmt.Sprintf("ugLit: unsupported %T", v))
}

func ugColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(" + ugLit(table) + ")")
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

// ugClone inserts a copy of the first row matching where, with overrides applied
// (an override naming a column this schema lacks is ignored). Cloning a row the
// old release really wrote is what keeps the generated row faithful to columns
// this file has never heard of. quote() keeps every copied value byte-exact.
func ugClone(db *sql.DB, table, where string, overrides map[string]any) error {
	cols, err := ugColumns(db, table)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return fmt.Errorf("clone into %s: no such table", table)
	}
	exprs := make([]string, len(cols))
	for i, c := range cols {
		exprs[i] = `quote("` + c + `")`
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
			vals[i] = ugLit(v)
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

func ugExec(db *sql.DB, q string) error {
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("%s: %w", q, err)
	}
	return nil
}

func ugHasColumn(db *sql.DB, table, column string) (bool, error) {
	cols, err := ugColumns(db, table)
	if err != nil {
		return false, err
	}
	return slices.Contains(cols, column), nil
}

// ugNameVariant returns a name that is unique per index even after case folding
// and NFC, in one of the shapes the folding backfills exist for. The trailing
// index is what rules out an intended-refusal collision (INV-STORAGE-18).
func ugNameVariant(c *ugCursor, base string, i int) string {
	switch c.next(3) {
	case 1:
		return strings.ToUpper(base[:1]) + base[1:] + "-" + strconv.Itoa(i)
	case 2:
		return base + "-café-" + strconv.Itoa(i)
	}
	return base + "-" + strconv.Itoa(i)
}

func ugIDs(db *sql.DB, q string) ([]uint, error) {
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uint
	for rows.Next() {
		var id uint
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ugApplyState writes the state data decodes to on the old-schema database db.
func ugApplyState(db *sql.DB, data []byte, cfg ugConfig) (*ugExpect, error) {
	c := &ugCursor{data: data}
	exp := &ugExpect{}
	if cfg.Fold == nil {
		cfg.Fold = func(string) string { return "" }
	}

	// Projects and environments.
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
		if err := ugClone(db, "projects", "id = 1", ov); err != nil {
			return nil, err
		}
		projects = append(projects, id)
		for j := range 2 {
			eid := uint(ugEnvBase + i*10 + j)
			eov := map[string]any{"id": eid, "project_id": id, "name": "env" + strconv.Itoa(j), "created_at": ugTime, "updated_at": ugTime}
			if c.next(6) == 0 {
				eov["deleted_at"] = ugTime
			}
			if err := ugClone(db, "environments", "project_id = 1", eov); err != nil {
				return nil, err
			}
			envs = append(envs, env{eid, id})
		}
	}

	// Users.
	var users []uint
	nUsers := 2 + c.next(4)
	for i := range nUsers {
		id := uint(ugUserBase + i)
		name := ugNameVariant(c, "user", i)
		email := "u" + strconv.Itoa(i) + "@example.com"
		if err := ugClone(db, "users", "id = 1", map[string]any{
			"id": id, "username": name, "username_folded": cfg.Fold(name), "email": email, "email_folded": cfg.Fold(email),
			"external_id": nil, "display_name": name, "created_at": ugTime, "updated_at": ugTime,
		}); err != nil {
			return nil, err
		}
		users = append(users, id)
	}

	// Custom roles over the seeded permissions, plus the seeded roles to pick from.
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
		if err := ugClone(db, "roles", "name = 'viewer'", ov); err != nil {
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

	// Direct grants.
	urHasExpiry, err := ugHasColumn(db, "user_roles", "expires_at")
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

	// Groups: membership (global or project-bound) and group grants.
	nGroups := c.next(3)
	for i := range nGroups {
		id := uint(ugGroupBase + i)
		name := ugNameVariant(c, "group", i)
		ov := map[string]any{"id": id, "name": name, "name_folded": cfg.Fold(name), "description": "generated", "created_at": ugTime, "updated_at": ugTime}
		if c.next(5) == 0 {
			ov["deleted_at"] = ugTime
		}
		if err := ugClone(db, "groups", "1 = 1", ov); err != nil {
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

	// Secrets, each with 1-3 versions (a later version is a rotation).
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
			if err := ugClone(db, "secret_nodes", "id = 1", sov); err != nil {
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
				if err := ugClone(db, "secret_versions", "secret_node_id = 1", map[string]any{
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

	// Audit rows appended to the old release's own chain.
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
			if err := ugClone(db, "audit_events", fmt.Sprintf("id = %d", lastID), map[string]any{
				"id": id, "event_type": "fuzz.generated", "description": "generated-" + strconv.Itoa(i),
				"event_time": at, "prev_hash": head, "entry_hash": "",
			}); err != nil {
				return nil, err
			}
			next, err := cfg.SealAudit(db, id, head)
			if err != nil {
				return nil, err
			}
			if err := ugExec(db, fmt.Sprintf("UPDATE audit_events SET entry_hash = %s WHERE id = %d", ugLit(next), id)); err != nil {
				return nil, err
			}
			head = next
			exp.AuditAdded++
		}
	}
	return exp, nil
}

// ugGrant is one role assignment at a scope.
type ugGrant struct {
	role           uint
	project, env   uint
	notExpired     bool
	projectLive    bool
	environmentLve bool
}

// ugModel answers Authorize from the rows of an old-schema database, using the
// rule every release from v0.92 to HEAD implements (see the file comment for the
// shapes it does not model).
type ugModel struct {
	direct      map[uint][]ugGrant
	groupGrants map[uint][]ugGrant
	membership  map[uint]map[uint]uint // user -> group -> membership project
	groupLive   map[uint]bool
	rolePerm    map[uint]map[string]bool
	bypass      map[uint]bool
	Users       []uint
	Scopes      [][2]uint
}

// ugBypassNames are the admin-tier seeded role names. Every supported release
// gives exactly these the permission bypass, by name or by the ADR-084 flag.
var ugBypassNames = []string{"super_admin", "admin", "system_admin", "project_admin"}

// ugProbePerms is the fixed permission probe set.
var ugProbePerms = []string{"secrets.read", "secrets.write", "audit.read", "roles.assign"}

func ugBuildModel(db *sql.DB) (*ugModel, error) {
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
		expiry := "1"
		has, err := ugHasColumn(db, table, "expires_at")
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

	// Fixed scope probes: global, every project, every project-environment pair
	// that exists (live or soft-deleted).
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

func ugGrantApplies(g ugGrant, project, env uint) bool {
	if !g.notExpired {
		return false
	}
	if g.project != 0 && (g.project != project || !g.projectLive) {
		return false
	}
	if g.env != 0 && (g.env != env || !g.environmentLve) {
		return false
	}
	return true
}

// Decide is the old-version decision for user holding perm at (project, env).
func (m *ugModel) Decide(user uint, perm string, project, env uint) bool {
	roles := map[uint]bool{}
	for _, g := range m.direct[user] {
		if ugGrantApplies(g, project, env) {
			roles[g.role] = true
		}
	}
	for group, mp := range m.membership[user] {
		if !m.groupLive[group] || (mp != 0 && mp != project) {
			continue
		}
		for _, g := range m.groupGrants[group] {
			if ugGrantApplies(g, project, env) {
				roles[g.role] = true
			}
		}
	}
	for r := range roles {
		if m.bypass[r] || m.rolePerm[r][perm] {
			return true
		}
	}
	return false
}

// normalize_backfill.go — Go-side backfill for the new *_folded/NFC-normalized
// identity columns (#1642). Unlike the LOWER()-based partial indexes elsewhere in
// this package, Unicode NFC normalization and PRECIS case-folding can't be
// expressed as a portable SQL expression both SQLite and Postgres support, so this
// reads every row, computes the target value in Go via internal/identity, and
// writes it back — refusing outright (no row modified) if two existing rows would
// normalize to the same identity, since silently merging two identities on
// upgrade is the worst possible outcome of a normalization migration.
package storage

import (
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/identity"
)

// foldIdentity adapts identity.NewFoldedName to backfillFoldedColumn's
// fold func(string) (string, error) shape.
func foldIdentity(raw string) (string, error) {
	n, err := identity.NewFoldedName(raw)
	if err != nil {
		return "", err
	}
	return n.Folded(), nil
}

// normalizeAddress adapts identity.NewAddressName to backfillFoldedColumn's
// fold func(string) (string, error) shape.
func normalizeAddress(raw string) (string, error) {
	n, err := identity.NewAddressName(raw)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// backfillFoldedColumn computes foldColumn for every row of table (optionally
// scoped by whereClause) from sourceColumn, via fold, and writes it back.
// Only rows where foldColumn is still empty are considered — a non-empty value
// means either an earlier run already backfilled it, or a normalization-aware
// write path (post-#1642) already populated it correctly at create/update time.
//
// Refuses to write ANY row if two different rows' source values normalize to
// the same folded value: this is a genuine identity collision uncovered by
// tightening the definition of "the same name", and auto-resolving it (keep
// one, drop/rename the other) is exactly the kind of unattended data-merging
// decision this codebase's own #490 precedent (warnIfDuplicatesExist) refuses
// to make. The operator must resolve it deliberately via the application's own
// rename/merge API, which records a proper audit entry.
func backfillFoldedColumn(db *gorm.DB, table, idColumn, sourceColumn, foldColumn, whereClause string, fold func(string) (string, error)) error {
	type row struct {
		ID     uint
		Source string
	}
	var rows []row
	q := db.Table(table).Select(idColumn + " AS id, " + sourceColumn + " AS source")
	q = q.Where(foldColumn + " = '' OR " + foldColumn + " IS NULL")
	if whereClause != "" {
		q = q.Where(whereClause)
	}
	if err := q.Scan(&rows).Error; err != nil {
		return fmt.Errorf("failed to read %s for %s backfill: %w", table, foldColumn, err)
	}
	if len(rows) == 0 {
		return nil
	}

	foldedByID := make(map[uint]string, len(rows))
	idsByFolded := make(map[string][]uint, len(rows))
	for _, r := range rows {
		folded, err := fold(r.Source)
		if err != nil {
			return fmt.Errorf("failed to normalize %s.%s=%q (id=%d): %w", table, sourceColumn, r.Source, r.ID, err)
		}
		foldedByID[r.ID] = folded
		idsByFolded[folded] = append(idsByFolded[folded], r.ID)
	}

	var collisions []string
	for folded, ids := range idsByFolded {
		if len(ids) > 1 {
			collisions = append(collisions, fmt.Sprintf("%q shared by %s row id(s) %v", folded, table, ids))
		}
	}
	if len(collisions) > 0 {
		sort.Strings(collisions)
		return fmt.Errorf(
			"cannot backfill %s.%s: %d existing row group(s) normalize to the same identity under Unicode NFC normalization/case-folding -- "+
				"resolve manually via the application's rename API before upgrading (renaming one row changes only that row's identity, never merges the two): %s",
			table, foldColumn, len(collisions), strings.Join(collisions, "; "))
	}

	for id, folded := range foldedByID {
		if err := db.Table(table).Where(idColumn+" = ?", id).Update(foldColumn, folded).Error; err != nil {
			return fmt.Errorf("failed to backfill %s.%s for id=%d: %w", table, foldColumn, id, err)
		}
	}
	return nil
}

// normalizeColumnInPlace re-normalizes every row of table's column (scoped by
// whereClause) via normalize, overwriting the SAME column with its normalized
// form — unlike backfillFoldedColumn, there is no separate target column,
// because normalize (identity.NewAddressName, for secret names) does not
// fold case: the normalized value IS the value to display, so there is
// nothing to keep display-distinct-from-comparison the way the *_folded
// columns do. Only rows whose normalized form actually differs from the
// stored value are written, so this is a no-op for an already-normalized
// database. Same fail-loud collision refusal as backfillFoldedColumn: if two
// existing rows normalize to the same value WITHIN THE SAME scopeColumns
// tuple, nothing is written and the error lists every colliding pair for
// manual resolution.
//
// scopeColumns is a comma-separated list of column names (or "" for no
// scoping) that participate in the column's own real uniqueness constraint.
// This matters because not every normalized column is globally unique the
// way roles.name_folded/users.username_folded are: secret_nodes.name is only
// unique within (project_id, environment_id) — see
// uniq_secret_nodes_project_env_name_active — so two secrets legitimately
// named "DATABASE_URL" in different projects are not a collision and must
// not be grouped together. Passing "" preserves the original global-grouping
// behavior for callers whose column genuinely has no scope (the *_folded
// columns).
func normalizeColumnInPlace(db *gorm.DB, table, idColumn, column, whereClause, scopeColumns string, normalize func(string) (string, error)) error {
	type row struct {
		ID     uint
		Source string
		Scope  string
	}
	var rows []row
	// scopeColumns is a comma-separated raw column-name list (matching
	// warnIfDuplicatesExist's keyExpr convention elsewhere in this package),
	// combined here into one delimited string via the portable CAST(...AS
	// TEXT) || sep || ... form (both SQLite and Postgres support TEXT casts
	// and the || concatenation operator identically) rather than any
	// dialect-specific tuple/ROW syntax. \x1f (ASCII unit separator) can't
	// appear in an integer column's textual representation, so it can't be
	// spoofed into a false cross-scope match.
	scopeExpr := "''"
	if scopeColumns != "" {
		cols := strings.Split(scopeColumns, ",")
		parts := make([]string, len(cols))
		for i, c := range cols {
			parts[i] = "CAST(" + strings.TrimSpace(c) + " AS TEXT)"
		}
		scopeExpr = strings.Join(parts, " || '\x1f' || ")
	}
	q := db.Table(table).Select(idColumn + " AS id, " + column + " AS source, (" + scopeExpr + ") AS scope")
	if whereClause != "" {
		q = q.Where(whereClause)
	}
	if err := q.Scan(&rows).Error; err != nil {
		return fmt.Errorf("failed to read %s for %s normalization: %w", table, column, err)
	}
	if len(rows) == 0 {
		return nil
	}

	type change struct {
		id  uint
		new string
	}
	var changes []change
	// Keyed on scope+"\x00"+normalized so two rows only collide when they
	// share BOTH the same scope tuple and the same normalized value — a
	// NUL byte can't appear in either half (scope is numeric column values
	// joined by SQL concatenation; normalized is a validated identity/
	// address string), so this can't be spoofed into a false match.
	idsByScopeAndNormalized := make(map[string][]uint, len(rows))
	keyLabel := make(map[string]string, len(rows))
	for _, r := range rows {
		normalized, err := normalize(r.Source)
		if err != nil {
			return fmt.Errorf("failed to normalize %s.%s=%q (id=%d): %w", table, column, r.Source, r.ID, err)
		}
		key := r.Scope + "\x00" + normalized
		idsByScopeAndNormalized[key] = append(idsByScopeAndNormalized[key], r.ID)
		if scopeColumns != "" {
			keyLabel[key] = fmt.Sprintf("%q (scope %s=%s)", normalized, scopeColumns, r.Scope)
		} else {
			keyLabel[key] = fmt.Sprintf("%q", normalized)
		}
		if normalized != r.Source {
			changes = append(changes, change{id: r.ID, new: normalized})
		}
	}

	var collisions []string
	for key, ids := range idsByScopeAndNormalized {
		if len(ids) > 1 {
			collisions = append(collisions, fmt.Sprintf("%s shared by %s row id(s) %v", keyLabel[key], table, ids))
		}
	}
	if len(collisions) > 0 {
		sort.Strings(collisions)
		return fmt.Errorf(
			"cannot normalize %s.%s: %d existing row group(s) normalize to the same value under Unicode NFC normalization -- "+
				"resolve manually via the application's rename API before upgrading (renaming one row changes only that row's identity, never merges the two): %s",
			table, column, len(collisions), strings.Join(collisions, "; "))
	}

	for _, c := range changes {
		if err := db.Table(table).Where(idColumn+" = ?", c.id).Update(column, c.new).Error; err != nil {
			return fmt.Errorf("failed to normalize %s.%s for id=%d: %w", table, column, c.id, err)
		}
	}
	return nil
}

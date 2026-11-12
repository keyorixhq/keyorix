package canary

import (
	"database/sql"
	"fmt"
	"strings"
)

// ChannelDBPrefix prefixes the channel of every database column DumpSQLite returns.
const ChannelDBPrefix = "db:"

// DumpSQLite returns the contents of every column of every table of a SQLite
// database as one Output per table and column ("db:<table>.<column>"). The table
// list comes from sqlite_master, so a table nobody thought of is still covered.
// It returns an error rather than a partial dump: a column that cannot be read
// must not look like a clean one.
func DumpSQLite(db *sql.DB) ([]Output, error) {
	tables, err := sqliteTables(db)
	if err != nil {
		return nil, err
	}
	var out []Output
	for _, table := range tables {
		cols, err := dumpTable(db, table)
		if err != nil {
			return nil, fmt.Errorf("table %s: %w", table, err)
		}
		out = append(out, cols...)
	}
	return out, nil
}

func sqliteTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("list tables: %w", err)
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

// selectAllFrom returns a SELECT over one table. The identifier comes from
// sqlite_master in a test helper and identifiers cannot be bound, so it is
// quoted as an identifier instead.
func selectAllFrom(table string) string {
	return `SELECT * FROM "` + strings.ReplaceAll(table, `"`, `""`) + `"`
}

func dumpTable(db *sql.DB, table string) ([]Output, error) {
	rows, err := db.Query(selectAllFrom(table))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	data := make([][]byte, len(cols))
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
			case []byte:
				data[i] = append(append(data[i], x...), '\n')
			case string:
				data[i] = append(append(data[i], x...), '\n')
			default:
				data[i] = fmt.Appendf(data[i], "%v\n", x)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Output, 0, len(cols))
	for i, col := range cols {
		if len(data[i]) > 0 {
			out = append(out, Output{Channel: ChannelDBPrefix + table + "." + col, Data: data[i]})
		}
	}
	return out, nil
}

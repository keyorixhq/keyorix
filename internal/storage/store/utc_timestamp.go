package store

import "time"

// dbTimestampLayouts are the text forms a timestamp column can come back in when
// scanned into a string by a raw query: SQLite (modernc) returns RFC 3339 or the
// space-separated form with the stored offset, Postgres the space form with a
// short "+02" offset. A value with no zone is treated as UTC.
var dbTimestampLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z07",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
}

// parseDBTimestamp parses a raw timestamp column value.
func parseDBTimestamp(s string) (time.Time, bool) {
	for _, layout := range dbTimestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// utcRFC3339 renders a raw timestamp column value as UTC RFC 3339 so an API
// payload never mixes "+02:00" and "Z" (#2951). Display only: the stored text is
// untouched. An empty or unparseable value is returned as-is.
func utcRFC3339(s string) string {
	if t, ok := parseDBTimestamp(s); ok {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return s
}

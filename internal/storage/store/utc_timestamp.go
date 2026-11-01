package store

import (
	"strings"
	"time"
)

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
	// A time.Time written by the driver in its own String() form, which is how a pre-upgrade
	// host-zone value looks ("2026-11-01 21:00:00 +0900 JST"); the offset decides the instant.
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

// parseDBTimestamp parses a raw timestamp column value.
//
// A time.Time that still carried a monotonic clock reading (a bare time.Now(), as the pre-UTC
// writers bound it) was stored by modernc as its String() form, which ends in " m=±<seconds>":
// "2026-11-01 13:37:30.058117 +0100 CET m=+0.014210209". The suffix is dropped before parsing,
// as modernc's own reader does; it is process-relative and says nothing about the instant.
func parseDBTimestamp(s string) (time.Time, bool) {
	if before, _, found := strings.Cut(s, " m="); found {
		s = before
	}
	for _, layout := range dbTimestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// utcPtr returns t in UTC, nil for nil. For the nullable time columns written
// through Updates(map) / Update(col, v), which run no BeforeSave hook and no
// NowFunc: on SQLite a non-UTC time is stored as text with the caller's offset
// that does not order against the UTC values everything else writes.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
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

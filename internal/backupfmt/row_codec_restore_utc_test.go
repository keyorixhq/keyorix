package backupfmt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type utcDecodeRow struct {
	ID        uint
	CreatedAt time.Time
	DeletedAt *time.Time
}

// An archived instant with a non-UTC offset must come back located in UTC, so
// the driver stores it in a form every host can read back.
func TestUnmarshalRow_DecodesTimesInUTC(t *testing.T) {
	var got utcDecodeRow
	err := unmarshalRow([]byte(`{"ID":1,"CreatedAt":"2026-10-29T10:55:10.966304+01:00","DeletedAt":"2026-10-29T11:00:00+05:30"}`), &got)
	require.NoError(t, err)

	want := time.Date(2026, 10, 29, 9, 55, 10, 966304000, time.UTC)
	require.True(t, got.CreatedAt.Equal(want), "instant changed: %v", got.CreatedAt)
	require.Equal(t, time.UTC, got.CreatedAt.Location())
	require.NotNil(t, got.DeletedAt)
	require.Equal(t, time.UTC, got.DeletedAt.Location())
	require.True(t, got.DeletedAt.Equal(time.Date(2026, 10, 29, 5, 30, 0, 0, time.UTC)))
}

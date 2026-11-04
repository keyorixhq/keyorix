// recover_admin_alert_first_start_test.go pins what the first RunRecoverAdminAlerting
// pass does after an upgrade, per the three installs docs/UPGRADING.md section 6j
// describes. The doc cites these tests; change them together.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type alertWindow struct{ after, upTo uint }

func TestRunRecoverAdminAlerting_FirstStartAfterUpgrade(t *testing.T) {
	const w = recoverAdminAlertScanWindow
	cases := []struct {
		name        string
		stored      string // "" = no stored mark
		found       bool
		highest     uint
		wantWindows []alertWindow
		wantMarks   []string
	}{
		{
			// (a) fresh install: no mark and an empty audit table. Nothing is read
			// and no mark is written until the first audit row exists.
			name: "fresh install, empty audit table", highest: 0,
		},
		{
			// (a') fresh install a moment later: no mark, a few setup rows. The scan
			// starts at 0 and is one short window.
			name: "fresh install, a few rows", highest: 12,
			wantWindows: []alertWindow{{0, 12}}, wantMarks: []string{"12"},
		},
		{
			// (b) existing install that never used recover-admin: the old job never
			// wrote a mark, so the first pass walks the whole table from id 0, in
			// windows, saving the mark after each.
			name: "never alerted, large table", highest: 2*w + 50,
			wantWindows: []alertWindow{{0, w}, {w, 2 * w}, {2 * w, 2*w + 50}},
			wantMarks:   []string{"100000", "200000", "200050"},
		},
		{
			// (c) existing install that alerted before: the old job left the mark at
			// the id of its last notified event. The first pass resumes there, so it
			// reads only (mark, highest], not the whole table.
			name: "alerted before, resumes from last alerted id", stored: "150000", found: true,
			highest:     2*w + 50,
			wantWindows: []alertWindow{{150000, 2*w + 50}},
			wantMarks:   []string{"200050"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := new(MockStorage)
			var windows []alertWindow
			var marks []string
			st.On("GetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey).Return(tc.stored, tc.found, nil)
			st.On("MaxAuditEventID", mock.Anything).Return(tc.highest, nil)
			st.On("GetAuditLogs", mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					f := args.Get(1).(*storage.AuditFilter)
					windows = append(windows, alertWindow{*f.AfterID, *f.UpToID})
				}).Return([]*models.AuditEvent{}, int64(0), nil).Maybe()
			st.On("SetSystemMetadata", mock.Anything, recoverAdminAlertHighWaterKey, mock.Anything).
				Run(func(args mock.Arguments) { marks = append(marks, args.String(2)) }).Return(nil).Maybe()

			n, err := NewKeyorixCore(st).RunRecoverAdminAlerting(context.Background())
			require.NoError(t, err)
			assert.Zero(t, n)
			assert.Equal(t, tc.wantWindows, windows)
			assert.Equal(t, tc.wantMarks, marks)
		})
	}
}

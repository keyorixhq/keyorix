// impersonation_utc_test.go -- TZ-RESIDUE-1 item 1 (#3914).
//
// StartImpersonation stamped LastSeenAt and ImpersonationStartedAt from c.now() unchanged. Session's
// BeforeSave normalises only ExpiresAt, so on a host east of UTC last_seen_at was stored as host-zone
// text ("... +0900 JST"). TouchSession compares last_seen_at against a UTC cutoff as SQLite text, so
// the host-zone wall clock (18:00) sorted after the cutoff (09:09) and every touch of an
// impersonation session was skipped. Runs in the TZ=Asia/Tokyo subprocess of forEachUTCDialect.

package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestStartImpersonationStoresSeenTimesAsUTCSoTouchSessionAdvances(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, &models.User{}, &models.Session{})
		real := store.NewLocalStorage(db)
		ctx := context.Background()
		seedAliceUser(t, db)
		require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "b@b.com",
			EmailFolded: "b@b.com", IsActive: true, AccountState: "active"}).Error)

		ms := new(MockStorage)
		c := &KeyorixCore{storage: ms, now: hostClock()}
		ms.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin"}, nil)
		ms.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "alice", IsActive: true, AccountState: AccountActive}, nil)
		ms.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{}, nil)
		ms.On("LogAuditEvent", ctx, mock.Anything).Return(nil)
		// CreateSession writes through the real store so the column holds whatever the core handed it.
		created := &models.Session{}
		ms.On("CreateSession", ctx, mock.Anything).Run(func(args mock.Arguments) {
			row, err := real.CreateSession(ctx, args.Get(1).(*models.Session))
			require.NoError(t, err)
			*created = *row
		}).Return(created, nil)

		session, _, err := c.StartImpersonation(ctx, 1, 2, "203.0.113.9")
		require.NoError(t, err)

		d.requireStored(t, db, "sessions", "last_seen_at", utcWritesInstant, "id = ?", session.ID)
		d.requireStored(t, db, "sessions", "impersonation_started_at", utcWritesInstant, "id = ?", session.ID)

		// A touch past the staleness window must move last_seen_at forward.
		later := utcWritesInstant.Add(10 * time.Minute).In(time.Local)
		require.NoError(t, real.TouchSession(ctx, session.ID, later, time.Minute))
		d.requireStored(t, db, "sessions", "last_seen_at", later, "id = ?", session.ID)
	})
}

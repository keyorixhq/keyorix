package core

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// FuzzLoginLockoutModel is an op-sequence fuzzer over the per-account login
// lockout state machine (login_lockout.go): failure counting inside a window,
// the trip into an exponentially backing-off cooldown, lock expiry on read, the
// success clear and the admin unlock, all under a fake clock the program moves
// (including to the exact boundary instants, where >= vs > mistakes live).
//
// The oracle is lockoutModel below, a ~40-line independent restatement of the
// documented rules (not a copy of the production code path: it keeps plain
// values, no storage, no user struct to keep in sync). After EVERY op the real
// stored columns (failed_login_attempts, last_failed_login_at,
// login_locked_until, login_lockout_count) and the real loginLocked verdict must
// equal the model's.
//
// Program encoding (op numbers are corpus encoding: APPEND ONLY, never renumber):
//
//	bytes 0..3: policy  (MaxAttempts 1..5, Window 1..30 min, BaseCooldown
//	            1..10 min, MaxCooldown 1..120 min)
//	then (op, arg) pairs, at most lockoutModelMaxOps of them:
//	  0 fail            recordFailedLogin (wrong credential)
//	  1 advance         clock += table[arg]
//	  2 advance-to-lock-end        clock = locked_until            (exact boundary)
//	  3 advance-to-lock-end-minus  clock = locked_until - 1us
//	  4 advance-to-window-edge     clock = last_failure + Window   (exact boundary)
//	  5 advance-to-window-edge+1us clock = last_failure + Window + 1us
//	  6 succeed         LoginCompletion.Succeeded (clears)
//	  7 admin-unlock    UnlockUser
//	  8 real-login-right  Login with the correct password   (bcrypt, capped)
//	  9 real-login-wrong  Login with a wrong password       (bcrypt, capped)
//	 10 check           no-op (invariants only)
//
// bcrypt is the only expensive step; the stored hash is minimum-cost and the
// number of real Login ops per program is capped at lockoutModelMaxLogins so a
// hostile program cannot make an iteration slow. Everything else is storage
// writes on an in-memory SQLite.
//
// Not covered (say so rather than imply it): concurrent bursts (see
// FuzzLoginThrottleConcurrency and concurrency_login_lockout_test.go), storage
// faults and the in-memory fallback budget (account_lockout_*fallback* tests),
// and MFA / WebAuthn second-factor paths. The model assumes no storage error.
func FuzzLoginLockoutModel(f *testing.F) {
	// seeds: threshold trip, expiry+backoff, window staleness, boundary instants,
	// admin unlock, real logins around a lock.
	f.Add([]byte{2, 14, 4, 59 /* policy */, 0, 0, 0, 0, 0, 0, 8, 0, 1, 5, 8, 0})
	f.Add([]byte{2, 14, 4, 59, 0, 0, 0, 0, 0, 0, 3, 0, 8, 0, 2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0})
	f.Add([]byte{2, 14, 4, 59, 0, 0, 0, 0, 5, 0, 0, 0, 10, 0})
	f.Add([]byte{2, 14, 4, 59, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0})
	f.Add([]byte{2, 14, 4, 59, 0, 0, 0, 0, 6, 0, 0, 0, 7, 0, 9, 0, 8, 0})
	f.Add([]byte{0, 14, 0, 2, 0, 0, 1, 5, 0, 0, 1, 5, 0, 0, 1, 5, 0, 0, 10, 0}) // cooldown doubling overshoots MaxCooldown: clamp
	f.Add([]byte{4, 29, 9, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 8, 0, 0})

	f.Fuzz(func(t *testing.T, prog []byte) {
		if len(prog) < 4 {
			return
		}
		w := lockoutModelWorld(t)
		pol := LoginLockoutPolicy{
			Enabled:      true,
			MaxAttempts:  1 + int(prog[0])%5,
			Window:       time.Duration(1+int(prog[1])%30) * time.Minute,
			BaseCooldown: time.Duration(1+int(prog[2])%10) * time.Minute,
			MaxCooldown:  time.Duration(1+int(prog[3])%120) * time.Minute,
		}
		w.reset(t)

		clock := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
		c := &KeyorixCore{
			storage:        store.NewLocalStorage(w.db),
			now:            func() time.Time { return clock },
			passwordPolicy: DefaultPasswordPolicy(),
		}
		c.SetLoginLockoutPolicy(pol)
		m := &lockoutModel{pol: pol}
		ctx := context.Background()

		load := func() *models.User {
			var u models.User
			if err := w.db.First(&u, lockoutModelUserID).Error; err != nil {
				t.Fatalf("load user: %v", err)
			}
			return &u
		}

		ops := prog[4:]
		logins := 0
		for i := 0; i+1 < len(ops) && i/2 < lockoutModelMaxOps; i += 2 {
			op, arg := ops[i]%11, ops[i+1]
			var what string
			switch op {
			case 0:
				what = "fail"
				m.fail(clock)
				c.recordFailedLogin(ctx, load())
			case 1:
				what = "advance"
				clock = clock.Add(lockoutModelSteps[int(arg)%len(lockoutModelSteps)])
			case 2:
				what = "advance-to-lock-end"
				if m.lockedUntil != nil && m.lockedUntil.After(clock) {
					clock = *m.lockedUntil
				}
			case 3:
				what = "advance-to-lock-end-minus"
				if m.lockedUntil != nil && m.lockedUntil.Add(-time.Microsecond).After(clock) {
					clock = m.lockedUntil.Add(-time.Microsecond)
				}
			case 4:
				what = "advance-to-window-edge"
				if m.lastFail != nil && m.lastFail.Add(pol.Window).After(clock) {
					clock = m.lastFail.Add(pol.Window)
				}
			case 5:
				what = "advance-to-window-edge+1us"
				if m.lastFail != nil && m.lastFail.Add(pol.Window+time.Microsecond).After(clock) {
					clock = m.lastFail.Add(pol.Window + time.Microsecond)
				}
			case 6:
				what = "succeed"
				m.clear()
				c.newLoginCompletion(load()).Succeeded(ctx)
			case 7:
				what = "admin-unlock"
				m.clear()
				if err := c.UnlockUser(ctx, 1, lockoutModelUserID); err != nil {
					t.Fatalf("op %d %s: UnlockUser: %v", i/2, what, err)
				}
			case 8, 9:
				if logins >= lockoutModelMaxLogins {
					continue
				}
				logins++
				right := op == 8
				pw := "wrong-password"
				what = "login-wrong"
				if right {
					pw, what = lockoutModelPassword, "login-right"
				}
				lockedBefore := m.locked(clock)
				_, _, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: pw})
				switch {
				case lockedBefore:
					// The gate refuses before the password is processed: even the
					// correct one is refused, and nothing is counted.
					if err == nil {
						t.Fatalf("op %d %s: LOCKED ACCOUNT LOGGED IN (model: locked until %v, now %v)", i/2, what, m.lockedUntil, clock)
					}
				case right:
					if err != nil {
						t.Fatalf("op %d %s: correct password refused while the model says unlocked: %v", i/2, what, err)
					}
					m.clear()
				default:
					if err == nil || !strings.Contains(err.Error(), "invalid credentials") {
						t.Fatalf("op %d %s: wrong password gave %v, want invalid credentials", i/2, what, err)
					}
					m.fail(clock)
				}
			case 10:
				what = "check"
			}

			// invariants after every op
			u := load()
			if got, want := c.loginLocked(u), m.locked(clock); got != want {
				t.Fatalf("op %d %s: loginLocked=%v, model=%v\n model=%+v\n stored: failed=%d count=%d lastFail=%v lockedUntil=%v now=%v",
					i/2, what, got, want, m, u.FailedLoginAttempts, u.LoginLockoutCount, u.LastFailedLoginAt, u.LoginLockedUntil, clock)
			}
			if u.FailedLoginAttempts != m.failed || u.LoginLockoutCount != m.count ||
				!timePtrEqual(u.LastFailedLoginAt, m.lastFail) || !timePtrEqual(u.LoginLockedUntil, m.lockedUntil) {
				t.Fatalf("op %d %s (policy %+v): stored lockout columns diverge from model\n model: failed=%d count=%d lastFail=%v lockedUntil=%v\n stored: failed=%d count=%d lastFail=%v lockedUntil=%v\n now=%v",
					i/2, what, pol, m.failed, m.count, m.lastFail, m.lockedUntil,
					u.FailedLoginAttempts, u.LoginLockoutCount, u.LastFailedLoginAt, u.LoginLockedUntil, clock)
			}
			// A stored lock may never exceed the policy's ceiling from "now" at trip time.
			if u.LoginLockedUntil != nil && u.LoginLockedUntil.Sub(*u.LastFailedLoginAt) > pol.MaxCooldown && pol.MaxCooldown >= pol.BaseCooldown {
				t.Fatalf("op %d %s: lock lasts %v, above MaxCooldown %v", i/2, what, u.LoginLockedUntil.Sub(*u.LastFailedLoginAt), pol.MaxCooldown)
			}
		}
	})
}

const (
	lockoutModelUserID    = 1
	lockoutModelMaxOps    = 64
	lockoutModelMaxLogins = 3
	lockoutModelPassword  = "Secret#Pass123"
)

var lockoutModelSteps = []time.Duration{
	time.Microsecond, time.Second, 30 * time.Second, time.Minute, 4 * time.Minute, 5 * time.Minute,
	6 * time.Minute, 14 * time.Minute, 15 * time.Minute, 16 * time.Minute, time.Hour, 3 * time.Hour,
}

// lockoutModel restates the rules in login_lockout.go with plain values:
//
//   - a failure while a lock is active changes nothing (no escalation);
//   - otherwise a failure older than Window restarts the count, then counts;
//   - reaching MaxAttempts bumps the lockout count, locks for
//     min(MaxCooldown, BaseCooldown * 2^(count-1)) and zeroes the window counter;
//   - a lock is active while now < locked_until (at the exact end it is over);
//   - a failure is "inside the window" while now - lastFail <= Window;
//   - success and admin unlock zero all four columns.
type lockoutModel struct {
	pol         LoginLockoutPolicy
	failed      int
	count       int
	lastFail    *time.Time
	lockedUntil *time.Time
}

func (m *lockoutModel) clear() { m.failed, m.count, m.lastFail, m.lockedUntil = 0, 0, nil, nil }

func (m *lockoutModel) locked(now time.Time) bool {
	if m.lockedUntil != nil && now.Before(*m.lockedUntil) {
		return true
	}
	// spent: stored failures inside the window reach MaxAttempts (never true after a
	// trip, which zeroes the counter; kept so the model states the production rule).
	return m.lastFail != nil && now.Sub(*m.lastFail) <= m.pol.Window && m.failed >= m.pol.MaxAttempts
}

func (m *lockoutModel) fail(now time.Time) {
	if m.lockedUntil != nil && now.Before(*m.lockedUntil) {
		return
	}
	if m.lastFail != nil && now.Sub(*m.lastFail) > m.pol.Window {
		m.failed = 0
	}
	m.failed++
	t := now
	m.lastFail = &t
	if m.failed >= m.pol.MaxAttempts {
		m.count++
		exp := min(m.count-1, 12)
		cd := min(m.pol.BaseCooldown<<uint(exp), m.pol.MaxCooldown)
		until := now.Add(cd)
		m.lockedUntil = &until
		m.failed = 0
	}
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// lockoutModelWorldT is one SQLite database for the whole fuzz process: opening
// and migrating per iteration would dominate the run. reset() restores the single
// user row and empties the tables Login / UnlockUser write, so iterations are
// independent. The bcrypt hash is made once, at MinCost.
type lockoutModelWorldT struct {
	db *gorm.DB
}

var (
	lockoutModelWorldOnce sync.Once
	lockoutModelWorldV    *lockoutModelWorldT
	lockoutModelWorldErr  error
)

func lockoutModelWorld(t *testing.T) *lockoutModelWorldT {
	t.Helper()
	lockoutModelWorldOnce.Do(func() {
		db, err := gorm.Open(sqlitedialect.Open(":memory:"), &gorm.Config{})
		if err != nil {
			lockoutModelWorldErr = err
			return
		}
		sqlDB, err := db.DB()
		if err != nil {
			lockoutModelWorldErr = err
			return
		}
		sqlDB.SetMaxOpenConns(1) // ":memory:" is per connection
		if err := db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}); err != nil {
			lockoutModelWorldErr = err
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(lockoutModelPassword), bcrypt.MinCost)
		if err != nil {
			lockoutModelWorldErr = err
			return
		}
		lockoutModelWorldErr = db.Create(&models.User{
			ID: lockoutModelUserID, Username: "alice", UsernameFolded: "alice",
			PasswordHash: string(hash), AccountState: AccountActive,
		}).Error
		lockoutModelWorldV = &lockoutModelWorldT{db: db}
	})
	if lockoutModelWorldErr != nil {
		t.Fatalf("lockout model world: %v", lockoutModelWorldErr)
	}
	return lockoutModelWorldV
}

func (w *lockoutModelWorldT) reset(t *testing.T) {
	t.Helper()
	err := w.db.Model(&models.User{}).Where("id = ?", lockoutModelUserID).Updates(map[string]any{
		"failed_login_attempts": 0, "last_failed_login_at": nil, "login_locked_until": nil, "login_lockout_count": 0,
	}).Error
	if err != nil {
		t.Fatalf("reset user: %v", err)
	}
	if err := w.db.Exec("DELETE FROM sessions").Error; err != nil {
		t.Fatalf("reset sessions: %v", err)
	}
	if err := w.db.Exec("DELETE FROM audit_events").Error; err != nil {
		t.Fatalf("reset audit_events: %v", err)
	}
}

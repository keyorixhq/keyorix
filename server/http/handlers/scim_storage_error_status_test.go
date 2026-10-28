package handlers

// #3494 (SCIM-STORAGE-ERR-1): the SCIM user endpoints must tell an IdP the truth
// about a failed write. A 404 means "this user does not exist" and an IdP that gets
// one for a deactivation or a DELETE stops retrying: if the write was actually
// rolled back by a storage failure, the account stays active after the IdP believes
// it is deprovisioned (an offboarding failure). These tests inject storage faults
// under the real core and pin the status per error class:
//
//   - the user positively does not exist, or is not SCIM-managed -> 404
//   - the email is taken by another user                        -> 409 "uniqueness"
//   - SQLite write-gate contention or a concurrent state change  -> 503 + Retry-After
//   - any other storage error (transient, deadlock, rolled back,
//     context canceled)                                          -> 500, generic detail
//
// and, for the 500/503 cases, that the deactivation really did not happen (the
// account is still active), so the retry the status asks for is the right move.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// scimInjectedDetail is in every injected error, so a test can prove it never
// reaches the client.
const scimInjectedDetail = "pq-internal-detail-7f3a"

func setupSCIMFaultTest(t *testing.T) (*SCIMHandler, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// One connection: a :memory: DSN gives every connection its own database.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return NewSCIMHandler(core.NewKeyorixCore(fs)), fs, db
}

// scimLogCapture is captureLogBuf with a lock the reader shares with the writer.
// The standard logger is process-global, so a background goroutine a EARLIER test
// left behind (the last-used coalescer's timer flush logs through log.Printf) can
// write while this test reads; a bare bytes.Buffer made `go test -race` fail with
// a data race in the merge queue. Stray lines from that goroutine are harmless to
// the assertion (it only looks for the injected detail).
type scimLogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *scimLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *scimLogCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureSCIMLog(t *testing.T) *scimLogCapture {
	t.Helper()
	c := &scimLogCapture{}
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(c)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})
	return c
}

// scimStorageFaults are the "any other storage error" class: none of them may
// become a 404 (or any 4xx).
var scimStorageFaults = map[string]error{
	"transient":        fmt.Errorf("dial tcp 10.0.0.5:5432: connection reset by peer (%s)", scimInjectedDetail),
	"deadlock":         fmt.Errorf("ERROR: deadlock detected (SQLSTATE 40P01) %s", scimInjectedDetail),
	"rolled back":      fmt.Errorf("sql: transaction has already been committed or rolled back: %s", scimInjectedDetail),
	"context canceled": fmt.Errorf("%s: %w", scimInjectedDetail, context.Canceled),
}

type scimUserOp struct {
	name       string
	deactivate bool // the operation revokes access (and so runs the PAT revoke)
	do         func(h *SCIMHandler, id string) *httptest.ResponseRecorder
}

func scimDo(h http.HandlerFunc, method, id, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, withID(httptest.NewRequest(method, "/scim/v2/Users/"+id, bytes.NewReader([]byte(body))), id))
	return w
}

var scimUserOps = []scimUserOp{
	{"PUT active=false", true, func(h *SCIMHandler, id string) *httptest.ResponseRecorder {
		return scimDo(h.ReplaceUser, http.MethodPut, id, `{"userName":"u@corp.com","active":false}`)
	}},
	{"PATCH active=false", true, func(h *SCIMHandler, id string) *httptest.ResponseRecorder {
		return scimDo(h.PatchUser, http.MethodPatch, id, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	}},
	{"DELETE", true, func(h *SCIMHandler, id string) *httptest.ResponseRecorder {
		return scimDo(h.DeleteUser, http.MethodDelete, id, "")
	}},
	{"PATCH displayName", false, func(h *SCIMHandler, id string) *httptest.ResponseRecorder {
		return scimDo(h.PatchUser, http.MethodPatch, id, `{"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`)
	}},
}

// scimFaultSites are storage calls each operation makes; a fault at any of them must
// be classified the same way. ops limits a site to the operations that reach it.
var scimFaultSites = []struct {
	method string
	nth    int
	only   func(op scimUserOp) bool
}{
	{"GetUser", 1, nil},           // the pre-check read, before any lock
	{"LockUserForUpdate", 1, nil}, // the locked read inside the transaction
	{"UpdateUserIfActiveStateMatches", 1, nil},
	{"RevokeAllPersonalAccessTokensForUser", 1, func(op scimUserOp) bool { return op.deactivate }},
	{"DeleteSessionsForUserExcept", 1, func(op scimUserOp) bool { return op.name == "DELETE" }},
	{"DeleteUser", 1, func(op scimUserOp) bool { return op.name == "DELETE" }},
	{"WithTransaction", 1, nil},
}

func assertSCIMErrorBody(t *testing.T, w *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	require.Equal(t, status, w.Code, w.Body.String())
	assert.Equal(t, scimContentType, w.Header().Get("Content-Type"))
	body := decodeSCIM(t, w)
	assert.Equal(t, []any{scimErrorSchema}, body["schemas"])
	assert.Equal(t, strconv.Itoa(status), body["status"])
	assert.NotContains(t, w.Body.String(), scimInjectedDetail, "internal error detail must not reach the IdP")
	return body
}

func scimUserActive(t *testing.T, db *gorm.DB, id string) bool {
	t.Helper()
	var u models.User
	require.NoError(t, db.Unscoped().First(&u, id).Error)
	return u.IsActive && !u.DeletedAt.Valid
}

// TestSCIM_UserWriteStorageError_Is500NotNotFound is the #3494 regression: every
// storage failure on PUT/PATCH/DELETE answers 500 with the generic detail, the
// injected text stays in the server log, and a failed deactivation left the account
// active (so "retry" is the correct thing for the IdP to do).
func TestSCIM_UserWriteStorageError_Is500NotNotFound(t *testing.T) {
	for _, op := range scimUserOps {
		for _, site := range scimFaultSites {
			if site.only != nil && !site.only(op) {
				continue
			}
			for kind, ferr := range scimStorageFaults {
				t.Run(op.name+"/"+site.method+"/"+kind, func(t *testing.T) {
					h, fs, db := setupSCIMFaultTest(t)
					id := provisionUser(t, h, "u@corp.com")
					logBuf := captureSCIMLog(t)

					fs.Arm(&faultstorage.FaultSpec{Method: site.method, NthCall: site.nth, Kind: faultstorage.KindError, Err: ferr})
					w := op.do(h, id)
					require.True(t, fs.Fired(), "the armed %s fault must have fired", site.method)
					fs.Arm(nil)

					body := assertSCIMErrorBody(t, w, http.StatusInternalServerError)
					assert.Equal(t, clientSafe(ferr), body["detail"])
					assert.Nil(t, body["scimType"])
					assert.Contains(t, logBuf.String(), scimInjectedDetail, "the real error must be logged for the operator")
					if op.deactivate {
						assert.True(t, scimUserActive(t, db, id), "a failed deactivation must leave the account active (rolled back)")
					}
				})
			}
		}
	}
}

// TestSCIM_UserWriteContention_Is503RetryAfter: the SQLite write gate's contention
// sentinel is an explicitly transient failure; the IdP gets a SCIM 503 with
// Retry-After (not the API's non-SCIM WriteContention body).
func TestSCIM_UserWriteContention_Is503RetryAfter(t *testing.T) {
	contention := fmt.Errorf("begin write transaction (%s): %w", scimInjectedDetail, corestorage.ErrSQLiteWriteContention)
	for _, op := range scimUserOps {
		t.Run(op.name, func(t *testing.T) {
			h, fs, db := setupSCIMFaultTest(t)
			id := provisionUser(t, h, "u@corp.com")

			fs.Arm(&faultstorage.FaultSpec{Method: "WithTransaction", NthCall: 1, Kind: faultstorage.KindError, Err: contention})
			w := op.do(h, id)
			require.True(t, fs.Fired())
			fs.Arm(nil)

			assertSCIMErrorBody(t, w, http.StatusServiceUnavailable)
			assert.Equal(t, strconv.Itoa(middleware.WriteContentionRetryAfterSeconds), w.Header().Get("Retry-After"))
			if op.deactivate {
				assert.True(t, scimUserActive(t, db, id))
			}
		})
	}
}

// TestSCIM_UserWriteStateConflict_Is503RetryAfter: a concurrent state change lost
// the conditional write (core.ErrUserActiveStateConflict / ErrUserAccountStateConflict),
// nothing was written, and the same request is safe to retry.
func TestSCIM_UserWriteStateConflict_Is503RetryAfter(t *testing.T) {
	for _, sentinel := range []error{core.ErrUserActiveStateConflict, core.ErrUserAccountStateConflict} {
		for _, op := range scimUserOps {
			t.Run(sentinel.Error()+"/"+op.name, func(t *testing.T) {
				h, fs, db := setupSCIMFaultTest(t)
				id := provisionUser(t, h, "u@corp.com")

				fs.Arm(&faultstorage.FaultSpec{Method: "UpdateUserIfActiveStateMatches", NthCall: 1, Kind: faultstorage.KindError,
					Err: fmt.Errorf("user %s: %w", id, sentinel)})
				w := op.do(h, id)
				require.True(t, fs.Fired())
				fs.Arm(nil)

				assertSCIMErrorBody(t, w, http.StatusServiceUnavailable)
				assert.NotEmpty(t, w.Header().Get("Retry-After"))
				if op.deactivate {
					assert.True(t, scimUserActive(t, db, id))
				}
			})
		}
	}
}

// TestSCIM_UserWriteNotFound_Is404: a 404 is reserved for "positively absent" — an
// id with no row, or a native (non-SCIM-managed) account (#120/#G85: same answer).
// Also when the not-found surfaces from the locked read inside the transaction.
func TestSCIM_UserWriteNotFound_Is404(t *testing.T) {
	for _, op := range scimUserOps {
		t.Run(op.name+"/no such id", func(t *testing.T) {
			h, _, _ := setupSCIMFaultTest(t)
			body := assertSCIMErrorBody(t, op.do(h, "999999"), http.StatusNotFound)
			assert.Nil(t, body["scimType"])
		})
		t.Run(op.name+"/native account", func(t *testing.T) {
			h, _, db := setupSCIMFaultTest(t)
			native := &models.User{Username: "native", Email: "native@corp.com", IsActive: true, AccountState: "active"}
			require.NoError(t, db.Create(native).Error)
			id := strconv.FormatUint(uint64(native.ID), 10)
			assertSCIMErrorBody(t, op.do(h, id), http.StatusNotFound)
			assert.True(t, scimUserActive(t, db, id))
		})
		t.Run(op.name+"/gone inside the transaction", func(t *testing.T) {
			h, fs, _ := setupSCIMFaultTest(t)
			id := provisionUser(t, h, "u@corp.com")
			fs.Arm(&faultstorage.FaultSpec{Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError,
				Err: fmt.Errorf("user not found: %w", corestorage.ErrUserNotFound)})
			w := op.do(h, id)
			require.True(t, fs.Fired())
			assertSCIMErrorBody(t, w, http.StatusNotFound)
		})
	}
}

// TestSCIM_UserWriteEmailConflict_Is409Uniqueness: an email taken by another user
// is RFC 7644 409 scimType "uniqueness", both from the up-front check and from the
// DB unique index catching a concurrent writer (storage.ErrDuplicateEmail).
func TestSCIM_UserWriteEmailConflict_Is409Uniqueness(t *testing.T) {
	t.Run("pre-check", func(t *testing.T) {
		h, _, _ := setupSCIMFaultTest(t)
		id := provisionUser(t, h, "a@corp.com")
		provisionUser(t, h, "b@corp.com")
		w := scimDo(h.ReplaceUser, http.MethodPut, id, `{"userName":"b@corp.com"}`)
		body := assertSCIMErrorBody(t, w, http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
	t.Run("unique index race", func(t *testing.T) {
		h, fs, _ := setupSCIMFaultTest(t)
		id := provisionUser(t, h, "a@corp.com")
		fs.Arm(&faultstorage.FaultSpec{Method: "UpdateUserIfActiveStateMatches", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("%s: %w", scimInjectedDetail, corestorage.ErrDuplicateEmail)})
		w := scimDo(h.ReplaceUser, http.MethodPut, id, `{"userName":"fresh@corp.com"}`)
		require.True(t, fs.Fired())
		body := assertSCIMErrorBody(t, w, http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
	t.Run("email check read fails", func(t *testing.T) {
		h, fs, _ := setupSCIMFaultTest(t)
		id := provisionUser(t, h, "a@corp.com")
		fs.Arm(&faultstorage.FaultSpec{Method: "GetUserByEmail", NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
		w := scimDo(h.ReplaceUser, http.MethodPut, id, `{"userName":"fresh@corp.com"}`)
		require.True(t, fs.Fired())
		assertSCIMErrorBody(t, w, http.StatusInternalServerError)
	})
}

// TestSCIM_GetUserStorageError_Is500: GET is what an IdP reconciles with; a storage
// failure must not read as "this user is gone" either.
func TestSCIM_GetUserStorageError_Is500(t *testing.T) {
	h, fs, _ := setupSCIMFaultTest(t)
	id := provisionUser(t, h, "u@corp.com")
	fs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
	w := scimDo(h.GetUser, http.MethodGet, id, "")
	require.True(t, fs.Fired())
	fs.Arm(nil)
	assertSCIMErrorBody(t, w, http.StatusInternalServerError)

	assertSCIMErrorBody(t, scimDo(h.GetUser, http.MethodGet, "999999", ""), http.StatusNotFound)
}

// TestSCIM_CreateUserStorageError_Is500: a storage failure on create is not the
// IdP's fault (it used to be a 400, which IdPs do not retry); a duplicate is 409
// "uniqueness".
func TestSCIM_CreateUserStorageError_Is500(t *testing.T) {
	create := func(h *SCIMHandler, userName string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users",
			bytes.NewReader([]byte(`{"userName":"`+userName+`","externalId":"idp-`+userName+`"}`))))
		return w
	}
	for _, method := range []string{"GetUserByExternalID", "GetUserByEmail", "CreateUser", "AssignRole", "WithTransaction"} {
		t.Run(method, func(t *testing.T) {
			h, fs, _ := setupSCIMFaultTest(t)
			fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: scimStorageFaults["transient"]})
			w := create(h, "new@corp.com")
			require.True(t, fs.Fired())
			assertSCIMErrorBody(t, w, http.StatusInternalServerError)
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		h, _, _ := setupSCIMFaultTest(t)
		require.Equal(t, http.StatusCreated, create(h, "dup@corp.com").Code)
		body := assertSCIMErrorBody(t, create(h, "dup@corp.com"), http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
	t.Run("duplicate via unique index", func(t *testing.T) {
		h, fs, _ := setupSCIMFaultTest(t)
		fs.Arm(&faultstorage.FaultSpec{Method: "CreateUser", NthCall: 1, Kind: faultstorage.KindError,
			Err: fmt.Errorf("%s: %w", scimInjectedDetail, corestorage.ErrDuplicateEmail)})
		body := assertSCIMErrorBody(t, create(h, "race@corp.com"), http.StatusConflict)
		assert.Equal(t, "uniqueness", body["scimType"])
	})
}

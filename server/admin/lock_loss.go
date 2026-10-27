package admin

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"

	"github.com/keyorixhq/keyorix/internal/serverguard"
)

// lostDatabaseLockMsg is printed when an admin command's exclusive database lock
// is found lost while the command runs.
const lostDatabaseLockMsg = "ERROR: this admin command's exclusive database lock was lost (its database connection died, " +
	"or its SQLite lock file <database>.server.lock was deleted or replaced), " +
	"so a server or another admin command may have started beside it. Stopping now, as after a crash. " +
	"Check that no server or admin command is running against this database (stop any that started), " +
	"then re-run this command; see docs/postgresql-poolers.md, \"When a lock is lost\".\n"

// exitOnLostDatabaseLock ends the process when the lock is lost. A variable so
// tests can observe it instead of exiting.
var exitOnLostDatabaseLock = func() { os.Exit(1) }

// lostLockCleanups run, in registration order, before the process exits on a
// lost lock: os.Exit skips every deferred cleanup, so a command that writes an
// output file in place registers its removal here (onLostDatabaseLock).
// lostLockMu also orders that exit against a command's own last step
// (lostLockCleanup.commit): one of the two runs first, never both interleaved.
var (
	lostLockMu       sync.Mutex
	lostLockCleanups = map[int]func(){}
	lostLockNextID   int
)

// lostLockCleanup is one registered cleanup (onLostDatabaseLock).
type lostLockCleanup struct{ id int }

// onLostDatabaseLock registers fn to run if the exclusive lock is found lost
// before the returned cleanup is committed or dropped.
func onLostDatabaseLock(fn func()) *lostLockCleanup {
	lostLockMu.Lock()
	defer lostLockMu.Unlock()
	c := &lostLockCleanup{id: lostLockNextID}
	lostLockNextID++
	lostLockCleanups[c.id] = fn
	return c
}

// commit runs fn while no lost-lock exit can start, then drops the cleanup, so
// a command's last check-then-commit (backup: is the lock still held? close the
// archive) is never interleaved with the exit removing what it committed. If
// the exit already started, it never returns: the process is ending.
func (c *lostLockCleanup) commit(fn func()) {
	lostLockMu.Lock()
	defer lostLockMu.Unlock()
	fn()
	delete(lostLockCleanups, c.id)
}

// drop unregisters the cleanup. Safe to call more than once.
func (c *lostLockCleanup) drop() { c.commit(func() {}) }

// stopOnLostDatabaseLock stops the admin command, with exit status 1, when its
// exclusive lock is found lost (serverguard.Exclusive.Lost): from that moment
// the lock no longer keeps servers and other admin commands off the database,
// and with storage.encryption.key_dir_lock: database it is the only thing that
// keeps them off the key files (docs/multi-replica-keys.md). Stopping part-way
// is what a crash does, which every state-changing admin command already has to
// survive (DEK rotation's crash recovery, transactions rolled back with the
// connection); running on beside a server is not. Output written in place is
// removed first, by the cleanups registered with onLostDatabaseLock.
//
// PostgreSQL: the lock's connection died. SQLite: the <database>.server.lock
// sidecar was deleted or replaced (the watch keeps the new file locked, so no
// server starts before this exit). Nothing happens for a nil lock (--force past
// a held lock, remote storage, an in-memory SQLite database). Lost is never
// closed after Release, so a command that finished is never stopped; its
// goroutine stays parked until the process exits, which for a one-shot admin
// command is at once.
func stopOnLostDatabaseLock(lock *serverguard.Exclusive) {
	lost := lock.Lost()
	if lost == nil {
		return
	}
	go func() {
		<-lost
		lostLockMu.Lock()
		defer lostLockMu.Unlock()
		for _, id := range slices.Sorted(maps.Keys(lostLockCleanups)) {
			lostLockCleanups[id]()
			delete(lostLockCleanups, id)
		}
		fmt.Fprint(os.Stderr, lostDatabaseLockMsg)
		exitOnLostDatabaseLock()
	}()
}

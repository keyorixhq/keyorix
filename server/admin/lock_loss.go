package admin

import (
	"fmt"
	"os"

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

// stopOnLostDatabaseLock stops the admin command, with exit status 1, when its
// exclusive lock is found lost (serverguard.Exclusive.Lost): from that moment
// the lock no longer keeps servers and other admin commands off the database,
// and with storage.encryption.key_dir_lock: database it is the only thing that
// keeps them off the key files (docs/multi-replica-keys.md). Stopping part-way
// is what a crash does, which every state-changing admin command already has to
// survive (DEK rotation's crash recovery, transactions rolled back with the
// connection); running on beside a server is not.
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
		fmt.Fprint(os.Stderr, lostDatabaseLockMsg)
		exitOnLostDatabaseLock()
	}()
}

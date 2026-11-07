package storage

import (
	"errors"
	"log"

	msqlite "modernc.org/sqlite"
)

// sqliteFdatasync is the seam over modernc.org/sqlite's process-wide switch, so
// tests can simulate a platform (macOS, Windows) where it is unavailable.
var sqliteFdatasync = msqlite.Fdatasync

// applySQLiteFdatasync honours database.fdatasync for the SQLite backend. It
// runs only on the local-SQLite path (createLocalStorage), never for
// PostgreSQL. Default off: when the option is unset it does nothing at all, so
// it never flips a setting some other caller in the process made. It never
// fails startup: where the driver cannot sync with fdatasync it logs one
// warning and the process keeps fsync.
func applySQLiteFdatasync(enabled bool) {
	if !enabled {
		return
	}
	if _, err := sqliteFdatasync(true); err != nil {
		if errors.Is(err, msqlite.ErrFdatasyncUnavailable) {
			log.Printf("storage: database.fdatasync is set but this platform cannot sync with fdatasync; SQLite keeps fsync")
			return
		}
		log.Printf("storage: database.fdatasync could not be enabled (%v); SQLite keeps its current sync call", err)
		return
	}
}

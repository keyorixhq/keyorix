package backupfmt

// LoadProgress is one progress notification from LoadArchiveWithProgress. It
// carries table names and counts only -- never row content, keys or secrets.
type LoadProgress struct {
	Table       string // table being loaded
	TableRows   int64  // rows of Table read so far
	TableTotal  int64  // rows the manifest declares for Table
	TablesDone  int    // tables fully loaded before this one
	TablesTotal int    // tables the archive declares
	Start       bool   // first notification for Table (a table boundary)
	Finished    bool   // Table is fully loaded (a table boundary)
}

// LoadProgressFunc receives LoadProgress notifications on the loading
// goroutine, once at the start of every table, after every inserted batch and
// once when the table is done. It must be cheap and must not retain state
// that outlives the load.
type LoadProgressFunc func(LoadProgress)

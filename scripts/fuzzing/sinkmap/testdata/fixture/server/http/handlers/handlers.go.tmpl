// Package handlers is the fixture's API entry package. Its import path tail
// (server/http/handlers) matches an entryPrefix, so exported funcs here are
// treated as entry roots by the analyser.
package handlers

import (
	"os"

	"sinkfixture/internal/sinks"
)

// Handle is an exported entry point. It contains one sink directly (os.Open,
// so the sink is "is-entry" API-reachable) and calls into the sinks package,
// making RunExec and BuildQuery API-reachable via qualified call edges.
func Handle(name string, table string) {
	_, _ = os.Open(name) // fs-path sink in an entry func
	sinks.RunExec(name)   // -> exec sink becomes API-reachable
	sinks.BuildQuery(table)
}

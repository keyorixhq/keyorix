// Package sinks holds exactly one sink of each kind the analyser recognises.
// It is never compiled (it lives under testdata/ and has its own go.mod); the
// analyser only parses it.
package sinks

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

// RunExec is an exec sink (shell-ish: sh -c). API-reachable via Handle.
func RunExec(arg string) {
	_ = exec.Command("sh", "-c", arg)
}

// BuildQuery is a SQL sink: a query string built with fmt.Sprintf then passed
// to Query. API-reachable via Handle.
func BuildQuery(table string) {
	var db *sql.DB
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM %s", table))
}

// Dial is a net-out sink with a variable URL. NOT API-reachable (no entry
// func calls it).
func Dial(url string) {
	_, _ = http.NewRequest("GET", url, nil)
}

// Compile is a template/regexp sink with a variable pattern. Fuzz-covered by
// FuzzCompile.
func Compile(pat string) {
	_ = regexp.MustCompile(pat)
}

// Parse is a deserialization sink (json.Unmarshal).
func Parse(b []byte) {
	var v any
	_ = json.Unmarshal(b, &v)
}

// Compare is a crypto-compare sink: == on a credential-named operand.
func Compare(token, want string) bool {
	return token == want
}

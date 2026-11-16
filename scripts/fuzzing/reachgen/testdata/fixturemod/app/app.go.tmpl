// Package app is reachgen's unit-test fixture: a tiny "Keyorix-like" package
// that calls into stand-in third-party deps with several argument provenances.
package app

import (
	"fmt"

	"example.com/lib"
	pgx "github.com/jackc/pgx/v5"
)

// AppConfig is a config-typed struct; values of it are "config" provenance.
type AppConfig struct {
	Name string
}

// HandleRequest simulates a handler: s is attacker-controlled (request-body).
func HandleRequest(s string) {
	_ = lib.ParseRequest(s) // request-body
	body := []byte(s)
	_ = lib.ParseBytes(body) // request-body, propagated through assignment
	fmt.Println(s)           // stdlib — must NOT be recorded
	ownHelper(s)             // own code — must NOT be recorded
}

// UsesConfig passes a config-typed field.
func UsesConfig(cfg AppConfig) {
	lib.FromConfig(cfg.Name) // config
}

// UsesBackend passes a backend response.
func UsesBackend() {
	row := pgx.QueryRow() // backend-response source
	_ = lib.ParseRequest(row)
}

// StaticCall passes only a literal — must be filtered out of untrusted set.
func StaticCall() {
	lib.StaticOnly("literal") // static
}

// UsesDecoder exercises method-call resolution with a []byte param (request).
func UsesDecoder(b []byte) {
	d := lib.NewDecoder()
	_ = d.Decode(b) // request-body, method
}

func ownHelper(s string) {}

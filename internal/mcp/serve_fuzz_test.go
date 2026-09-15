package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// fuzzSecretReader is a no-op SecretReader: Serve's JSON-RPC parse/dispatch is the
// target, not the secret backend, so both methods just fail closed. No DB, no
// network — the harness stays a pure protocol-parser fuzz.
type fuzzSecretReader struct{}

func (fuzzSecretReader) GetSecret(_ context.Context, _ string) (string, error) {
	return "", errors.New("fuzz: no secrets")
}
func (fuzzSecretReader) ListSecrets(_ context.Context, _ string) ([]SecretInfo, bool, error) {
	return nil, false, errors.New("fuzz: no secrets")
}

// FuzzMCPServe fuzzes Server.Serve, the stdio JSON-RPC loop an MCP client drives.
// The client is a local AI agent, and everything on the wire is attacker-
// influenceable (a manipulated agent, or whatever produced the bytes upstream),
// so the decode → dispatch path must never panic on malformed, truncated,
// oversized, or adversarially-nested input. Serve reads until EOF, so a
// bytes.Reader over the fuzz input drives exactly one session to completion; the
// only acceptable outcomes are a clean return (nil on EOF) or a parse/dispatch
// error — never a panic or hang (Guard bounds the wall clock).
func FuzzMCPServe(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n",
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n",
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"app/prod/db"}}}` + "\n",
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{"environment":"prod"}}}` + "\n",
		// two messages back-to-back (streaming), a notification then a request
		`{"jsonrpc":"2.0","method":"x"}` + "\n" + `{"jsonrpc":"2.0","id":5,"method":"tools/list"}` + "\n",
		`not json at all`,
		``,
		`{"jsonrpc":"2.0","id":`, // truncated
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope","arguments":42}}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		s := NewServer(fuzzSecretReader{}, "fuzz")
		fuzzutil.Guard(t.Fatalf, "mcp.Server.Serve", func() {
			_ = s.Serve(context.Background(), bytes.NewReader(data), io.Discard)
		})
	})
}

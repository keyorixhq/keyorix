/*
Keyorix MCP server — exposes read-only Keyorix secret access to an AI agent over the
Model Context Protocol (stdio JSON-RPC 2.0). It is a thin, audited proxy in front of the
Keyorix API: every read carries a least-privilege machine-identity token and is subject
to Keyorix's scoped permission, max_reads, suspension, and audit. Secret values are
never logged.

Configure it in your agent client (e.g. Claude Desktop/Code) as a stdio MCP server with
KEYORIX_URL and a scoped KEYORIX_TOKEN in the environment.

Copyright (C) 2025 Keyorix Contributors. Licensed under the AGPL-3.0-or-later.
*/
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/mcp"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	// Logs go to stderr so they never corrupt the JSON-RPC stream on stdout.
	log.SetOutput(os.Stderr)
	log.SetPrefix("keyorix-mcp: ")

	baseURL := strings.TrimSpace(os.Getenv("KEYORIX_URL"))
	if baseURL == "" {
		log.Fatal("KEYORIX_URL is required (the Keyorix server base URL)")
	}
	token := strings.TrimSpace(os.Getenv("KEYORIX_TOKEN"))
	if token == "" {
		log.Fatal("KEYORIX_TOKEN is required (a least-privilege Keyorix machine-identity token)")
	}

	server := mcp.NewServer(mcp.NewKeyorixClient(baseURL, token), version)
	log.Printf("ready (server %s) — read-only Keyorix tools over stdio", version)
	if err := server.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// toolDefinitions is the static tool catalogue advertised via tools/list. Read-only by
// design (ADR-061): no write/rotate/delete tools.
func toolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name": "keyorix_get_secret",
			"description": "Read a secret's current value from Keyorix by a " +
				"\"project/environment/name\" reference (e.g. \"app/production/db-password\"). " +
				"The value is returned as text. Access is least-privilege and every read is audited.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"ref": map[string]interface{}{
						"type":        "string",
						"description": "The secret reference: project/environment/name.",
					},
				},
				"required": []string{"ref"},
			},
		},
		{
			"name": "keyorix_list_secrets",
			"description": "List the secret references the configured token can see " +
				"(metadata only — no values), optionally filtered to one environment. Use the " +
				"returned refs with keyorix_get_secret.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment": map[string]interface{}{
						"type":        "string",
						"description": "Optional environment name to filter by (e.g. \"production\").",
					},
				},
			},
		},
	}
}

// callTool dispatches a tools/call request. A bad request shape is a JSON-RPC error; a
// tool execution failure is returned in-band as an isError result (per MCP), so the
// agent can read the reason without the call itself failing.
func (s *Server) callTool(ctx context.Context, params json.RawMessage) (map[string]interface{}, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) == 0 || json.Unmarshal(params, &p) != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid tools/call params"}
	}

	switch p.Name {
	case "keyorix_get_secret":
		return s.toolGetSecret(ctx, p.Arguments), nil
	case "keyorix_list_secrets":
		return s.toolListSecrets(ctx, p.Arguments), nil
	default:
		return nil, &rpcError{Code: codeMethodNotFound, Message: "unknown tool: " + p.Name}
	}
}

func (s *Server) toolGetSecret(ctx context.Context, args json.RawMessage) map[string]interface{} {
	var a struct {
		Ref string `json:"ref"`
	}
	_ = json.Unmarshal(args, &a)
	if strings.TrimSpace(a.Ref) == "" {
		return errorResult("ref is required (project/environment/name)")
	}
	value, err := s.reader.GetSecret(ctx, a.Ref)
	if err != nil {
		return errorResult(fmt.Sprintf("could not read %q: %v", a.Ref, err))
	}
	return textResult(value)
}

func (s *Server) toolListSecrets(ctx context.Context, args json.RawMessage) map[string]interface{} {
	var a struct {
		Environment string `json:"environment"`
	}
	_ = json.Unmarshal(args, &a)
	infos, err := s.reader.ListSecrets(ctx, a.Environment)
	if err != nil {
		return errorResult(fmt.Sprintf("could not list secrets: %v", err))
	}
	if len(infos) == 0 {
		return textResult("(no secrets visible to this token)")
	}
	var b strings.Builder
	for _, info := range infos {
		b.WriteString(info.Ref)
		if info.Type != "" {
			b.WriteString("  (" + info.Type + ")")
		}
		b.WriteByte('\n')
	}
	return textResult(strings.TrimRight(b.String(), "\n"))
}

// textResult / errorResult build the MCP tool-result envelope (content blocks). A tool
// failure is signalled in-band with isError, not as a JSON-RPC error.
func textResult(text string) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
	}
}

func errorResult(msg string) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": msg}},
		"isError": true,
	}
}

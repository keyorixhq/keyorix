package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

// protocolVersion is the MCP revision the server speaks if a client does not request a
// specific one. When the client sends a protocolVersion in initialize, the server echoes
// it back (maximising interop) since the surface used here is stable across revisions.
const defaultProtocolVersion = "2024-11-05"

// jsonrpcVersion is the only JSON-RPC version MCP uses.
const jsonrpcVersion = "2.0"

// SecretReader is the slice of Keyorix the MCP tools need — a seam so the server is
// unit-tested without HTTP. Satisfied by *KeyorixClient.
type SecretReader interface {
	GetSecret(ctx context.Context, ref string) (string, error)
	ListSecrets(ctx context.Context, environment string) ([]SecretInfo, error)
}

// Server speaks MCP over a JSON-RPC 2.0 stream (stdio). It exposes read-only Keyorix
// tools and holds no state between messages.
type Server struct {
	reader  SecretReader
	version string
}

// NewServer builds a server over the given reader; version is reported in serverInfo.
func NewServer(reader SecretReader, version string) *Server {
	if version == "" {
		version = "dev"
	}
	return &Server{reader: reader, version: version}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent ⇒ notification (no reply)
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSON-RPC standard error codes used here.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Serve reads JSON-RPC messages from r and writes responses to w until EOF. It returns
// nil on a clean EOF. Diagnostics must go to stderr (never to w); values are never
// written anywhere but a tool result requested by the client.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	dec := json.NewDecoder(r)
	enc := json.NewEncoder(w)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// The stream is no longer parseable; report once and stop (id unknown).
			_ = enc.Encode(rpcResponse{JSONRPC: jsonrpcVersion, ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParseError, Message: "parse error"}})
			return err
		}
		// A notification (no id) gets no reply — e.g. notifications/initialized.
		if len(req.ID) == 0 {
			continue
		}
		if err := enc.Encode(s.handle(ctx, &req)); err != nil {
			return err
		}
	}
}

func (s *Server) handle(ctx context.Context, req *rpcRequest) rpcResponse {
	resp := rpcResponse{JSONRPC: jsonrpcVersion, ID: req.ID}
	if req.JSONRPC != jsonrpcVersion {
		resp.Error = &rpcError{Code: codeInvalidRequest, Message: "jsonrpc must be \"2.0\""}
		return resp
	}
	switch req.Method {
	case "initialize":
		resp.Result = s.initialize(req.Params)
	case "ping":
		resp.Result = map[string]interface{}{}
	case "tools/list":
		resp.Result = map[string]interface{}{"tools": toolDefinitions()}
	case "tools/call":
		result, err := s.callTool(ctx, req.Params)
		if err != nil {
			resp.Error = err
			return resp
		}
		resp.Result = result
	default:
		resp.Error = &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}
	return resp
}

// initialize negotiates the protocol version (echoing the client's when present) and
// advertises the tools capability.
func (s *Server) initialize(params json.RawMessage) map[string]interface{} {
	version := defaultProtocolVersion
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			version = p.ProtocolVersion
		}
	}
	return map[string]interface{}{
		"protocolVersion": version,
		"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
		"serverInfo":      map[string]interface{}{"name": "keyorix-mcp", "version": s.version},
	}
}

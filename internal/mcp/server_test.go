package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReader struct {
	value   string
	getErr  error
	list    []SecretInfo
	listErr error

	gotRef string
	gotEnv string
}

func (f *fakeReader) GetSecret(_ context.Context, ref string) (string, error) {
	f.gotRef = ref
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.value, nil
}

func (f *fakeReader) ListSecrets(_ context.Context, env string) ([]SecretInfo, error) {
	f.gotEnv = env
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

// run feeds the given JSON-RPC messages through Serve and returns the decoded responses.
func run(t *testing.T, s *Server, msgs ...string) []rpcResponse {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, s.Serve(context.Background(), strings.NewReader(strings.Join(msgs, "\n")), &out))
	dec := json.NewDecoder(&out)
	var resps []rpcResponse
	for {
		var r rpcResponse
		if err := dec.Decode(&r); err != nil {
			break
		}
		resps = append(resps, r)
	}
	return resps
}

// resultMap re-decodes a response's Result into a map for assertions.
func resultMap(t *testing.T, r rpcResponse) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(r.Result)
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestServe_Initialize(t *testing.T) {
	s := NewServer(&fakeReader{}, "1.2.3")
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.Equal(t, "2025-06-18", res["protocolVersion"], "server echoes the client's protocol version")
	info := res["serverInfo"].(map[string]interface{})
	assert.Equal(t, "keyorix-mcp", info["name"])
	assert.Equal(t, "1.2.3", info["version"])
	assert.Contains(t, res["capabilities"].(map[string]interface{}), "tools")
}

func TestServe_NotificationGetsNoReply(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	resps := run(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // no id ⇒ no reply
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	)
	require.Len(t, resps, 2, "the notification produces no response")
}

func TestServe_ToolsList(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Len(t, resps, 1)
	tools := resultMap(t, resps[0])["tools"].([]interface{})
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]interface{})["name"].(string)] = true
	}
	assert.True(t, names["keyorix_get_secret"])
	assert.True(t, names["keyorix_list_secrets"])
}

func TestServe_GetSecretSuccess(t *testing.T) {
	fr := &fakeReader{value: "p4ss"}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"app/prod/db"}}}`)
	require.Len(t, resps, 1)
	assert.Equal(t, "app/prod/db", fr.gotRef)
	res := resultMap(t, resps[0])
	assert.NotEqual(t, true, res["isError"])
	content := res["content"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "p4ss", content["text"])
}

func TestServe_GetSecretErrorIsInBand(t *testing.T) {
	fr := &fakeReader{getErr: errors.New("not authorized (HTTP 403)")}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{"ref":"app/prod/db"}}}`)
	require.Len(t, resps, 1)
	assert.Nil(t, resps[0].Error, "a tool failure is in-band, not a JSON-RPC error")
	res := resultMap(t, resps[0])
	assert.Equal(t, true, res["isError"])
	text := res["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	assert.Contains(t, text, "not authorized")
}

func TestServe_GetSecretRequiresRef(t *testing.T) {
	resps := run(t, NewServer(&fakeReader{}, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_get_secret","arguments":{}}}`)
	res := resultMap(t, resps[0])
	assert.Equal(t, true, res["isError"])
	assert.Contains(t, res["content"].([]interface{})[0].(map[string]interface{})["text"], "ref is required")
}

func TestServe_ListSecrets(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{{Ref: "app/prod/db", Type: "password"}, {Ref: "app/prod/api"}}}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{"environment":"prod"}}}`)
	assert.Equal(t, "prod", fr.gotEnv)
	text := resultMap(t, resps[0])["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	assert.Contains(t, text, "app/prod/db")
	assert.Contains(t, text, "(password)")
	assert.Contains(t, text, "app/prod/api")
}

func TestServe_UnknownMethodAndTool(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	resps := run(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"does/not/exist"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keyorix_delete","arguments":{}}}`)
	require.Len(t, resps, 2)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeMethodNotFound, resps[0].Error.Code)
	require.NotNil(t, resps[1].Error)
	assert.Contains(t, resps[1].Error.Message, "unknown tool")
}

func TestServe_RejectsBadJSONRPCVersion(t *testing.T) {
	resps := run(t, NewServer(&fakeReader{}, ""), `{"jsonrpc":"1.0","id":1,"method":"ping"}`)
	require.Len(t, resps, 1)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeInvalidRequest, resps[0].Error.Code)
}

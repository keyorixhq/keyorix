package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Serve: parse error path -------------------------------------------------

// TestServe_ParseError exercises the branch where the incoming stream contains
// unparseable JSON. Serve should write a parse-error response and then return
// the underlying decode error (not nil).
func TestServe_ParseError(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	var out bytes.Buffer
	err := s.Serve(context.Background(), strings.NewReader("{bad json"), &out)
	// Serve must return the decode error, not nil.
	require.Error(t, err)
	// The response written before returning must be a parse-error response.
	dec := json.NewDecoder(&out)
	var resp rpcResponse
	require.NoError(t, dec.Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, codeParseError, resp.Error.Code)
}

// TestServe_EncodeError exercises the branch where writing the response to the
// writer fails. Serve should surface the encoder error.
func TestServe_EncodeError(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	pr, pw := io.Pipe()
	// Close the write-end of the reader immediately so the goroutine's pipe
	// writer (to our errWriter) fails.
	pr.Close()

	// Use an io.Pipe to get a reader+writer pair:
	// feed a valid request to Serve but have the writer reject writes.
	r := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	err := s.Serve(context.Background(), r, pw)
	_ = pw.Close()
	// Serve must return an error when it cannot write the response.
	require.Error(t, err)
}

// -- callTool: empty params --------------------------------------------------

// TestCallTool_EmptyParams covers the len(params)==0 branch in callTool.
func TestCallTool_EmptyParams(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	// tools/call with no params field at all → callTool receives nil/empty JSON.
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	require.Len(t, resps, 1)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeInvalidParams, resps[0].Error.Code)
}

// TestCallTool_InvalidParamsJSON covers the json.Unmarshal failure branch in callTool.
func TestCallTool_InvalidParamsJSON(t *testing.T) {
	s := NewServer(&fakeReader{}, "")
	resps := run(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`)
	require.Len(t, resps, 1)
	require.NotNil(t, resps[0].Error)
	assert.Equal(t, codeInvalidParams, resps[0].Error.Code)
}

// -- toolListSecrets: shown==0 branch ----------------------------------------

// TestToolListSecrets_NoVisible covers the "no secrets visible to this token"
// branch when the reader returns an empty list.
func TestToolListSecrets_NoVisible(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{}}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, "no secrets visible")
}

// TestToolListSecrets_AllFilteredByAllowList covers the shown==0 branch when
// allowedRefs filters out every entry returned by the reader.
func TestToolListSecrets_AllFilteredByAllowList(t *testing.T) {
	fr := &fakeReader{list: []SecretInfo{{Ref: "app/prod/db"}, {Ref: "app/prod/api"}}}
	s := NewServer(fr, "")
	s.SetAllowedRefs([]string{"other/env/*"}) // nothing matches
	resps := run(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	assert.Contains(t, text, "no secrets visible")
}

// TestToolListSecrets_Error covers the error return from the reader.
func TestToolListSecrets_Error(t *testing.T) {
	fr := &fakeReader{listErr: errTest}
	resps := run(t, NewServer(fr, ""),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"keyorix_list_secrets","arguments":{}}}`)
	require.Len(t, resps, 1)
	res := resultMap(t, resps[0])
	assert.Equal(t, true, res["isError"])
	assert.Equal(t, genericListError, res["content"].([]any)[0].(map[string]any)["text"])
}

// errTest is a sentinel error used across these tests.
var errTest = errSentinel("test error")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// -- requireHTTPSURL: uncovered branches -------------------------------------

// TestRequireHTTPSURL_InvalidURL covers the url.Parse error / empty host branch.
func TestRequireHTTPSURL_InvalidURL(t *testing.T) {
	// An empty string produces a URL with no host.
	err := requireHTTPSURL("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid KEYORIX_URL")

	// A relative path also has no host.
	err2 := requireHTTPSURL("/no-host/path")
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), "invalid KEYORIX_URL")
}

// TestRequireHTTPSURL_UnknownScheme covers the default case (not http or https).
func TestRequireHTTPSURL_UnknownScheme(t *testing.T) {
	err := requireHTTPSURL("ftp://keyorix.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

// -- getJSON: empty data branch ----------------------------------------------

// TestGetJSON_EmptyData covers the "empty data in response" branch where the
// server returns a 200 with a non-null envelope but nil/absent "data" field.
func TestGetJSON_EmptyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"other_field":"value"}`))
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

// TestGetJSON_MalformedJSON covers the json decode failure in getJSON.
func TestGetJSON_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode response")
}

// TestGetJSON_RequestBuildError exercises the request-build failure path by
// using a context that is already cancelled — the client.Do call should fail.
func TestGetJSON_RequestFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"v"}}`))
	}))
	srv.Close() // close immediately so the request fails

	c := mustClient(t, srv.URL, "tok")
	_, err := c.GetSecret(context.Background(), "app/prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// -- ListSecrets: getJSON error ----------------------------------------------

// TestListSecrets_HTTPError covers the error-return path in ListSecrets when
// the server returns a non-2xx status.
func TestListSecrets_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, "tok")
	_, err := c.ListSecrets(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

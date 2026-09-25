package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateSecret_201HasJSONContentType is the regression test for the bug this
// commit fixes: CreateSecret called w.WriteHeader(http.StatusCreated) BEFORE
// h.sendSuccess set Content-Type -- Go silently drops header mutations made
// after WriteHeader, so the real response shipped with an auto-sniffed
// Content-Type (not "application/json"). oapi-codegen's generated client
// (cli/internal/apiclient's ParseCreateSecretResponse) gates its typed 201
// decode on `strings.Contains(Content-Type, "json")`, so every real
// `keyorix secret create` treated a genuinely successful creation as a
// failure (JSON201 stayed nil) -- found live via scripts/smoke.sh against the
// shipped binary, not by any existing unit test, because json.Decoder
// (unlike the generated client) never checks Content-Type before decoding a
// body that happens to be valid JSON regardless of its declared type.
//
// Asserts what the generated client's parser actually checks: status 201,
// Content-Type containing "json", and a body that decodes into the same
// {"data": {...}} envelope shape JSON201's struct expects -- not just that
// SOME JSON came back.
func TestCreateSecret_201HasJSONContentType(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := `{"name":"content-type-regression","value":"test-value","project_id":1,"environment_id":1,"type":"password"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/secrets", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "json",
		"a 201 response's Content-Type must contain \"json\" -- the generated CLI client "+
			"gates its typed decode on exactly this header, so a wrong Content-Type here "+
			"makes a real, successful creation look like a failure to every REST client "+
			"that checks it (not just json.Decoder-based tests, which don't)")

	var dest struct {
		Data *struct {
			ID   float64 `json:"ID"`
			Name string  `json:"Name"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&dest))
	require.NotNil(t, dest.Data, "the response must decode into a non-nil data envelope")
	assert.Equal(t, "content-type-regression", dest.Data.Name)
}

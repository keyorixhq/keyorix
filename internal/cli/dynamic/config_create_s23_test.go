package dynamic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// createConfigCmd — command metadata
// ---------------------------------------------------------------------------

// TestCreateConfigCmd_S23_UseField verifies that the create subcommand's Use
// field is exactly "create", which controls the help output and cobra routing.
func TestCreateConfigCmd_S23_UseField(t *testing.T) {
	assert.Equal(t, "create", createConfigCmd.Use)
}

// TestCreateConfigCmd_S23_ShortNonEmpty verifies that the Short description of
// the create subcommand is non-empty, so it appears in the parent command's
// help listing.
func TestCreateConfigCmd_S23_ShortNonEmpty(t *testing.T) {
	assert.NotEmpty(t, createConfigCmd.Short)
}

// TestCreateConfigCmd_S23_ShortMentionsConfig verifies that the Short
// description mentions config or target so the command's purpose is clear.
func TestCreateConfigCmd_S23_ShortMentionsConfig(t *testing.T) {
	lc := strings.ToLower(createConfigCmd.Short)
	assert.True(t,
		strings.Contains(lc, "config") || strings.Contains(lc, "target") || strings.Contains(lc, "register"),
		"short description should mention config, target, or register, got: %s", createConfigCmd.Short,
	)
}

// ---------------------------------------------------------------------------
// adminDSNEnv constant
// ---------------------------------------------------------------------------

// TestAdminDSNEnv_S23_ConstantValue verifies the exact value of the adminDSNEnv
// constant so that documentation, CI scripts, and the CLI Long description all
// stay consistent with the actual environment variable name the code reads.
func TestAdminDSNEnv_S23_ConstantValue(t *testing.T) {
	assert.Equal(t, "KEYORIX_DYNAMIC_ADMIN_DSN", adminDSNEnv)
}

// ---------------------------------------------------------------------------
// createConfigCmd — required-flags validation
// ---------------------------------------------------------------------------

// TestCreateConfig_S23_AllFlagsMissing verifies that the error is returned when
// all three required flags (--name, --project-id, --backend) are absent.
func TestCreateConfig_S23_AllFlagsMissing(t *testing.T) {
	cfgName, cfgProjectID, cfgBackend = "", 0, ""
	err := createConfigCmd.RunE(createConfigCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestCreateConfig_S23_ErrorMentionsAllThreeFlags verifies that the validation
// error message names all three required flags so the operator knows exactly
// what is missing without re-reading the help text.
func TestCreateConfig_S23_ErrorMentionsAllThreeFlags(t *testing.T) {
	cfgName, cfgProjectID, cfgBackend = "", 0, ""
	err := createConfigCmd.RunE(createConfigCmd, nil)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "--name")
	assert.Contains(t, msg, "--project-id")
	assert.Contains(t, msg, "--backend")
}

// ---------------------------------------------------------------------------
// createConfigCmd — POST body field mapping
// ---------------------------------------------------------------------------

// TestCreateConfig_S23_NameInBody verifies that the --name flag value is sent
// as the "name" key in the POST body.
func TestCreateConfig_S23_NameInBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":1,"name":"pg-prod","backend_type":"postgres"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, "postgres://admin:pw@host/db")
	cfgName, cfgProjectID, cfgBackend = "pg-prod", 4, "postgres"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Equal(t, "pg-prod", gotBody["name"])
}

// TestCreateConfig_S23_ProjectIDInBody verifies that the --project-id flag
// value is sent as the "project_id" key in the POST body.
func TestCreateConfig_S23_ProjectIDInBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":2,"name":"mydb","backend_type":"mysql"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, "mysql://root:pw@db/app")
	cfgName, cfgProjectID, cfgBackend = "mydb", 99, "mysql"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Equal(t, float64(99), gotBody["project_id"])
}

// TestCreateConfig_S23_BackendTypeInBody verifies that the --backend flag
// value is sent as the "backend_type" key in the POST body.
func TestCreateConfig_S23_BackendTypeInBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":3,"name":"kv","backend_type":"redis"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, "redis://admin:pw@cache:6379/0")
	cfgName, cfgProjectID, cfgBackend = "kv", 1, "redis"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Equal(t, "redis", gotBody["backend_type"])
}

// TestCreateConfig_S23_AdminDSNInBody verifies that the admin DSN read from
// the environment variable is forwarded as the "admin_dsn" key in the POST
// body, and is never omitted.
func TestCreateConfig_S23_AdminDSNInBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":4,"name":"mongo-svc","backend_type":"mongodb"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, "mongodb://admin:secret@mongo:27017/admin")
	cfgName, cfgProjectID, cfgBackend = "mongo-svc", 1, "mongodb"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Equal(t, "mongodb://admin:secret@mongo:27017/admin", gotBody["admin_dsn"])
}

// ---------------------------------------------------------------------------
// createConfigCmd — success output detail
// ---------------------------------------------------------------------------

// TestCreateConfig_S23_IssueHintContainsDynamicSecretIssue verifies that the
// follow-up hint printed after a successful create tells the user the exact
// subcommand to run, including "dynamic-secret issue", so they can copy-paste it.
func TestCreateConfig_S23_IssueHintContainsDynamicSecretIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":55,"name":"k8s-token","backend_type":"kubernetes"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, `{"namespace":"app","service_account":"my-app"}`)
	cfgName, cfgProjectID, cfgBackend = "k8s-token", 1, "kubernetes"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Contains(t, out, "dynamic-secret issue")
	assert.Contains(t, out, "55")
}

// TestCreateConfig_S23_OutputContainsCreatedWord verifies that the first output
// line printed on success contains the word "Created" so the operator can
// immediately confirm the operation succeeded.
func TestCreateConfig_S23_OutputContainsCreatedWord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":10,"name":"aws-ro","backend_type":"aws-sts"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, `{"role_arn":"arn:aws:iam::123:role/ro","region":"us-east-1"}`)
	cfgName, cfgProjectID, cfgBackend = "aws-ro", 2, "aws-sts"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Contains(t, out, "Created")
}

// ---------------------------------------------------------------------------
// readAdminDSN — error wrapping mentions the env var name
// ---------------------------------------------------------------------------

// TestReadAdminDSN_S23_ErrorMentionsEnvVar verifies that when KEYORIX_DYNAMIC_ADMIN_DSN
// is unset and ReadPassword fails (stdin is not a terminal in tests), the returned
// error message contains the adminDSNEnv constant so the operator knows which
// variable to set for non-interactive use.
func TestReadAdminDSN_S23_ErrorMentionsEnvVar(t *testing.T) {
	t.Setenv(adminDSNEnv, "") // unset so the tty path is taken
	_, err := readAdminDSN()
	// In a non-tty test environment ReadPassword always fails. The error must
	// mention the env var name or "non-interactive" guidance.
	require.Error(t, err)
	msg := err.Error()
	assert.True(t,
		strings.Contains(msg, adminDSNEnv) || strings.Contains(msg, "non-interactive"),
		"error should mention %s or non-interactive use, got: %s", adminDSNEnv, msg,
	)
}

// ---------------------------------------------------------------------------
// createConfigCmd — POST hits the expected API path
// ---------------------------------------------------------------------------

// TestCreateConfig_S23_PostPath verifies that the createConfigCmd sends the
// POST request to /api/v1/dynamic-secrets/configs and uses the POST method.
func TestCreateConfig_S23_PostPath(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"id":20,"name":"gcp-svc","backend_type":"gcp"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, `{"service_account":"sa@project.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}`)
	cfgName, cfgProjectID, cfgBackend = "gcp-svc", 3, "gcp"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/configs", gotPath)
}

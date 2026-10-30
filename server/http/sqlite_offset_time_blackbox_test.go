// sqlite_offset_time_blackbox_test.go — SQLITE-TIME-TAILS-1.
//
// Question: can production persist a NON-UTC time on SQLite? SQLITE-FIDELITY-1
// showed the production driver (modernc via internal/storage/sqlitedialect)
// writes a time carrying a non-UTC fixed zone in a form it scans back as a
// string, which breaks sql.NullTime scans (the raw machine-credential lookup
// scans expires_at / created_at that way) and also breaks SQLite's TEXT
// comparison against the UTC "now" bound parameters.
//
// This is a black box: the real storage factory (real migrations, the
// production dialect, a real SQLite file), the real core and the real router.
// One request per entry point that accepts a client time carrying an offset;
// for the duration-based entry points (machine credential, invitation,
// break-glass), the same request under a non-UTC HOST zone. Then authenticate
// with / read back the created object, and read the stored bytes through a
// second raw connection to the same file.
//
// What it does NOT cover: the GORM auto-timestamps (created_at / updated_at
// filled by NowFunc in the host zone). Those are not client times; see the
// report ("Needs coordinator").
package http

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver for the raw read-back
)

// otConnector is the smallest connector that lets a ref grant be created.
type otConnector struct{}

func (otConnector) Name() string { return "otconn" }
func (otConnector) Type() string { return "fake" }
func (otConnector) GetSecret(context.Context, string) (string, error) {
	return "v", nil
}

// otEnv is one real server on a real SQLite file plus a raw read-only handle on
// the same file.
type otEnv struct {
	t       *testing.T
	c       *core.KeyorixCore
	srv     *httptest.Server
	raw     *sql.DB
	admin   string // admin session token
	adminID uint
	project uint
	env     uint
	rows    []string
}

func newOTEnv(t *testing.T) *otEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	path := sqlitetest.FactoryPath(t, "kxtimetails_")
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: path}}}
	real, err := appstorage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	c := core.NewKeyorixCore(real)
	ctx := context.Background()
	c.SetBootstrapToken("ot-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "otadmin", Email: "otadmin@example.com", Password: "TestPassword123!", Token: "ot-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "otadmin@example.com")
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "otadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	// A nil deliverer is out-of-band; the base URL is what makes an invitation mint its setup link.
	c.SetCredentialDelivery(nil, "https://keyorix.example.test")
	c.SetConnectManager(connect.NewManager([]connect.Connector{otConnector{}}))
	c.SetConnectOwnership(map[string]core.ConnectOwnership{"otconn": {Scope: "project", ProjectID: projects[0].ID}})

	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	raw, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_busy_timeout=5000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	return &otEnv{t: t, c: c, srv: srv, raw: raw, admin: sess.SessionToken, adminID: admin.ID, project: projects[0].ID, env: envs[0].ID}
}

// do issues a request and returns status and body, then drains detached audit
// writers (same reason as miepAuthedRequest).
func (e *otEnv) do(method, path, token string, body any) (int, []byte) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(e.t, err)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, rdr)
	require.NoError(e.t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	return resp.StatusCode, out
}

// stored returns "<sqlite typeof>:<raw text>" for the (typeof, value) pair a
// query selects, the query error, or "NULL".
func (e *otEnv) stored(query string, args ...any) string {
	e.t.Helper()
	var typ, val sql.NullString
	if err := e.raw.QueryRow(query, args...).Scan(&typ, &val); err != nil {
		return "ERR " + err.Error()
	}
	if !val.Valid {
		return "NULL"
	}
	return typ.String + ":" + val.String
}

// nonUTCText matches a stored time that carries a numeric offset or a zone name
// instead of the "Z" (or no zone) of a UTC value.
var nonUTCText = regexp.MustCompile(`[+-]\d{2}:?\d{2}(\s|$)|\sm=[+-]`)

// row records one line of the report table and fails the test if the stored
// text is not UTC.
func (e *otEnv) row(entry, offset, stored, roundTrip string) {
	e.t.Helper()
	e.rows = append(e.rows, fmt.Sprintf("| %-40s | %-30s | %-46s | %s |", entry, offset, stored, roundTrip))
	// A read that found nothing (or failed) must not pass as "not non-UTC": the row has to hold a time.
	require.True(e.t, strings.HasPrefix(stored, "text:"), "%s: no stored time was read back: %s", entry, stored)
	require.False(e.t, nonUTCText.MatchString(stored), "%s: a non-UTC time reached the column: %s", entry, stored)
}

func (e *otEnv) dump() {
	for _, r := range e.rows {
		e.t.Log(r)
	}
}

// setHostZone makes time.Now() carry the given zone for the rest of the test,
// like a server whose host TZ is not UTC.
func setHostZone(t *testing.T, loc *time.Location) {
	t.Helper()
	old := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = old })
}

func loadZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("zone database has no %s: %v", name, err)
	}
	return loc
}

// TestSQLiteOffsetTimes_BlackBox_ClientOffsets: entry points that accept an
// RFC3339 time with an offset from the client.
func TestSQLiteOffsetTimes_BlackBox_ClientOffsets(t *testing.T) {
	e := newOTEnv(t)
	defer e.dump()
	m12 := time.FixedZone("", -12*3600)
	p14 := time.FixedZone("", 14*3600)
	ctx := context.Background()

	// A future instant written with a wall clock that is BEHIND utc now: any
	// comparison of the stored text against a UTC "now" calls it expired.
	t.Run("PAT_future_minus12", func(t *testing.T) {
		e.t = t
		exp := time.Now().Add(time.Hour).In(m12).Format(time.RFC3339)
		status, body := e.do("POST", "/api/v1/auth/tokens", e.admin, map[string]any{"name": "pat-m12", "expires_at": exp})
		require.Equal(t, http.StatusCreated, status, string(body))
		var env struct {
			Data struct {
				Token string `json:"token"`
				PAT   struct {
					ID        uint   `json:"id"`
					ExpiresAt string `json:"expires_at"`
				} `json:"pat"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &env))
		got, perr := time.Parse(time.RFC3339, env.Data.PAT.ExpiresAt)
		require.NoError(t, perr)
		want, _ := time.Parse(time.RFC3339, exp)
		require.True(t, got.Equal(want), "response instant %s != requested %s", got, want)
		pstatus, pbody := e.do("GET", "/api/v1/projects", env.Data.Token, nil)
		e.row("PAT REST expires_at", exp, e.stored("SELECT typeof(expires_at), expires_at FROM personal_access_tokens WHERE id = ?", env.Data.PAT.ID),
			fmt.Sprintf("auth=%d, instant kept", pstatus))
		require.Equal(t, http.StatusOK, pstatus, string(pbody))
	})

	// The mirror image: a short expiry written ahead of UTC (+14:00) must still
	// expire at the right instant, not 14 hours late.
	t.Run("PAT_expires_at_the_right_instant_plus14", func(t *testing.T) {
		e.t = t
		exp := time.Now().Add(2 * time.Second).In(p14).Format(time.RFC3339)
		status, body := e.do("POST", "/api/v1/auth/tokens", e.admin, map[string]any{"name": "pat-p14", "expires_at": exp})
		require.Equal(t, http.StatusCreated, status, string(body))
		var env struct {
			Data struct {
				Token string `json:"token"`
				PAT   struct {
					ID uint `json:"id"`
				} `json:"pat"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &env))
		first, _ := e.do("GET", "/api/v1/projects", env.Data.Token, nil)
		time.Sleep(3 * time.Second)
		second, _ := e.do("GET", "/api/v1/projects", env.Data.Token, nil)
		e.row("PAT REST expires_at (expiry instant)", exp, e.stored("SELECT typeof(expires_at), expires_at FROM personal_access_tokens WHERE id = ?", env.Data.PAT.ID),
			fmt.Sprintf("auth before=%d after expiry=%d", first, second))
		require.Equal(t, http.StatusOK, first)
		require.Equal(t, http.StatusUnauthorized, second, "a PAT created with a +14:00 offset must expire at the stated instant")
	})

	var secretID uint
	t.Run("Secret_create_expiration_minus12", func(t *testing.T) {
		e.t = t
		exp := time.Now().Add(time.Hour).In(m12).Format(time.RFC3339)
		status, body := e.do("POST", "/api/v1/secrets", e.admin, map[string]any{
			"name": "ot-secret", "value": "v1", "project_id": e.project, "environment_id": e.env, "type": "generic", "expiration": exp,
		})
		require.Equal(t, http.StatusCreated, status, string(body))
		secretID = dataID(t, body, "id")
		gs, gb := e.do("GET", fmt.Sprintf("/api/v1/secrets/%d", secretID), e.admin, nil)
		e.row("Secret REST create expiration", exp, e.stored("SELECT typeof(expiration), expiration FROM secret_nodes WHERE id = ?", secretID),
			fmt.Sprintf("read-back=%d", gs))
		require.Equal(t, http.StatusOK, gs, string(gb))
	})

	t.Run("Secret_update_expiration_plus14", func(t *testing.T) {
		e.t = t
		require.NotZero(t, secretID)
		exp := time.Now().Add(2 * time.Hour).In(p14).Format(time.RFC3339)
		status, body := e.do("PUT", fmt.Sprintf("/api/v1/secrets/%d", secretID), e.admin, map[string]any{"expiration": exp})
		require.Equal(t, http.StatusOK, status, string(body))
		gs, gb := e.do("GET", fmt.Sprintf("/api/v1/secrets/%d", secretID), e.admin, nil)
		e.row("Secret REST update expiration", exp, e.stored("SELECT typeof(expiration), expiration FROM secret_nodes WHERE id = ?", secretID),
			fmt.Sprintf("read-back=%d", gs))
		require.Equal(t, http.StatusOK, gs, string(gb))
	})

	t.Run("Share_create_and_update_expiry", func(t *testing.T) {
		e.t = t
		require.NotZero(t, secretID)
		// The sharer must be a project member (a global admin grant does not count).
		require.NoError(t, e.c.AddProjectMember(ctx, e.adminID, e.project, e.adminID, "project_admin", false))
		rcpt, err := e.c.CreateUser(ctx, &core.CreateUserRequest{Username: "otrecipient", Email: "otrecipient@example.com", DisplayName: "OT", Password: "TestPassword123!"})
		require.NoError(t, err)
		require.NoError(t, e.c.AddProjectMember(ctx, e.adminID, e.project, rcpt.ID, "project_viewer", false))

		exp := time.Now().Add(time.Hour).In(m12).Format(time.RFC3339)
		status, body := e.do("POST", fmt.Sprintf("/api/v1/secrets/%d/share", secretID), e.admin,
			map[string]any{"recipient_id": rcpt.ID, "is_group": false, "permission": "read", "expires_at": exp})
		require.Equal(t, http.StatusCreated, status, string(body))
		shareID := dataID(t, body, "id")
		ls, lb := e.do("GET", fmt.Sprintf("/api/v1/secrets/%d/shares", secretID), e.admin, nil)
		e.row("Share REST create expires_at", exp, e.stored("SELECT typeof(expires_at), expires_at FROM share_records WHERE id = ?", shareID),
			fmt.Sprintf("owner share list=%d live=%v", ls, bytes.Contains(lb, []byte(fmt.Sprintf("\"recipient_id\":%d", rcpt.ID)))))
		require.Equal(t, http.StatusOK, ls, string(lb))
		require.Contains(t, string(lb), fmt.Sprintf("\"recipient_id\":%d", rcpt.ID), "a share expiring in an hour must be live")

		exp2 := time.Now().Add(2 * time.Hour).In(p14).Format(time.RFC3339)
		us, ub := e.do("PUT", fmt.Sprintf("/api/v1/shares/%d", shareID), e.admin, map[string]any{"permission": "read", "expires_at": exp2})
		require.Equal(t, http.StatusOK, us, string(ub))
		ls2, lb2 := e.do("GET", fmt.Sprintf("/api/v1/secrets/%d/shares", secretID), e.admin, nil)
		e.row("Share REST update expires_at", exp2, e.stored("SELECT typeof(expires_at), expires_at FROM share_records WHERE id = ?", shareID),
			fmt.Sprintf("owner share list=%d live=%v", ls2, bytes.Contains(lb2, []byte(fmt.Sprintf("\"recipient_id\":%d", rcpt.ID)))))
		require.Contains(t, string(lb2), fmt.Sprintf("\"recipient_id\":%d", rcpt.ID))
	})

	// Risk exception (governed control-gap acceptance): expires_at is an RFC3339
	// string from the client.
	t.Run("RiskException_expires_at_minus12", func(t *testing.T) {
		e.t = t
		exp := time.Now().Add(time.Hour).In(m12).Format(time.RFC3339)
		status, body := e.do("POST", "/api/v1/risk-exceptions", e.admin, map[string]any{
			"title": "ot", "category": "other", "reference": "ot-ref", "justification": "probe", "expires_at": exp,
		})
		ls, lb := e.do("GET", "/api/v1/risk-exceptions", e.admin, nil)
		e.row("RiskException REST expires_at", exp, e.stored("SELECT typeof(expires_at), expires_at FROM risk_exceptions ORDER BY id DESC LIMIT 1"),
			fmt.Sprintf("create=%d list=%d", status, ls))
		require.Equal(t, http.StatusCreated, status, string(body))
		require.Equal(t, http.StatusOK, ls, string(lb))
	})

	// Connect per-reference grant: expires_at is a JSON time from the client.
	t.Run("ConnectRefGrant_expires_at_plus14", func(t *testing.T) {
		e.t = t
		roles, err := e.c.Storage().ListRoles(ctx)
		require.NoError(t, err)
		var roleID uint
		for _, r := range roles {
			if r.Name == "project_developer" {
				roleID = r.ID
			}
		}
		require.NotZero(t, roleID)
		exp := time.Now().Add(2 * time.Hour).In(p14).Format(time.RFC3339)
		status, body := e.do("POST", "/api/v1/connect/ref-grants", e.admin, map[string]any{
			"role_id": roleID, "connector": "otconn", "ref_prefix": "p/", "expires_at": exp,
		})
		ls, lb := e.do("GET", "/api/v1/connect/ref-grants", e.admin, nil)
		e.row("ConnectRefGrant REST expires_at", exp, e.stored("SELECT typeof(expires_at), expires_at FROM connect_ref_grants ORDER BY id DESC LIMIT 1"),
			fmt.Sprintf("create=%d list=%d", status, ls))
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, string(body))
		require.Equal(t, http.StatusOK, ls, string(lb))
	})
}

// TestSQLiteOffsetTimes_BlackBox_NonUTCHost: entry points whose expiry is a
// duration added to the server clock. The offset comes from the HOST zone.
func TestSQLiteOffsetTimes_BlackBox_NonUTCHost(t *testing.T) {
	zones := map[string]func(*testing.T) *time.Location{
		"iana_Pacific_Kiritimati_plus14":  func(t *testing.T) *time.Location { return loadZone(t, "Pacific/Kiritimati") },
		"iana_America_St_Johns_minus0330": func(t *testing.T) *time.Location { return loadZone(t, "America/St_Johns") },
	}
	for name, mk := range zones {
		t.Run(name, func(t *testing.T) {
			e := newOTEnv(t)
			defer e.dump()
			setHostZone(t, mk(t))
			ctx := context.Background()

			t.Run("machine_credential", func(t *testing.T) {
				e.t = t
				mi, err := e.c.CreateMachineIdentity(ctx, e.project, "ot-runner", "ci", "", "", e.adminID, 0)
				require.NoError(t, err)
				status, body := e.do("POST", fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/tokens", e.project, mi.ID), e.admin,
					map[string]any{"name": "ot-cred", "expires_in_days": 1})
				e.row("machine credential expires_at", "expires_in_days=1", e.stored("SELECT typeof(expires_at), expires_at FROM machine_identity_credentials WHERE machine_identity_id = ?", mi.ID),
					fmt.Sprintf("issue=%d", status))
				require.Equal(t, http.StatusCreated, status, string(body))
			})

			t.Run("invitation", func(t *testing.T) {
				e.t = t
				status, body := e.do("POST", fmt.Sprintf("/api/v1/projects/%d/invitations", e.project), e.admin,
					map[string]any{"email": "ot-invitee@example.com", "role": "project_viewer"})
				ls, lb := e.do("GET", fmt.Sprintf("/api/v1/projects/%d/invitations", e.project), e.admin, nil)
				e.row("invitation expires_at", "(server TTL)", e.stored("SELECT typeof(expires_at), expires_at FROM project_invitations WHERE email = ?", "ot-invitee@example.com"),
					fmt.Sprintf("create=%d list=%d", status, ls))
				require.Equal(t, http.StatusCreated, status, string(body))
				require.Equal(t, http.StatusOK, ls, string(lb))
			})

			// The invitation's setup link is a second row with its own expiry.
			t.Run("invitation_setup_token", func(t *testing.T) {
				e.t = t
				e.row("invitation setup_token expires_at", "(server TTL)", e.stored("SELECT typeof(expires_at), expires_at FROM setup_tokens ORDER BY id DESC LIMIT 1"), "minted with the invitation")
			})

			t.Run("break_glass", func(t *testing.T) {
				e.t = t
				e.c.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour})
				u, err := e.c.CreateUser(ctx, &core.CreateUserRequest{Username: "otbg", Email: "otbg@example.com", DisplayName: "OT", Password: "TestPassword123!"})
				require.NoError(t, err)
				require.NoError(t, e.c.AddProjectMember(ctx, e.adminID, e.project, u.ID, "project_viewer", false))
				us, _, err := e.c.Login(ctx, &core.LoginRequest{Username: "otbg", Password: "TestPassword123!"})
				require.NoError(t, err)
				status, body := e.do("POST", fmt.Sprintf("/api/v1/projects/%d/break-glass", e.project), us.SessionToken,
					map[string]any{"justification": "SQLITE-TIME-TAILS-1 probe: production outage", "ttl": "1h"})
				ls, lb := e.do("GET", fmt.Sprintf("/api/v1/projects/%d/break-glass", e.project), e.admin, nil)
				e.row("break-glass expires_at", "ttl=1h", e.stored("SELECT typeof(expires_at), expires_at FROM break_glass_activations ORDER BY id DESC LIMIT 1"),
					fmt.Sprintf("activate=%d list=%d", status, ls))
				require.Equal(t, http.StatusCreated, status, string(body))
				require.Equal(t, http.StatusOK, ls, string(lb))
			})
		})
	}
}

// dataID extracts data.<key> (a JSON number) from an envelope response.
func dataID(t *testing.T, body []byte, key string) uint {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env), string(body))
	v, ok := env.Data[key].(float64)
	require.True(t, ok, "data.%s missing in %s", key, string(body))
	return uint(v)
}

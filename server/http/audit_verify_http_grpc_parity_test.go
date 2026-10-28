package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
)

// auditVerifyHTTPOnly lists the keys GET /api/v1/audit/verify returns that
// VerifyAuditChainResponse deliberately does not carry. Every other key the HTTP
// endpoint returns must exist on the gRPC message, so a field added to the report
// for HTTP cannot silently stay off gRPC (CORE-GRPC-TAILS-1 item 3: state_reason
// was missing, so gRPC clients saw status "sealed" with no reason).
//
// The set is the structured/diagnostic detail the gRPC response has never carried;
// the CLI and operators read it over HTTP.
var auditVerifyHTTPOnly = map[string]string{
	"coverage":                          "tail-check detail object",
	"rolling_cycle":                     "rolling-cycle detail object",
	"last_full_verification_started_at": "full-verification detail",
	"last_full_verification_through_id": "full-verification detail",
	"last_full_verification_source":     "full-verification detail",
	"last_checked_at":                   "posture detail",
	"anchor_token":                      "external-anchor detail (checkpoint endpoints)",
	"anchored_at":                       "external-anchor detail (checkpoint endpoints)",
	"anchor_provider":                   "external-anchor detail (checkpoint endpoints)",
	"anchor_trust_root_configured":      "external-anchor detail (checkpoint endpoints)",
}

// TestAuditVerify_HTTPvsGRPC_SameReport drives GET /api/v1/audit/verify and the
// VerifyAuditChain RPC over ONE core and requires the two to say the same thing:
// every field the gRPC message has holds the value HTTP returned (absent in JSON =
// the zero value on the message), and no HTTP key is missing from the message
// unless auditVerifyHTTPOnly names it.
//
// What it does not do: put the deployment in the sealed state. That needs the
// signed-checkpoint fixtures that live in package core's tests; the sealed
// rendering is covered by services.TestVerifyAuditChainResponse_CarriesStateReason
// and the shared field-set check below is what makes a missing state_reason fail
// here regardless of the status.
func TestAuditVerify_HTTPvsGRPC_SameReport(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	var admin models.User
	require.NoError(t, db.Where("username = ?", "admin").First(&admin).Error)
	session, _, err := c.Login(ctx, &core.LoginRequest{Username: "admin", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)

	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/audit/verify", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	require.NotEmpty(t, envelope.Data, "HTTP returned no report")

	gctx := context.WithValue(ctx, interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: admin.ID, Username: "admin"})
	got, err := services.NewAuditService(c).VerifyAuditChain(gctx, &emptypb.Empty{})
	require.NoError(t, err)

	fields := got.ProtoReflect().Descriptor().Fields()
	known := map[string]bool{}
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := string(fd.Name())
		known[name] = true
		httpVal, present := envelope.Data[name]
		gv := got.ProtoReflect().Get(fd)
		switch fd.Kind() {
		case protoreflect.StringKind:
			want, _ := httpVal.(string)
			assert.Equal(t, want, gv.String(), "string field %q (HTTP present=%v)", name, present)
		case protoreflect.BoolKind:
			want, _ := httpVal.(bool)
			assert.Equal(t, want, gv.Bool(), "bool field %q (HTTP present=%v)", name, present)
		case protoreflect.Int64Kind, protoreflect.Uint32Kind:
			want, _ := httpVal.(float64) // JSON numbers decode as float64
			var have float64
			if fd.Kind() == protoreflect.Int64Kind {
				have = float64(gv.Int())
			} else {
				have = float64(gv.Uint())
			}
			assert.Equal(t, want, have, "number field %q (HTTP present=%v)", name, present)
		case protoreflect.MessageKind:
			// timestamps: both sides absent, or both present
			assert.Equal(t, present && httpVal != nil, got.ProtoReflect().Has(fd), "presence of %q", name)
		default:
			t.Errorf("field %q has kind %v the parity test does not compare", name, fd.Kind())
		}
	}

	// The keys HTTP CAN return are the report's JSON fields, not just the ones this
	// deployment's report happened to populate (omitempty hides state_reason until a
	// state needs explaining, which is exactly when a client needs it).
	httpKeys := map[string]bool{}
	for key := range envelope.Data {
		httpKeys[key] = true
	}
	rt := reflect.TypeFor[core.AuditVerifyReport]()
	for field := range rt.Fields() {
		if name, _, _ := strings.Cut(field.Tag.Get("json"), ","); name != "" && name != "-" {
			httpKeys[name] = true
		}
	}
	var missing []string
	for key := range httpKeys {
		if known[key] {
			continue
		}
		if _, ok := auditVerifyHTTPOnly[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	assert.Empty(t, missing, fmt.Sprintf("GET /audit/verify returns %v that VerifyAuditChainResponse does not carry; add the field, or list it in auditVerifyHTTPOnly with the reason", missing))
}

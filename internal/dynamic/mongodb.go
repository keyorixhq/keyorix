package dynamic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// MongoEngine mints short-lived MongoDB users on the target's `admin` database and
// drops them on revoke. Like MySQL (and unlike PostgreSQL's VALID UNTIL), MongoDB
// users carry no built-in expiry, so a lease's TTL is enforced solely by the
// dynamic-secrets auto-revoke sweeper (ADR-035) — the sweeper must be enabled for
// MongoDB credentials to expire; the dropUser at revoke is the authoritative
// teardown either way.
//
// adminDSN is a MongoDB connection URI ("mongodb://admin:pass@host:27017/..."). The
// creation template is an operator-authored JSON role spec, e.g.
//
//	{"roles": [{"role": "readWrite", "db": "app"}, "clusterMonitor"]}
//
// applied as the new user's roles. Username and password are crypto/rand and are
// passed as typed BSON values (never string-interpolated), so credential injection
// is structurally impossible; the role spec is the operator-authored trust boundary.
// Users are created in the `admin` auth database; their roles may target any
// database.
type MongoEngine struct {
	// allowPrivateNetwork mirrors dynamic_secrets.allow_private_network_targets
	// (see New). When false, every connection re-validates the resolved
	// target address (including every mongodb+srv:// SRV-discovered target)
	// and refuses a private/link-local one (G48).
	allowPrivateNetwork bool
	// allowInsecureTransport mirrors dynamic_secrets.allow_insecure_transport
	// (see New). When false, connectMongo refuses a connection that isn't
	// using TLS, logging the exception when the operator has explicitly set
	// this true.
	allowInsecureTransport bool
}

func (e *MongoEngine) BackendType() string      { return "mongodb" }
func (e *MongoEngine) IsEphemeralBackend() bool { return false }

// RevokeInvalidatesCredential is always true: dropUser really removes the
// account, so a subsequent auth attempt with it fails immediately.
func (e *MongoEngine) RevokeInvalidatesCredential(_ string) bool { return true }

// SupportsNativeExpiry is false: MongoDB users have no native expiry, so lease
// expiry is enforced only by the auto-revoke sweeper (which must be enabled).
func (e *MongoEngine) SupportsNativeExpiry() bool { return false }

// mongoAuthDB is the database new users are created in (their authentication db).
// Roles within the template may still target any database.
const mongoAuthDB = "admin"

// mongoConnectTimeout bounds the connect+ping and each command at issue/revoke time.
const mongoConnectTimeout = 10 * time.Second

func (e *MongoEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, _ time.Duration) (Credential, string, error) {
	roles, err := parseMongoRoles(creationTemplate)
	if err != nil {
		return Credential{}, "", err
	}
	client, err := connectMongo(ctx, adminDSN, e.allowPrivateNetwork, e.allowInsecureTransport)
	if err != nil {
		return Credential{}, "", err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	suffix, err := randString(16)
	if err != nil {
		return Credential{}, "", err
	}
	user := "kx_dyn_" + suffix
	password, err := randString(32)
	if err != nil {
		return Credential{}, "", err
	}

	ports.ReportIssuedRole(ctx, user) // before the first write (see PostgresEngine.Issue)

	// createUser takes the name/password/roles as typed BSON, so the generated
	// credential can never be interpreted as a command — no quoting/escaping needed.
	cmd := bson.D{
		{Key: "createUser", Value: user},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: roles},
	}
	if err := client.Database(mongoAuthDB).RunCommand(ctx, cmd).Err(); err != nil {
		return Credential{}, "", fmt.Errorf("create user: %w", err)
	}
	return Credential{Username: user, Password: password}, user, nil
}

// Revoke drops the user from the auth database. roleName is the bare username.
func (e *MongoEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	// Defense-in-depth: reject a tampered role name before any connection, mirroring
	// the SQL engines. (Mongo passes it as a typed BSON value, so this is belt-and-
	// suspenders rather than an injection guard.)
	if err := assertSafeUsername(roleName); err != nil {
		return err
	}
	// The tls*File options Issue refuses are removed instead, with TLS kept on
	// (#3980): MongoDB users have no native expiry, so a refused revoke would
	// leave them live on the target.
	//
	// tlsInsecure=true (a certificate check Issue now refuses unless the operator
	// allowed insecure transport) is dropped the same way, with verification kept on.
	revokeURI, insecureDropped := adminDSN, false
	if !e.allowInsecureTransport {
		revokeURI, insecureDropped = mongoURIWithoutInsecureTLS(adminDSN)
	}
	revokeURI, removed := stripMongoRevokeOptions(revokeURI)
	client, err := connectMongo(ctx, revokeURI, e.allowPrivateNetwork, e.allowInsecureTransport)
	if err != nil {
		if _, refused := errors.AsType[*dsn.ForbiddenOptionError](err); refused {
			return err
		}
		caStripped := slices.ContainsFunc(removed, func(k string) bool {
			return strings.EqualFold(k, "tlsCAFile") || strings.EqualFold(k, "sslCertificateAuthorityFile")
		})
		err = revokeStrippedError(removed, caStripped, err)
		if insecureDropped {
			// Name the dropped option, so an operator reading revoke_failed knows
			// why a target with an untrusted certificate now fails the handshake.
			err = fmt.Errorf("revoke ran without admin_dsn option tlsInsecure (the server certificate was verified): %w", err)
		}
		return err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	if err := client.Database(mongoAuthDB).RunCommand(ctx, bson.D{{Key: "dropUser", Value: roleName}}).Err(); err != nil {
		if isMongoUserNotFound(err) {
			return nil // already gone — revoke is idempotent
		}
		return fmt.Errorf("drop user %s: %w", roleName, err)
	}
	return nil
}

// Renew is a no-op for MongoDB: users carry no expiry, so the renewed lease expiry
// is enforced entirely by the auto-revoke sweep (as with MySQL).
func (e *MongoEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

// mongoBlockedRoles are built-in MongoDB roles that grant cluster-wide or
// superuser privilege. Dynamic-secret credentials must never receive these:
// a leaked short-lived token with root or clusterAdmin access would be
// equivalent to a permanent admin credential.
var mongoBlockedRoles = map[string]bool{
	"root":                 true,
	"clusterAdmin":         true,
	"clusterManager":       true,
	"dbAdminAnyDatabase":   true,
	"userAdminAnyDatabase": true,
	"readWriteAnyDatabase": true,
	"backup":               true,
	"restore":              true,
	"__system":             true,
}

// parseMongoRoles extracts the roles array from the operator's JSON creation
// template. An empty template yields an empty roles array (a user that can
// authenticate but has no privileges — almost always you want roles). A non-empty
// template must be a JSON object carrying a "roles" array; each entry is either a
// built-in role name (string) or a {role, db} object, passed straight to createUser.
// Cluster-wide superuser roles (root, clusterAdmin, etc.) are always rejected.
func parseMongoRoles(template string) ([]any, error) {
	t := strings.TrimSpace(template)
	if t == "" {
		return []any{}, nil
	}
	var doc struct {
		Roles []any `json:"roles"`
	}
	if err := json.Unmarshal([]byte(t), &doc); err != nil {
		return nil, fmt.Errorf("mongodb creation template must be JSON like {\"roles\": [...]}: %w", err)
	}
	if doc.Roles == nil {
		return nil, fmt.Errorf("mongodb creation template must contain a \"roles\" array")
	}
	for _, entry := range doc.Roles {
		var roleName string
		switch v := entry.(type) {
		case string:
			roleName = v
		case map[string]any:
			if r, ok := v["role"].(string); ok {
				roleName = r
			}
		}
		if mongoBlockedRoles[roleName] {
			return nil, fmt.Errorf("mongodb creation template must not grant the %q role: it confers cluster-wide or superuser privilege", roleName)
		}
	}
	return doc.Roles, nil
}

// connectMongo opens and verifies a connection to the target using the admin
// URI, pinning the dial to a re-validated target address unless
// allowPrivateNetwork opts out, and requiring TLS unless allowInsecureTransport
// opts out. Replaces a bare mongo.Connect(ctx, options.Client().ApplyURI(...)):
// that path offers no hook to control the underlying TCP dial, and — critically
// — the actual connection it makes would otherwise re-resolve adminDSN's host
// independently of whatever check ran when the config was created or the DSN
// last decrypted, letting a DNS-rebinding attacker swap in a private/link-local
// address between the two resolutions (the same G48 gap Postgres/MySQL already
// close).
//
// mongodb+srv:// is a second, separate gap a plain dial-hook wrap does not
// cover: the driver resolves the SRV record internally, before any
// caller-supplied Dialer is ever invoked (see Guard.ValidateSRVTargets' doc
// comment for the verified driver-internals trail), so a caller has no
// visibility into which hostnames that step discovers. Guard.ValidateSRVTargets
// pre-resolves and validates them here, before the URI is ever handed to the
// driver — defense-in-depth on top of options.SetDialer below, which still
// re-validates the actual per-server dial regardless of discovery mode.
func connectMongo(ctx context.Context, adminDSN string, allowPrivateNetwork, allowInsecureTransport bool) (*mongo.Client, error) {
	connectCtx, cancel := context.WithTimeout(ctx, mongoConnectTimeout)
	defer cancel()

	if err := dsn.CheckLocalFileOptions("mongodb", adminDSN); err != nil {
		return nil, err
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		return nil, fmt.Errorf("invalid mongodb admin URI: %w", err)
	}

	guard := netutil.Guard{AllowInsecureTransport: allowInsecureTransport, InsecureTransportKey: "dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport"}
	if !allowPrivateNetwork {
		guard.Dial = netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal, Resolve: dialResolve}
		if u.Scheme == "mongodb+srv" {
			if err := guard.ValidateSRVTargets(connectCtx, "mongodb", "tcp", u.Hostname()); err != nil {
				return nil, fmt.Errorf("invalid mongodb admin URI: %w", err)
			}
		}
	}

	if err := guard.RequireTLS(mongoTLSEnabled(u), "mongodb admin_dsn", u.Hostname()); err != nil {
		return nil, err
	}

	opts := options.Client().ApplyURI(adminDSN)
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid mongodb admin URI: %w", err)
	}
	// The text check above reads option names as written; the driver lower-cases
	// them (TLS=false on a mongodb+srv URI turns the implicit TLS off). What the
	// driver will actually do is in the parsed options, so require TLS from them too.
	if err := guard.RequireTLS(opts.TLSConfig != nil, "mongodb admin_dsn", u.Hostname()); err != nil {
		return nil, err
	}
	// tlsInsecure=true (alias sslInsecure) satisfies the TLS requirement while the
	// driver accepts any certificate and hostname: a project admin could then undo
	// the operator's transport policy. Checked on the parsed options, not the DSN
	// text, so every spelling the driver accepts is covered. Allowed only where the
	// operator has opted into insecure transport, and then logged like a plaintext
	// connection.
	if opts.TLSConfig != nil && opts.TLSConfig.InsecureSkipVerify {
		if !allowInsecureTransport {
			return nil, &dsn.ForbiddenOptionError{
				Backend: "mongodb",
				Option:  "tlsInsecure",
				Reason:  "certificate verification cannot be turned off in an admin_dsn; remove tlsInsecure=true (or sslInsecure=true), or the operator can allow insecure transport",
			}
		}
		log.Printf("WARNING: mongodb admin_dsn host %q has tlsInsecure=true: the server certificate is not verified; dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport is explicitly enabled", u.Hostname())
	}
	if !allowPrivateNetwork {
		opts = opts.SetDialer(guard.Dial)
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid mongodb admin URI: %w", err)
	}
	if err := client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	return client, nil
}

// mongoTLSEnabled reports whether adminURI's connection will use TLS:
// mongodb+srv:// implies TLS by default (the MongoDB driver's own documented
// behaviour); a plain mongodb:// URI does not unless tls=true/ssl=true is
// present in the query string. An explicit tls=false/ssl=false always wins
// over the mongodb+srv:// default, matching the driver's own precedence. A
// pure function of the parsed URI (no I/O), so it's testable without a real
// connection attempt or DNS lookup.
func mongoTLSEnabled(u *url.URL) bool {
	enabled := u.Scheme == "mongodb+srv"
	// Read the raw query the way the driver does: options split on '&' and ';',
	// names lower-cased (TLS=false is tls=false), the last tls/ssl value wins (the
	// driver rejects tls and ssl that disagree, so there is no other case).
	for _, p := range strings.FieldsFunc(u.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		key, val, _ := strings.Cut(p, "=")
		if dec, err := url.QueryUnescape(key); err == nil {
			key = dec
		}
		if k := strings.ToLower(key); k != "tls" && k != "ssl" {
			continue
		}
		if dec, err := url.QueryUnescape(val); err == nil {
			val = dec
		}
		enabled = val == "true"
	}
	return enabled
}

// isMongoUserNotFound reports whether err is MongoDB's UserNotFound (code 11),
// returned by dropUser when the user is already gone — so revoke is idempotent.
func isMongoUserNotFound(err error) bool {
	if ce, ok := errors.AsType[mongo.CommandError](err); ok {
		return ce.Code == 11 || ce.Name == "UserNotFound"
	}
	return false
}

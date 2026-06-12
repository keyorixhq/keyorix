package dynamic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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
type MongoEngine struct{}

func (e *MongoEngine) BackendType() string { return "mongodb" }

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
	client, err := connectMongo(ctx, adminDSN)
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
	client, err := connectMongo(ctx, adminDSN)
	if err != nil {
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

// parseMongoRoles extracts the roles array from the operator's JSON creation
// template. An empty template yields an empty roles array (a user that can
// authenticate but has no privileges — almost always you want roles). A non-empty
// template must be a JSON object carrying a "roles" array; each entry is either a
// built-in role name (string) or a {role, db} object, passed straight to createUser.
func parseMongoRoles(template string) ([]interface{}, error) {
	t := strings.TrimSpace(template)
	if t == "" {
		return []interface{}{}, nil
	}
	var doc struct {
		Roles []interface{} `json:"roles"`
	}
	if err := json.Unmarshal([]byte(t), &doc); err != nil {
		return nil, fmt.Errorf("mongodb creation template must be JSON like {\"roles\": [...]}: %w", err)
	}
	if doc.Roles == nil {
		return nil, fmt.Errorf("mongodb creation template must contain a \"roles\" array")
	}
	return doc.Roles, nil
}

// connectMongo opens and verifies a connection to the target using the admin URI.
func connectMongo(ctx context.Context, adminDSN string) (*mongo.Client, error) {
	connectCtx, cancel := context.WithTimeout(ctx, mongoConnectTimeout)
	defer cancel()
	client, err := mongo.Connect(connectCtx, options.Client().ApplyURI(adminDSN))
	if err != nil {
		return nil, fmt.Errorf("invalid mongodb admin URI: %w", err)
	}
	if err := client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	return client, nil
}

// isMongoUserNotFound reports whether err is MongoDB's UserNotFound (code 11),
// returned by dropUser when the user is already gone — so revoke is idempotent.
func isMongoUserNotFound(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.Code == 11 || ce.Name == "UserNotFound"
	}
	return false
}

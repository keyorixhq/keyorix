// mongodb.go — the MongoDB rotation executor (ADR-047). Rotate sets an account's
// password via the updateUser command against an admin connection. The username and
// password are passed as typed BSON values (not concatenated into a command string), so
// neither can be interpreted as a command — injection is structurally impossible.
package rotation

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const mongoOpTimeout = 10 * time.Second

// mongoRotateAuthDB is the database the rotated account is defined in. Admin-managed
// accounts live in "admin"; rotation targets that, consistent with the dynamic engine.
const mongoRotateAuthDB = "admin"

// mongoConn is the high-level seam the executor uses — set a user's password and close.
// The driver stays contained in the real implementation; tests inject a fake.
type mongoConn interface {
	UpdateUserPassword(ctx context.Context, user, password string) error
	Close(ctx context.Context)
}

// MongoExecutor rotates a MongoDB account's password (in the admin database).
type MongoExecutor struct {
	name        string
	dsn         string
	allowedRefs []string
	newConn     func(ctx context.Context, dsn string) (mongoConn, error)
}

// NewMongoExecutor builds a MongoDB rotation executor. dsn is the admin connection
// string (operator-provided, env-sourced). allowedRefs restricts which usernames it may
// rotate (prefix allowlist) — required (fail-closed).
func NewMongoExecutor(name, dsn string, allowedRefs []string) *MongoExecutor {
	return &MongoExecutor{name: name, dsn: dsn, allowedRefs: allowedRefs}
}

func (e *MongoExecutor) Name() string { return e.name }
func (e *MongoExecutor) Type() string { return "mongodb" }

func (e *MongoExecutor) conn(ctx context.Context) (mongoConn, error) {
	if e.newConn != nil {
		return e.newConn(ctx, e.dsn)
	}
	cctx, cancel := context.WithTimeout(ctx, mongoOpTimeout)
	defer cancel()
	client, err := mongo.Connect(cctx, options.Client().ApplyURI(e.dsn))
	if err != nil {
		return nil, fmt.Errorf("mongodb: connect: %w", err)
	}
	return &mongoClientConn{client: client}, nil
}

// Rotate sets account `ref`'s password to newValue via updateUser.
func (e *MongoExecutor) Rotate(ctx context.Context, ref, newValue string) error {
	if ref == "" {
		return fmt.Errorf("mongodb: username (ref) is required")
	}
	if newValue == "" {
		return fmt.Errorf("mongodb: new value is required")
	}
	if len(e.allowedRefs) == 0 {
		return fmt.Errorf("mongodb: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return fmt.Errorf("mongodb: user %q is not permitted by this backend's allowed_refs", ref)
	}
	if e.dsn == "" {
		return fmt.Errorf("mongodb: backend %q has no admin DSN configured", e.name)
	}
	c, err := e.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	if err := c.UpdateUserPassword(ctx, ref, newValue); err != nil {
		return fmt.Errorf("mongodb: rotate user %q: %w", ref, err)
	}
	return nil
}

// mongoClientConn adapts *mongo.Client to the mongoConn seam.
type mongoClientConn struct{ client *mongo.Client }

func (m *mongoClientConn) UpdateUserPassword(ctx context.Context, user, password string) error {
	cctx, cancel := context.WithTimeout(ctx, mongoOpTimeout)
	defer cancel()
	// updateUser takes the name/pwd as typed BSON values — never string-concatenated.
	cmd := bson.D{{Key: "updateUser", Value: user}, {Key: "pwd", Value: password}}
	return m.client.Database(mongoRotateAuthDB).RunCommand(cctx, cmd).Err()
}

func (m *mongoClientConn) Close(context.Context) { _ = m.client.Disconnect(context.Background()) }

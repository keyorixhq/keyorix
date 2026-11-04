package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// A project admin writes admin_dsn, so it must not be able to name options that
// make the server's database driver read local files (mysql allowAllFiles lets a
// rogue server pull any file; mongodb tls*File and postgres ssl*/passfile read
// the server's disk). The host guard alone does not see these.
func TestDynamicSecrets_CreateConfig_RefusesLocalFileOptions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, backend, dsn, option string }{
		{"mysql allowAllFiles", "mysql", "root:pw@tcp(db.example.com:3306)/app?allowAllFiles=true", "allowallfiles"},
		{"mongodb tlsCAFile", "mongodb", "mongodb://u:pw@db.example.com/?tls=true&tlsCAFile=/etc/keyorix/ca.pem", "tlscafile"},
		{"mongodb oidc ambient token", "mongodb", "mongodb://u@db.example.com/?tls=true&authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:k8s", "authmechanism=mongodb-oidc"},
		{"postgres sslkey", "postgres", "postgres://u:pw@db.example.com/app?sslmode=require&sslkey=/etc/keyorix/key.pem", "sslkey"},
		{"postgres passfile kv", "postgres", "host=db.example.com user=u passfile=/root/.pgpass", "passfile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _, _, _ := newDynamicTestCore(t)
			_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
				Name:          "local-file-attempt",
				ProjectID:     1,
				EnvironmentID: 2,
				BackendType:   tc.backend,
				AdminDSN:      tc.dsn,
				CreatedBy:     "alice",
				ActorID:       testAdminActorID,
			})
			require.Error(t, err)
			var fe *dsn.ForbiddenOptionError
			require.True(t, errors.As(err, &fe), "got %v", err)
			assert.Equal(t, tc.option, fe.Option)
		})
	}
}

package rotation_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/rotation"
)

// DBCLIENT-PANIC-NOV-3 item 4 (#4777), rotation side: the MySQL executor opens its own
// connection (rotation/mysql.go), and netutil.MySQLGuardDialer does not cover a TLS
// connection, so the containment NewManager applies is the only defence against a
// malformed reply on it. See internal/dynamic/hostile_mysql_tls_test.go for the same
// check on the dynamic-secret engine, including why two frames are left out and why the
// connection release of a panicked call is not asserted.
func TestHostileMySQLOverTLSNeverPanicsIntoRotationCaller(t *testing.T) {
	skip := map[string]bool{"column-count-huge": true, "prepare-ok-huge-param-count": true}
	var contained atomic.Int32
	t.Run("cases", func(t *testing.T) {
		for _, tc := range myCases {
			if tc.stage == "greeting" || skip[tc.name] {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				host, port, handshakes := dynamictest.ServeMySQLTLS(t, tc.stage, tc.frame)
				dsn := fmt.Sprintf("admin:s3cret@tcp(%s:%s)/app?tls=skip-verify&timeout=2s&readTimeout=2s&writeTimeout=2s", host, port)
				exec, ok := rotation.NewManager([]rotation.Executor{rotation.NewMySQLExecutor("my", dsn, []string{"app_"})}).Get("my")
				if !ok {
					t.Fatal("executor not registered")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()

				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("PANIC escaped mysql.Rotate over TLS on %q: %T", tc.name, r)
						}
					}()
					err = exec.Rotate(ctx, "app_user", "n3w-value")
				}()
				if handshakes.Load() == 0 {
					t.Fatalf("no TLS handshake reached the hostile server: the case does not exercise the TLS path (err: %v)", err)
				}
				if errors.Is(err, dynamic.ErrEngineClientPanic) {
					contained.Add(1)
					var pe *dynamic.EngineClientPanicError
					if !errors.As(err, &pe) || pe.Name != "my" || pe.Op != "Rotate" {
						t.Errorf("want *EngineClientPanicError{my, Rotate}, got %#v", err)
					}
					for _, leak := range []string{"s3cret", "127.0.0.1", "n3w-value"} {
						if strings.Contains(err.Error(), leak) {
							t.Errorf("contained-panic error leaks %q: %v", leak, err)
						}
					}
				}
			})
		}
	})
	t.Logf("contained client-library panics over TLS: %d", contained.Load())
}

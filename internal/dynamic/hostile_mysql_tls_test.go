package dynamic_test

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
)

// DBCLIENT-PANIC-NOV-3 item 4 (#4777): netutil.MySQLGuardDialer steps aside once the
// client asks for TLS (the stream is ciphertext), so on a TLS connection the frames it
// refuses in plaintext reach the driver. The containment around the engine
// (dynamic.Contain, applied by dynamic.New) is then the only defence. This drives the
// real MySQL engine against a hostile server that negotiates TLS first and then sends
// the malformed replies of myCases, and checks what core would see: no panic escapes
// and a contained panic is the typed error without target bytes. It does not assert
// that the connection of a panicked call is released: database/sql never gets that
// connection back from the panicking driver, so it stays open until the target drops it
// (reported to the coordinator as a third-party finding, not worked around here).
//
// Two frames are left out: column-count-huge and prepare-ok-huge-param-count make the
// driver size an allocation from an attacker-announced count, which is exactly what the
// plaintext guard prevents and nothing prevents here; running them would risk the
// runner's memory instead of testing containment (an allocation failure is not a panic
// recover can catch).

var tlsSkippedCases = map[string]bool{
	"column-count-huge":           true,
	"prepare-ok-huge-param-count": true,
}

func TestHostileMySQLOverTLSNeverPanicsIntoCaller(t *testing.T) {
	ops := []struct {
		name string
		run  func(ctx context.Context, e dynamic.CredentialEngine, dsn string) error
	}{
		{"Issue", func(ctx context.Context, e dynamic.CredentialEngine, dsn string) error {
			_, _, err := e.Issue(ctx, dsn, "", time.Hour)
			return err
		}},
		{"Revoke", func(ctx context.Context, e dynamic.CredentialEngine, dsn string) error {
			return e.Revoke(ctx, dsn, "kx_dyn_probe")
		}},
	}
	var contained atomic.Int32
	t.Run("cases", func(t *testing.T) {
		for _, tc := range myCases {
			if tc.stage == "greeting" || tlsSkippedCases[tc.name] {
				continue // greeting frames arrive before the TLS upgrade, in plaintext, where the guard applies
			}
			for _, op := range ops {
				t.Run(tc.name+"/"+op.name, func(t *testing.T) {
					t.Parallel()
					host, port, handshakes := dynamictest.ServeMySQLTLS(t, tc.stage, tc.frame)
					eng, err := dynamic.New("mysql", true, true)
					if err != nil {
						t.Fatalf("dynamic.New: %v", err)
					}
					dsn := fmt.Sprintf("admin:s3cret@tcp(%s:%s)/app?tls=skip-verify&timeout=2s&readTimeout=2s&writeTimeout=2s", host, port)
					ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
					defer cancel()

					var opErr error
					if panicked, val := callEngine(func() { opErr = op.run(ctx, eng, dsn) }); panicked {
						t.Fatalf("PANIC escaped mysql.%s over TLS on %q: %T", op.name, tc.name, val)
					}
					if handshakes.Load() == 0 {
						t.Fatalf("no TLS handshake reached the hostile server: the case does not exercise the TLS path (err: %v)", opErr)
					}
					if errors.Is(opErr, dynamic.ErrEngineClientPanic) {
						contained.Add(1)
						var pe *dynamic.EngineClientPanicError
						if !errors.As(opErr, &pe) || pe.Name != "mysql" || pe.Op != op.name {
							t.Errorf("want *EngineClientPanicError{mysql, %s}, got %#v", op.name, opErr)
						}
						for _, leak := range []string{"s3cret", "127.0.0.1"} {
							if strings.Contains(opErr.Error(), leak) {
								t.Errorf("contained-panic error leaks %q: %v", leak, opErr)
							}
						}
					}
				})
			}
		}
	})
	t.Logf("contained client-library panics over TLS: %d", contained.Load())
}

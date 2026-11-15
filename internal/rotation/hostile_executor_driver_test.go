package rotation_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/rotation"
)

// DYNAMIC-ENGINE-PANIC-1 item 1 (#4133), rotation side: the DSN-based executors are
// pointed at the hostile loopback targets from hostile_executor_panic_test.go. A panic
// in the client library must not escape Rotate. The cloud executors (aws-iam, azure,
// gcp) have no DSN to point at a loopback server; their containment is covered by the
// stub-executor tests in contain_test.go.

type executorTarget struct {
	name    string
	cases   []hostileCase
	handler func(hostileCase) func(net.Conn)
	build   func(host, port string) rotation.Executor
}

var executorTargets = []executorTarget{
	{"postgres", pgCases, pgHandler, func(h, p string) rotation.Executor {
		return rotation.NewPostgresExecutor("pg", fmt.Sprintf("postgres://admin:s3cret@%s:%s/app?sslmode=disable&connect_timeout=2", h, p), []string{"app_"})
	}},
	{"mysql", myCases, myHandler, func(h, p string) rotation.Executor {
		return rotation.NewMySQLExecutor("my", fmt.Sprintf("admin:s3cret@tcp(%s:%s)/app?timeout=2s&readTimeout=2s&writeTimeout=2s", h, p), []string{"app_"})
	}},
	{"redis", redisCases, redisHandler, func(h, p string) rotation.Executor {
		return rotation.NewRedisExecutor("rd", fmt.Sprintf("redis://admin:s3cret@%s:%s/0", h, p), []string{"app_"})
	}},
	{"mongodb", mongoCases, mongoHandler, func(h, p string) rotation.Executor {
		return rotation.NewMongoExecutor("mg", fmt.Sprintf("mongodb://admin:s3cret@%s:%s/admin?directConnection=true&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000&socketTimeoutMS=2000", h, p), []string{"app_"})
	}},
}

func TestHostileTargetNeverPanicsIntoRotationCaller(t *testing.T) {
	for _, tg := range executorTargets {
		for _, tc := range tg.cases {
			t.Run(tg.name+"/"+tc.name, func(t *testing.T) {
				host, port := serveHostile(t, tg.handler(tc))
				// Through the Manager, as production resolves executors.
				exec, ok := rotation.NewManager([]rotation.Executor{tg.build(host, port)}).Get(tg.build(host, port).Name())
				if !ok {
					t.Fatal("executor not registered")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("PANIC escaped %s.Rotate on %q: %T", tg.name, tc.name, r)
						}
					}()
					_ = exec.Rotate(ctx, "app_user", "n3w-value")
				}()
			})
		}
	}
}

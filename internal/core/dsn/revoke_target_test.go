package dsn

import "testing"

// TestRevokeTarget_SameAndDifferent: two DSNs of one backend have the same
// RevokeTarget exactly when the backend's Revoke reaches the same server
// (REVIEW-4193-DEEP-1 F1: the port and the kubernetes namespace/revocable count).
func TestRevokeTarget_SameAndDifferent(t *testing.T) {
	k8s := `{"api_server":"https://k8s.example:6443","namespace":"a","service_account":"s","revocable":true,"token":"t1"}`
	for _, tc := range []struct {
		name, backend, a, b string
		same                bool
	}{
		{"pg implicit vs written default port", "postgres", "host=DB.example user=u dbname=x", "postgres://u:p@db.example:5432/y", true},
		{"pg other port", "postgres", "postgres://u@db.example:5432/x", "postgres://u@db.example:6543/x", false},
		{"pg kv other port", "postgres", "host=db.example port=5432", "host=db.example port=5433", false},
		{"pg query port override", "postgres", "postgres://u@db.example/x?port=5433", "postgres://u@db.example:5433/x", true},
		{"pg multi-host order", "postgres", "host=a.example,b.example port=5432", "postgres://u@b.example:5432,a.example:5432/x", true},
		{"pg multi-host one port moved", "postgres", "host=a.example,b.example port=5432,5433", "host=a.example,b.example port=5433,5432", false},
		{"pg hostaddr changed", "postgres", "host=db.example hostaddr=203.0.113.1", "host=db.example hostaddr=203.0.113.2", false},
		{"mysql implicit port", "mysql", "u:p@tcp(db.example)/x", "u:q@tcp(db.example:3306)/y", true},
		{"mysql other port", "mysql", "u:p@tcp(db.example:3306)/x", "u:p@tcp(db.example:3307)/x", false},
		{"mongo implicit port", "mongodb", "mongodb://u:p@db.example/?tls=true", "mongodb://u:q@db.example:27017/admin?tls=true", true},
		{"mongo other port", "mongodb", "mongodb://u:p@db.example:27017/", "mongodb://u:p@db.example:27018/", false},
		{"redis implicit port", "redis", "rediss://u:p@cache.example", "rediss://u:q@cache.example:6379/2", true},
		{"redis other port", "redis", "redis://cache.example:6379", "redis://cache.example:6380", false},
		{"k8s token rotated, default https port", "kubernetes", k8s,
			`{"api_server":"https://K8S.example:6443/","namespace":"a","service_account":"s2","revocable":true,"token":"t2"}`, true},
		{"k8s namespace", "kubernetes", k8s, `{"api_server":"https://k8s.example:6443","namespace":"b","revocable":true}`, false},
		{"k8s revocable off", "kubernetes", k8s, `{"api_server":"https://k8s.example:6443","namespace":"a"}`, false},
		{"k8s api port", "kubernetes", k8s, `{"api_server":"https://k8s.example","namespace":"a","revocable":true}`, false},
		{"k8s in-cluster vs explicit", "kubernetes", `{"namespace":"a","revocable":true}`, k8s, false},
		{"aws-sts no-op revoke", "aws-sts", `{"role_arn":"a"}`, `{"role_arn":"b"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta, okA := RevokeTarget(tc.backend, tc.a)
			tb, okB := RevokeTarget(tc.backend, tc.b)
			if !okA || !okB {
				t.Fatalf("both targets must be readable: ok=%v,%v (%q, %q)", okA, okB, ta, tb)
			}
			if (ta == tb) != tc.same {
				t.Fatalf("same=%v, want %v:\n  %s\n  %s", ta == tb, tc.same, ta, tb)
			}
		})
	}
}

// TestRevokeTarget_UnreadableFailsClosed: a DSN whose target cannot be read
// reports ok=false, so "same target" is never concluded from two empty results.
func TestRevokeTarget_UnreadableFailsClosed(t *testing.T) {
	for _, tc := range []struct{ backend, dsn string }{
		{"postgres", "user=u password=p dbname=x"},
		{"postgres", "service=prod"},
		{"postgres", "host=a.example,b.example port=1,2,3"},
		{"postgres", "postgres://u@a.example,b.example:5433/x"},
		{"postgres", "host='unterminated"},
		{"postgres", "host=db.example port=notaport"},
		{"mysql", "u:p@tcp/x"},
		{"mysql", "u:p@db.example/x"},
		{"mongodb", "mongodb://u:p@/x"},
		{"mongodb", "mongodb+srv://u:p@a.example:27017/x"},
		{"redis", "unix:///run/redis.sock"},
		{"redis", "redis://:p@/0"},
		{"kubernetes", "not json"},
		{"kubernetes", `{"api_server":"ftp://k8s.example","namespace":"a"}`},
		{"unknown", "postgres://u@db.example/x"},
	} {
		if got, ok := RevokeTarget(tc.backend, tc.dsn); ok {
			t.Errorf("RevokeTarget(%s, %q) = %q, ok; want not readable", tc.backend, tc.dsn, got)
		}
	}
}
